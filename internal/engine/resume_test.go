package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/seed"
)

func md5Lead() seed.Lead {
	return seed.Lead{RuleID: "md5", Title: "MD5 used", Class: "weak-hash", Surface: finding.SurfaceCode, CWE: []string{"CWE-328"},
		Severity: "medium", File: "app.py", Line: 1, Detail: "d", Fix: "Use SHA-256."}
}

// exhaustedRun runs a scan with two planned investigations and a budget
// that covers the planner and the first one. The first (the MD5 lead) is
// investigated and dismissed; the second (the SQL lead) is not reached.
func exhaustedRun(t *testing.T) (Options, Result) {
	t.Helper()
	plan := `{"intents":[` +
		`{"title":"check the hash","class":"weak-hash","hypothesis":"Is MD5 used for anything that matters?","files":["app.py"],"lead_ids":["` + leadID(md5Lead(), "fake") + `"],"priority":1},` +
		`{"title":"find query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["app.py"],"lead_ids":["` + leadID(sqlLead(), "fake") + `"],"priority":2}]}`
	fake := script{
		plan: plan, investigate: `{"verdict":"no_finding","reason":"the digest is a cache key, not a credential"}`,
		usage: llm.Usage{InputTokens: 10_000, CostKnown: true},
	}.provider()
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), md5Lead()}})
	// One investigation is estimated at 30,000 tokens. After the planner
	// call 35,000 remain, and after the first investigation 25,000.
	o.Config.Budget.Tokens = 45_000
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != "budget-exhausted" || len(fake.Requests) != 2 {
		t.Fatalf("outcome = %s after %d model calls, want the budget to end the run after the first investigation", res.Run.Outcome, len(fake.Requests))
	}
	return o, res
}

// resumeOpts returns the options of a second scan of the same target with
// the same state directory, a new run id and a new model script.
func resumeOpts(first Options, fake *llm.Fake) Options {
	o := first
	o.RunID = "20261122-130000-fedcba"
	o.Config.Budget.Tokens = config.Default().Budget.Tokens
	o.ProviderFactory = func(config.Model) (llm.Provider, error) { return llm.NewRedacting(fake), nil }
	return o
}

func briefFindings(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+" "+f.Confidence.Level+" "+f.Status)
	}
	return out
}

func TestResumeContinuesWhereTheBudgetRanOut(t *testing.T) {
	first, res := exhaustedRun(t)
	if !Resumable(res.Run) {
		t.Fatal("a run that stopped on its budget with an investigation left is not reported as resumable")
	}
	if len(res.Run.Findings) != 2 {
		t.Fatalf("first run findings = %+v", res.Run.Findings)
	}

	fake := script{plan: `{"intents":[]}`, investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"q is interpolated on line 4"}`}.provider()
	o := resumeOpts(first, fake)
	o.Resume = "latest"
	res2, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	run := res2.Run
	if run.Outcome != "completed" || Resumable(run) {
		t.Fatalf("resumed run outcome = %s", run.Outcome)
	}
	investigations := 0
	for _, req := range fake.Requests {
		switch stageOf(req) {
		case "planner":
			t.Fatal("the resumed run planned again instead of continuing the earlier plan")
		case "investigator":
			investigations++
		}
	}
	if investigations != 1 {
		t.Fatalf("%d investigations ran, want only the one the earlier run did not reach", investigations)
	}

	// The report is complete: the new finding, and the earlier dismissal
	// carried forward instead of the lead reappearing as never looked at.
	if len(run.Findings) != 2 {
		t.Fatalf("findings = %d, want the new one and the carried one: %v", len(run.Findings), briefFindings(run.Findings))
	}
	var sql, md5 finding.Finding
	for _, f := range run.Findings {
		switch f.Class {
		case "sql-injection":
			sql = f
		case "weak-hash":
			md5 = f
		}
	}
	if sql.Confidence.Level != finding.ConfidenceHigh || sql.Status != finding.StatusOpen {
		t.Fatalf("the continued investigation did not replace the unconfirmed lead: %+v", sql)
	}
	if md5.Status != finding.StatusDismissed || !strings.Contains(md5.DismissReason, "cache key") {
		t.Fatalf("the earlier dismissal was not carried forward: status=%s reason=%q", md5.Status, md5.DismissReason)
	}
	if !containsNote(run.Notes, "Resumed from run "+first.RunID+": the 1 investigations") {
		t.Fatalf("the report does not say it continues an earlier run: %q", run.Notes)
	}

	events, err := ledger.Read(res2.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	var start ledger.RunStart
	var intents []ledger.Intent
	for _, e := range events {
		switch e.Type {
		case ledger.TypeRunStart:
			if err := e.Decode(&start); err != nil {
				t.Fatal(err)
			}
		case ledger.TypeIntent:
			var it ledger.Intent
			if err := e.Decode(&it); err != nil {
				t.Fatal(err)
			}
			intents = append(intents, it)
		}
	}
	if start.ResumedFrom != first.RunID {
		t.Fatalf("run.start resumed_from = %q, want %q", start.ResumedFrom, first.RunID)
	}
	if len(intents) != 1 || intents[0].Title != "find query" || intents[0].Source != "resumed" {
		t.Fatalf("intents of the resumed run = %+v", intents)
	}

	// The resumed run finished its plan, so there is nothing to resume.
	o.RunID = "20261122-140000-aaaaaa"
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no planned investigation left") {
		t.Fatalf("resuming a completed run: err = %v", err)
	}
}

func TestResumeRefusals(t *testing.T) {
	first, _ := exhaustedRun(t)
	fake := script{investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"ok"}`}.provider()
	runs := func() int {
		entries, _ := os.ReadDir(RunsDir(first.Config.StateDir))
		return len(entries)
	}

	// Without a model there is nothing that could investigate.
	o := resumeOpts(first, fake)
	o.Resume, o.Config.Model = first.RunID, config.Model{}
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "needs a model") {
		t.Fatalf("no model: err = %v", err)
	}
	// A run id that does not exist.
	o = resumeOpts(first, fake)
	o.Resume = "20200101-000000-nosuch"
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--resume") {
		t.Fatalf("unknown run: err = %v", err)
	}
	// Another directory than the one the run scanned.
	o = resumeOpts(first, fake)
	o.Resume, o.Target = first.RunID, testTarget(t)
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "Resume it with the directory it scanned") {
		t.Fatalf("other target: err = %v", err)
	}
	// A dry run, a git URL and a running target.
	o = resumeOpts(first, fake)
	o.Resume, o.DryRun = first.RunID, true
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--dry-run") {
		t.Fatalf("dry run: err = %v", err)
	}
	for _, target := range []string{"https://example.test/owner/repo.git", "http://localhost:8081"} {
		o = resumeOpts(first, fake)
		o.Resume, o.Target = first.RunID, target
		if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--resume") {
			t.Fatalf("%s: err = %v", target, err)
		}
	}
	if len(fake.Requests) != 0 || runs() != 1 {
		t.Fatalf("a refused resume made %d model calls and left %d run directories", len(fake.Requests), runs())
	}
}

func TestResumeNeedsTheSameCommitUnlessForced(t *testing.T) {
	// The target is a repository of its own before the first run.
	plan := `{"intents":[{"title":"find query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["app.py"],"lead_ids":["` + leadID(sqlLead(), "fake") + `"],"priority":1}]}`
	exhausted := script{plan: plan, investigate: goodDraft(), usage: llm.Usage{InputTokens: 900, OutputTokens: 200, CostKnown: true}}.provider()
	first := agenticOpts(t, exhausted, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	diffTarget(t, first.Target)
	first.Config.Budget.Tokens = 1000 // the planner call alone uses it up
	if res, err := Run(context.Background(), first); err != nil || !Resumable(res.Run) {
		t.Fatalf("first run: resumable = %v, err = %v", err == nil && Resumable(res.Run), err)
	}

	if err := os.WriteFile(filepath.Join(first.Target, "new.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, first.Target, "add", "-A")
	gitIn(t, first.Target, "commit", "-q", "-m", "moved on")

	fake := script{investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"ok"}`}.provider()
	o := resumeOpts(first, fake)
	o.Resume = first.RunID
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("changed commit: err = %v", err)
	}
	if len(fake.Requests) != 0 {
		t.Fatal("a refused resume called the model")
	}
	o.Force = true
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != "completed" || len(res.Run.Findings) != 1 || res.Run.Findings[0].Confidence.Level != finding.ConfidenceHigh {
		t.Fatalf("forced resume: outcome = %s findings = %v", res.Run.Outcome, briefFindings(res.Run.Findings))
	}
}

// A resumed diff scan keeps the earlier run's file set: without a diff flag
// it applies the stored one, and a different one is refused.
func TestResumeKeepsTheDiffBase(t *testing.T) {
	inOld := sqlLead()
	inOld.File, inOld.RuleID, inOld.Class, inOld.Title = "old.py", "py-os-system", "command-injection", "os.system with a variable"
	plan := `{"intents":[{"title":"find query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["app.py"],"lead_ids":["` + leadID(sqlLead(), "fake") + `"],"priority":1}]}`
	exhausted := script{plan: plan, investigate: goodDraft(), usage: llm.Usage{InputTokens: 900, OutputTokens: 200, CostKnown: true}}.provider()
	first := agenticOpts(t, exhausted, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), inOld}})
	first.Since = diffTarget(t, first.Target)
	first.Config.Budget.Tokens = 1000 // the planner call alone uses it up
	res, err := Run(context.Background(), first)
	if err != nil || !Resumable(res.Run) {
		t.Fatalf("first run: resumable = %v, err = %v", err == nil && Resumable(res.Run), err)
	}
	if res.Run.Since != first.Since {
		t.Fatalf("the run does not record its diff base: since = %q", res.Run.Since)
	}
	if got, want := ResumeFlags(res.Run), "--since "+first.Since+" --resume "+first.RunID; got != want {
		t.Fatalf("resume flags = %q, want %q", got, want)
	}

	// Another diff base is refused before anything runs.
	fake := script{investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"ok"}`}.provider()
	o := resumeOpts(first, fake)
	o.Resume, o.Since, o.Changed = first.RunID, "", true
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--since "+first.Since) {
		t.Fatalf("other diff base: err = %v", err)
	}
	if len(fake.Requests) != 0 {
		t.Fatal("a refused resume called the model")
	}

	// Without a diff flag the stored base applies: the lead in the
	// unchanged file stays out of the report.
	o = resumeOpts(first, fake)
	o.Resume, o.Since = first.RunID, ""
	res, err = Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Run.Findings {
		if f.Location.File != "app.py" {
			t.Fatalf("the resumed diff scan reports a finding outside the diff: %v", briefFindings(res.Run.Findings))
		}
	}
	if res.Run.Since != first.Since || !containsNote(res.Run.Notes, "Diff scan against "+first.Since) {
		t.Fatalf("the resumed run did not keep the diff base: since = %q, notes = %q", res.Run.Since, res.Run.Notes)
	}
}

// A resumed diff scan keeps the earlier run's --diff-scope: without the
// flag it applies the stored one, and the other scope is refused.
func TestResumeKeepsTheDiffScope(t *testing.T) {
	plan := `{"intents":[{"title":"find query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["app.py"],"lead_ids":["` + leadID(sqlLead(), "fake") + `"],"priority":1}]}`
	onChanged := sqlLead()
	onChanged.RuleID, onChanged.Line = "on-changed-line", 6
	exhausted := script{plan: plan, investigate: goodDraft(), usage: llm.Usage{InputTokens: 900, OutputTokens: 200, CostKnown: true}}.provider()
	first := agenticOpts(t, exhausted, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), onChanged}})
	first.Since, first.DiffScope = diffTarget(t, first.Target), DiffScopeLines
	first.Config.Budget.Tokens = 1000 // the planner call alone uses it up
	res, err := Run(context.Background(), first)
	if err != nil || !Resumable(res.Run) || res.Run.DiffScope != DiffScopeLines {
		t.Fatalf("first run: resumable = %v, diff scope = %q, err = %v", err == nil && Resumable(res.Run), res.Run.DiffScope, err)
	}

	fake := script{investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"ok"}`}.provider()
	o := resumeOpts(first, fake)
	o.Resume, o.Since, o.DiffScope = first.RunID, "", DiffScopeFile
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--diff-scope lines") {
		t.Fatalf("other diff scope: err = %v", err)
	}
	if len(fake.Requests) != 0 {
		t.Fatal("a refused resume called the model")
	}

	o = resumeOpts(first, fake)
	o.Resume, o.Since, o.DiffScope = first.RunID, "", ""
	if res, err = Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if res.Run.DiffScope != DiffScopeLines || !containsNote(res.Run.Notes, "--diff-scope lines") {
		t.Fatalf("the resumed run did not keep the diff scope: %q, notes = %q", res.Run.DiffScope, res.Run.Notes)
	}
}
