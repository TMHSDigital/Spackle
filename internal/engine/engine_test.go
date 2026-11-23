package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/report"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// fakeSeeder returns fixed leads so engine tests do not depend on rules.
type fakeSeeder struct {
	name  string
	leads []seed.Lead
	err   error
}

func (f fakeSeeder) Name() string              { return f.name }
func (f fakeSeeder) Available() (bool, string) { return true, "" }
func (f fakeSeeder) Run(context.Context, string, []walk.File) ([]seed.Lead, error) {
	return f.leads, f.err
}

type missingSeeder struct{}

func (missingSeeder) Name() string              { return "absent-tool" }
func (missingSeeder) Available() (bool, string) { return false, "install absent-tool" }
func (missingSeeder) Run(context.Context, string, []walk.File) ([]seed.Lead, error) {
	panic("an unavailable seeder must not be run")
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func testTarget(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "my app")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "import sqlite3\n\ndef find(q):\n    return db.execute(f\"SELECT * FROM t WHERE a = '{q}'\")\n"
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func sqlLead() seed.Lead {
	return seed.Lead{
		RuleID: "py-sql-fstring", Title: "SQL query built with an f-string", Class: "sql-injection",
		Surface: finding.SurfaceCode, CWE: []string{"CWE-89"}, Severity: "critical",
		File: "app.py", Line: 4, Snippet: `return db.execute(f"SELECT * FROM t WHERE a = '{q}'")`,
		Detail: "The query text includes q directly.", Fix: "Pass q as a bound parameter.",
	}
}

func opts(t *testing.T, seeders ...seed.Seeder) Options {
	t.Helper()
	cfg := config.Default()
	cfg.StateDir = filepath.Join(t.TempDir(), ".spackle")
	return Options{Target: testTarget(t), Config: cfg, Seeders: seeders, Clock: fixedClock(), RunID: "20261122-120000-abcdef"}
}

func TestRunWritesLedgerFindingsAndEveryReportFormat(t *testing.T) {
	low := seed.Lead{
		RuleID: "unpinned", Title: "Action not pinned", Class: "supply-chain", Surface: finding.SurfaceInfra,
		CWE: []string{"CWE-829"}, Severity: "low", File: "app.py", Line: 1, Detail: "d", Fix: "Pin it.",
	}
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), low}}, missingSeeder{})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Run.Findings))
	}
	top := res.Run.Findings[0]
	if top.Class != "sql-injection" || top.Severity.Label != "critical" || top.Severity.Unscored || top.Severity.Score == 0 {
		t.Fatalf("top finding severity = %+v", top.Severity)
	}
	if top.Confidence.Level != finding.ConfidencePlausible || top.Proof.Status != finding.ProofNotRun {
		t.Fatalf("a lead with no model must be plausible and not-run, got %s / %s", top.Confidence.Level, top.Proof.Status)
	}
	if !strings.Contains(top.Confidence.Reason, "fake rule py-sql-fstring") {
		t.Fatalf("confidence reason = %q", top.Confidence.Reason)
	}
	// The seeder said low; the class default vector scores far higher. The
	// finding must keep the seeder's label and say it is unscored.
	second := res.Run.Findings[1]
	if second.Severity.Label != "low" || !second.Severity.Unscored || second.Severity.Vector != "" {
		t.Fatalf("mismatched hint severity = %+v", second.Severity)
	}
	for _, f := range res.Run.Findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s is invalid: %v", f.ID, err)
		}
		if _, err := os.Stat(filepath.Join(res.RunDir, "findings", f.ID, "finding.json")); err != nil {
			t.Errorf("missing finding.json for %s", f.ID)
		}
	}
	for _, ext := range []string{"txt", "md", "html", "json", "sarif"} {
		b, err := os.ReadFile(filepath.Join(res.RunDir, "reports", "report."+ext))
		if err != nil || len(b) == 0 {
			t.Errorf("report.%s missing or empty: %v", ext, err)
		}
	}

	events, err := ledger.Read(res.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Type]++
	}
	if counts[ledger.TypeRunStart] != 1 || counts[ledger.TypeMap] != 1 || counts[ledger.TypeSeeder] != 2 ||
		counts[ledger.TypeLead] != 2 || counts[ledger.TypeFinding] != 2 || counts[ledger.TypeRunEnd] != 1 {
		t.Fatalf("event counts = %v", counts)
	}
	if res.Run.Outcome != "completed" || res.Run.Mode != "deterministic" {
		t.Fatalf("outcome=%s mode=%s", res.Run.Outcome, res.Run.Mode)
	}
	var missing bool
	for _, s := range res.Run.Seeders {
		if s.Name == "absent-tool" && !s.Available && s.Note == "install absent-tool" {
			missing = true
		}
	}
	if !missing {
		t.Fatalf("the missing seeder was not recorded: %+v", res.Run.Seeders)
	}
}

func TestReportIsReproducibleFromTheLedgerAlone(t *testing.T) {
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	// Delete everything except the ledger, then rebuild.
	for _, sub := range []string{"reports", "findings"} {
		if err := os.RemoveAll(filepath.Join(res.RunDir, sub)); err != nil {
			t.Fatal(err)
		}
	}
	run, err := report.Load(res.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range report.Formats() {
		var first, second bytes.Buffer
		if err := report.Render(format, res.Run, &first); err != nil {
			t.Fatal(err)
		}
		if err := report.Render(format, run, &second); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Errorf("%s report differs when rebuilt from the ledger", format)
		}
	}
}

func TestSeederFailureDoesNotStopTheRun(t *testing.T) {
	o := opts(t,
		fakeSeeder{name: "broken", err: errors.New("scanner crashed")},
		fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}},
	)
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Run.Findings))
	}
	var recorded bool
	for _, s := range res.Run.Seeders {
		if s.Name == "broken" && s.Error == "scanner crashed" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("the seeder error was not recorded")
	}
}

func TestSameFlawFromTwoSeedersIsOneFinding(t *testing.T) {
	o := opts(t,
		fakeSeeder{name: "one", leads: []seed.Lead{sqlLead()}},
		fakeSeeder{name: "two", leads: []seed.Lead{sqlLead()}},
	)
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 || len(res.Run.Findings[0].Origin) != 2 {
		t.Fatalf("findings = %+v", res.Run.Findings)
	}
}

func TestDifferentRulesAtOnePlaceStayApart(t *testing.T) {
	a, b := sqlLead(), sqlLead()
	b.RuleID, b.Title, b.Severity = "py-sql-concat", "SQL query built by concatenation", "medium"
	o := opts(t,
		fakeSeeder{name: "one", leads: []seed.Lead{a, b}},
		fakeSeeder{name: "two", leads: []seed.Lead{b}},
	)
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	fs := res.Run.Findings
	if len(fs) != 2 || fs[0].ID == fs[1].ID {
		t.Fatalf("two rules of one class on one line must stay two findings: %+v", fs)
	}
	for _, f := range fs {
		want := 1
		if f.Title == b.Title {
			want = 2 // the same rule from two seeders still merges
		}
		if len(f.Origin) != want {
			t.Errorf("%s: origins = %v, want %d", f.Title, f.Origin, want)
		}
	}
}

func TestMaxFindingsIsRecordedAsSkipped(t *testing.T) {
	a, b := sqlLead(), sqlLead()
	b.Line, b.Severity, b.Class, b.RuleID = 1, "medium", "debug-enabled", "dbg"
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{a, b}})
	o.Config.Budget.MaxFindings = 1
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 || res.Run.Findings[0].Class != "sql-injection" {
		t.Fatalf("kept = %+v", res.Run.Findings)
	}
	if len(res.Run.Skipped) != 1 || len(res.Run.Skipped[0].Skipped) != 1 {
		t.Fatalf("skipped = %+v", res.Run.Skipped)
	}
}

func TestInvalidLeadIsRejectedNotReported(t *testing.T) {
	bad := sqlLead()
	bad.File = "../outside.py"
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{bad}})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 0 {
		t.Fatalf("a lead pointing outside the target became a finding: %+v", res.Run.Findings)
	}
	events, _ := ledger.Read(res.RunDir)
	var rejected bool
	for _, e := range events {
		if e.Type == ledger.TypeReject {
			rejected = true
		}
	}
	if !rejected {
		t.Fatal("the rejection was not written to the ledger")
	}
}

func TestLiveAndMissingTargetsAreRefused(t *testing.T) {
	for _, tgt := range []string{"http://127.0.0.1:9", filepath.Join(t.TempDir(), "nope")} {
		o := opts(t)
		o.Target = tgt
		_, err := Run(context.Background(), o)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("Run(%s) = %v, want ErrRefused", tgt, err)
		}
		if entries, _ := os.ReadDir(RunsDir(o.Config.StateDir)); len(entries) != 0 {
			t.Errorf("a refused run for %s left a run directory behind", tgt)
		}
	}
}

func TestSecretValuesNeverReachTheRunDirectory(t *testing.T) {
	secret := "tr0ub4dor-" + "fixture-9Zq2Lm7x"
	root := testTarget(t)
	if err := os.WriteFile(filepath.Join(root, "settings.py"), []byte("DB_PASSWORD = \""+secret+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.StateDir = filepath.Join(t.TempDir(), ".spackle")
	res, err := Run(context.Background(), Options{Target: root, Config: cfg, Seeders: seed.Builtin(), Clock: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Run.Findings {
		if f.Class == "hardcoded-secret" {
			found = true
		}
	}
	if !found {
		t.Fatal("the planted secret was not reported")
	}
	err = filepath.WalkDir(res.RunDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%s contains the secret value", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestResolveRun(t *testing.T) {
	state := t.TempDir()
	for _, id := range []string{"20261122-120000-aaaaaa", "20261122-130000-bbbbbb", "20261123-090000-cccccc"} {
		if err := os.MkdirAll(filepath.Join(RunsDir(state), id), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	latest, err := ResolveRun(state, "latest")
	if err != nil || filepath.Base(latest) != "20261123-090000-cccccc" {
		t.Fatalf("latest = %s, %v", latest, err)
	}
	if got, err := ResolveRun(state, "20261122-13"); err != nil || filepath.Base(got) != "20261122-130000-bbbbbb" {
		t.Fatalf("prefix = %s, %v", got, err)
	}
	if _, err := ResolveRun(state, "20261122"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("got %v", err)
	}
	if _, err := ResolveRun(state, "zzz"); err == nil || !strings.Contains(err.Error(), "most recent run") {
		t.Fatalf("got %v", err)
	}
	if _, err := ResolveRun(t.TempDir(), "latest"); err == nil {
		t.Fatal("want an error when there are no runs")
	}
}

func TestFindingJSONRoundTrips(t *testing.T) {
	f := FromLead(func() seed.Lead { l := sqlLead(); l.Source = "fake"; return l }(), "no model")
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back finding.Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != f.ID || back.Severity.Vector != f.Severity.Vector {
		t.Fatalf("round trip changed the finding")
	}
}
