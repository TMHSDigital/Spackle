package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/seed"
)

// Tests of the branches that decide whether a finding survives an error,
// a budget stop or an interrupt in one of the later stages.

// failing returns labProvider with one stage replaced: the stage whose
// system prompt holds marker answers with reply instead.
func failing(marker string, reply func() (llm.Response, error)) *llm.Fake {
	f := labProvider()
	play := f.Handler
	f.Handler = func(req llm.Request, n int) (llm.Response, error) {
		if strings.Contains(req.System, marker) {
			return reply()
		}
		return play(req, n)
	}
	return f
}

// failingOpts are labOpts with a provider that fails one stage.
func failingOpts(t *testing.T, rt *fakeRuntime, fake *llm.Fake) Options {
	t.Helper()
	o := labOpts(t, rt)
	o.ProviderFactory = agenticOpts(t, fake).ProviderFactory
	return o
}

func soleFinding(t *testing.T, res Result) finding.Finding {
	t.Helper()
	if len(res.Run.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (notes %q)", len(res.Run.Findings), res.Run.Notes)
	}
	return res.Run.Findings[0]
}

func ledgerEvents(t *testing.T, runDir string) []ledger.Event {
	t.Helper()
	events, err := ledger.Read(runDir)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestReviewerFailuresKeepTheFinding(t *testing.T) {
	for _, c := range []struct {
		name, reason, outcome string
		err                   error
	}{
		{"budget", "Not reviewed: the budget ran out first.", ledger.OutcomeBudgetExhausted, fmt.Errorf("token cap: %w", budget.ErrExhausted)},
		{"error", "Not reviewed: the review call failed.", ledger.OutcomeCompleted, errors.New("provider returned 500")},
	} {
		t.Run(c.name, func(t *testing.T) {
			fake := failing("adversarial review", func() (llm.Response, error) { return llm.Response{}, c.err })
			// No runtime: a proof would replace the confidence reason.
			res, err := Run(context.Background(), agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}}))
			if err != nil {
				t.Fatal(err)
			}
			f := soleFinding(t, res)
			if !strings.Contains(f.Confidence.Reason, c.reason) || res.Run.Outcome != c.outcome {
				t.Fatalf("outcome %s, confidence reason %q", res.Run.Outcome, f.Confidence.Reason)
			}
		})
	}
}

func TestProverErrorKeepsTheTracedFinding(t *testing.T) {
	fake := failing("demonstrate one finding", func() (llm.Response, error) { return llm.Response{}, errors.New("provider returned 500") })
	res, err := Run(context.Background(), failingOpts(t, &fakeRuntime{fixClosesProof: true}, fake))
	if err != nil {
		t.Fatal(err)
	}
	f := soleFinding(t, res)
	if res.Run.Outcome != ledger.OutcomeCompleted || f.Proof.Status == finding.ProofDemonstrated || !strings.Contains(f.Proof.Reason, "The proof step failed") {
		t.Fatalf("outcome %s, proof %s: %q", res.Run.Outcome, f.Proof.Status, f.Proof.Reason)
	}
}

// A prover error is confined to its own finding: the next intent is still
// investigated, demonstrated and fixed.
func TestProverErrorDoesNotStopTheNextIntent(t *testing.T) {
	other := sqlLead()
	other.File = "other.py"
	plan := `{"intents":[` +
		`{"title":"find query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["app.py"],"lead_ids":["` + leadID(sqlLead(), "fake") + `"],"priority":1},` +
		`{"title":"other query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["other.py"],"lead_ids":["` + leadID(other, "fake") + `"],"priority":2}]}`
	otherDraft := strings.ReplaceAll(goodDraft(), `"app.py"`, `"other.py"`)

	fake := labProvider()
	play := fake.Handler
	fake.Handler = func(req llm.Request, n int) (llm.Response, error) {
		user := req.Messages[0].Text
		switch {
		case strings.Contains(req.System, "this step is planning"):
			return llm.Response{StopReason: llm.StopEnd, Text: plan, Usage: llm.Usage{InputTokens: 100, OutputTokens: 50, CostKnown: true}}, nil
		case strings.Contains(req.System, "demonstrate one finding") && !strings.Contains(user, "other.py"):
			return llm.Response{}, errors.New("provider returned 500")
		case stageOf(req) == "investigator" && !strings.Contains(req.System, "demonstrate one finding") && !strings.Contains(req.System, "fix one finding") && strings.Contains(user, "other.py"):
			return llm.Response{StopReason: llm.StopEnd, Text: otherDraft, Usage: llm.Usage{InputTokens: 100, OutputTokens: 50, CostKnown: true}}, nil
		}
		return play(req, n)
	}
	o := failingOpts(t, &fakeRuntime{fixClosesProof: true}, fake)
	o.Seeders = []seed.Seeder{fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), other}}}
	src, err := os.ReadFile(filepath.Join(o.Target, "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.Target, "other.py"), src, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != ledger.OutcomeCompleted || len(res.Run.Findings) != 2 {
		t.Fatalf("outcome %s, %d findings (notes %q)", res.Run.Outcome, len(res.Run.Findings), res.Run.Notes)
	}
	for _, f := range res.Run.Findings {
		switch f.Location.File {
		case "app.py":
			if f.Proof.Status == finding.ProofDemonstrated || !strings.Contains(f.Proof.Reason, "The proof step failed") {
				t.Errorf("app.py: proof %s: %q", f.Proof.Status, f.Proof.Reason)
			}
		case "other.py":
			if f.Proof.Status != finding.ProofDemonstrated || f.Status != finding.StatusPatchAvailable {
				t.Errorf("other.py: proof %s, status %s: %q", f.Proof.Status, f.Status, f.Proof.Reason)
			}
		default:
			t.Errorf("unexpected finding in %s", f.Location.File)
		}
	}
}

// An error that proveAndFix returns itself (here: the proof's files cannot
// be stored in the run directory) does not end the run. The finding is
// kept as it was traced, and the failure is a prover reject in the ledger.
func TestProveAndFixErrorIsAProverReject(t *testing.T) {
	// The finding id is stable, so a first run tells where the second one
	// stores the proof.
	first, err := Run(context.Background(), labOpts(t, &fakeRuntime{fixClosesProof: true}))
	if err != nil {
		t.Fatal(err)
	}
	id := soleFinding(t, first).ID

	o := labOpts(t, &fakeRuntime{fixClosesProof: true})
	// A file where the proof's directory has to go makes writing it fail.
	findingDir := filepath.Join(RunsDir(o.Config.StateDir), o.RunID, "findings", id)
	if err := os.MkdirAll(findingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(findingDir, "poc"), []byte("in the way\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := soleFinding(t, res)
	if f.ID != id || res.Run.Outcome != ledger.OutcomeCompleted || f.Proof.Status == finding.ProofDemonstrated || f.Remediation.Patch != "" {
		t.Fatalf("id %s (want %s), outcome %s, proof %s, patch %q", f.ID, id, res.Run.Outcome, f.Proof.Status, f.Remediation.Patch)
	}
	rejected := false
	for _, e := range ledgerEvents(t, res.RunDir) {
		var r ledger.Reject
		if e.Type == ledger.TypeReject && e.Decode(&r) == nil && r.Stage == "prover" && strings.Contains(r.Reason, "the proof or fix step failed") {
			rejected = true
		}
	}
	if !rejected {
		t.Fatal("no prover reject in the ledger")
	}
}

// A finding that does not validate when the findings are recorded is left
// out and recorded as an engine reject with the reason, and the valid ones
// are still recorded. Every stage validates what it produces first, so
// this is the net for a Spackle bug and is tested on recordFindings itself.
func TestInvalidFindingIsAnEngineReject(t *testing.T) {
	dir := t.TempDir()
	led, err := ledger.Create(dir, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	r := &runner{cfg: config.Default(), led: led, runDir: dir}

	good := FromLead(sqlLead(), "not investigated")
	bad := good
	bad.ID, bad.Title = "SPK-BAD00001", ""
	if err := r.recordFindings(0, []finding.Finding{good, bad}, nil); err != nil {
		t.Fatal(err)
	}

	var rejects []ledger.Reject
	var recorded []string
	for _, e := range ledgerEvents(t, dir) {
		var rj ledger.Reject
		var f finding.Finding
		switch {
		case e.Type == ledger.TypeReject && e.Decode(&rj) == nil:
			rejects = append(rejects, rj)
		case e.Type == ledger.TypeFinding && e.Decode(&f) == nil:
			recorded = append(recorded, f.ID)
		}
	}
	if len(rejects) != 1 || rejects[0].Stage != "engine" || rejects[0].Intent != bad.ID || !strings.Contains(rejects[0].Reason, "title is empty") {
		t.Fatalf("rejects = %+v, want one engine reject of %s", rejects, bad.ID)
	}
	if len(recorded) != 1 || recorded[0] != good.ID {
		t.Fatalf("recorded findings = %v, want only %s", recorded, good.ID)
	}
}

func TestFixerErrorAndRefusal(t *testing.T) {
	fake := failing("fix one finding", func() (llm.Response, error) { return llm.Response{}, errors.New("provider returned 500") })
	res, err := Run(context.Background(), failingOpts(t, &fakeRuntime{fixClosesProof: true}, fake))
	if err != nil {
		t.Fatal(err)
	}
	f := soleFinding(t, res)
	if res.Run.Outcome != ledger.OutcomeCompleted || f.Remediation.Patch != "" || !strings.HasPrefix(f.Remediation.Verification, "no patch: the fix step failed") {
		t.Fatalf("outcome %s, verification %q", res.Run.Outcome, f.Remediation.Verification)
	}

	// A fixer that gives a reason and no files is recorded as a rejected fix.
	fake = failing("fix one finding", func() (llm.Response, error) {
		return llm.Response{StopReason: llm.StopEnd, Text: `{"reason":"the query builder is generated code"}`, Usage: llm.Usage{InputTokens: 10, CostKnown: true}}, nil
	})
	res, err = Run(context.Background(), failingOpts(t, &fakeRuntime{fixClosesProof: true}, fake))
	if err != nil {
		t.Fatal(err)
	}
	if f := soleFinding(t, res); f.Remediation.Patch != "" {
		t.Fatalf("a refused fix left a patch: %q", f.Remediation.Patch)
	}
	rejected := false
	for _, e := range ledgerEvents(t, res.RunDir) {
		var v ledger.Verdict
		if e.Type == ledger.TypeVerdict && e.Decode(&v) == nil && v.Outcome == ledger.VerdictFixRejected {
			rejected = true
		}
	}
	if !rejected {
		t.Fatal("no fix-rejected verdict in the ledger")
	}
}

func TestInterruptDuringTheProofKeepsTheFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := failing("demonstrate one finding", func() (llm.Response, error) {
		cancel()
		return llm.Response{}, context.Canceled
	})
	res, err := Run(ctx, failingOpts(t, &fakeRuntime{fixClosesProof: true}, fake))
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != ledger.OutcomeInterrupted {
		t.Fatalf("outcome = %s, want interrupted", res.Run.Outcome)
	}
	f := soleFinding(t, res)
	found := false
	for _, e := range ledgerEvents(t, res.RunDir) {
		var lf finding.Finding
		if e.Type == ledger.TypeFinding && e.Decode(&lf) == nil && lf.ID == f.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("the finding is not in the ledger")
	}
}

// A lead that was not selected, of the same class at the same place as an
// investigated finding, becomes one of that finding's origins instead of a
// second finding.
func TestUnselectedLeadMergesIntoTheInvestigatedFinding(t *testing.T) {
	o := labOpts(t, &fakeRuntime{fixClosesProof: true})
	o.Seeders = append(o.Seeders, fakeSeeder{name: "other", leads: []seed.Lead{sqlLead()}})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := soleFinding(t, res)
	if len(f.Origin) < 2 {
		t.Fatalf("origins = %v, want the investigated lead and the merged one", f.Origin)
	}
}

func TestLanguageWithoutProofsGetsANote(t *testing.T) {
	o := labOpts(t, &fakeRuntime{fixClosesProof: true})
	if err := os.WriteFile(filepath.Join(o.Target, "app.rb"), []byte("puts 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !containsNote(res.Run.Notes, "ruby (1 files): findings and analysis only") {
		t.Fatalf("notes = %q", res.Run.Notes)
	}
}
