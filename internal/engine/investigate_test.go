package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/agent"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
)

// investigation gives what investigateOne needs to run one investigation by
// itself: a runner with an open ledger and started model stages, the stages,
// the intent for the one lead, and the ledger event to hang it on.
func investigation(t *testing.T, fake *llm.Fake) (*runner, agenticStages, agent.Intent, int64) {
	t.Helper()
	o := agenticOpts(t, fake)
	r, seq := openRun(t)
	r.cfg, r.clock, r.provs = o.Config, fixedClock(), newProviders(o.Config, o.ProviderFactory)
	if err := r.startAgents(); err != nil {
		t.Fatal(err)
	}
	lead := sqlLead()
	lead.Source = "fake"
	lead.Finalize()
	sg := agenticStages{root: o.Target, leads: []seed.Lead{lead}, newRegistry: r.registries(o.Target, nil)}
	for stage, into := range map[string]**agent.Runner{"investigator": &sg.investigator, "reviewer": &sg.reviewer, "prover": &sg.prover, "fixer": &sg.fixer} {
		run, err := r.runnerFor(stage)
		if err != nil {
			t.Fatal(err)
		}
		*into = run
	}
	it := agent.Intent{ID: "I-1", Title: "find query", Class: "sql-injection", Hypothesis: "Does q reach SQL?", Files: []string{"app.py"}, LeadIDs: []string{lead.ID}, Priority: 1, Source: "planner"}
	return r, sg, it, seq
}

// rejects returns the reject events of a run.
func rejects(t *testing.T, runDir string) []ledger.Reject {
	t.Helper()
	events, err := ledger.Read(runDir)
	if err != nil {
		t.Fatal(err)
	}
	var out []ledger.Reject
	for _, e := range events {
		if e.Type == ledger.TypeReject {
			var rej ledger.Reject
			if err := e.Decode(&rej); err != nil {
				t.Fatal(err)
			}
			out = append(out, rej)
		}
	}
	return out
}

// A provider failure on one investigation is recorded and the loop goes on:
// the lead is marked incomplete with the reason, and the run is not cut
// short.
func TestInvestigateOneRecordsAFailedInvestigationAndGoesOn(t *testing.T) {
	fake := llm.NewFake()
	fake.Handler = func(llm.Request, int) (llm.Response, error) {
		return llm.Response{}, errors.New("the provider answered 500")
	}
	r, sg, it, seq := investigation(t, fake)
	st := newAgenticState()
	step, err := r.investigateOne(context.Background(), st, sg, it, seq)
	if err != nil || step != goOn {
		t.Fatalf("step = %d, err = %v, want goOn and no error", step, err)
	}
	fate := st.fates[it.LeadIDs[0]]
	if fate.kind != fateIncomplete || !strings.HasPrefix(fate.reason, "the investigation failed: ") || !strings.Contains(fate.reason, "answered 500") {
		t.Fatalf("fate = %+v, want incomplete with the failure as reason", fate)
	}
	if st.outcome != "completed" || st.capNote != "" || len(st.skipped) != 0 || st.interrupted || len(st.findings) != 0 {
		t.Fatalf("state = %+v, want an untouched run", st)
	}
	rej := rejects(t, r.runDir)
	if len(rej) != 1 || rej[0].Stage != "investigator" || rej[0].Reason != fate.reason || !strings.Contains(rej[0].Intent, it.Title) {
		t.Fatalf("rejects = %+v, want one from the investigator", rej)
	}
}

func TestInvestigateOneSettlesTheLeadsOfEachResult(t *testing.T) {
	t.Run("no finding dismisses the leads", func(t *testing.T) {
		fake := script{investigate: `{"verdict":"no_finding","reason":"q is bound as a parameter"}`}.provider()
		r, sg, it, seq := investigation(t, fake)
		st := newAgenticState()
		step, err := r.investigateOne(context.Background(), st, sg, it, seq)
		if err != nil || step != goOn {
			t.Fatalf("step = %d, err = %v", step, err)
		}
		if fate := st.fates[it.LeadIDs[0]]; fate.kind != fateDismissed || fate.reason != "q is bound as a parameter" {
			t.Fatalf("fate = %+v, want dismissed with the investigator's reason", fate)
		}
		if len(st.findings) != 0 {
			t.Fatalf("findings = %d, want none", len(st.findings))
		}
	})
	t.Run("a finding is reviewed, recorded and stands for the leads", func(t *testing.T) {
		fake := script{investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"q is interpolated on line 4"}`}.provider()
		r, sg, it, seq := investigation(t, fake)
		r.lab = r.newLab(sg.root, mapper.Harness{}, nil, "disabled in tests")
		st := newAgenticState()
		step, err := r.investigateOne(context.Background(), st, sg, it, seq)
		if err != nil || step != goOn {
			t.Fatalf("step = %d, err = %v", step, err)
		}
		if fate := st.fates[it.LeadIDs[0]]; fate.kind != fateFound {
			t.Fatalf("fate = %+v, want found", fate)
		}
		if len(st.findings) != 1 || st.findings[0].Class != "sql-injection" || st.parent[st.findings[0].ID] != seq {
			t.Fatalf("findings = %+v, parent = %v", st.findings, st.parent)
		}
		// The finding is in the ledger before the run ends.
		events, err := ledger.Read(r.runDir)
		if err != nil {
			t.Fatal(err)
		}
		stored := 0
		for _, e := range events {
			if e.Type == ledger.TypeFinding {
				stored++
			}
		}
		if stored != 1 {
			t.Fatalf("finding events = %d, want 1", stored)
		}
	})
	t.Run("a reached cap stops the loop before this investigation", func(t *testing.T) {
		fake := script{investigate: `{"verdict":"no_finding","reason":"x"}`}.provider()
		r, sg, it, seq := investigation(t, fake)
		r.cfg.Budget.Tokens = 1
		if err := r.startAgents(); err != nil {
			t.Fatal(err)
		}
		run, err := r.runnerFor("investigator")
		if err != nil {
			t.Fatal(err)
		}
		sg.investigator = run
		// The first call spends past the cap, so the second is refused.
		st := newAgenticState()
		if _, err := r.investigateOne(context.Background(), st, sg, it, seq); err != nil {
			t.Fatal(err)
		}
		st = newAgenticState()
		step, err := r.investigateOne(context.Background(), st, sg, it, seq)
		if err != nil || step != stopBefore {
			t.Fatalf("step = %d, err = %v, want stopBefore", step, err)
		}
		if st.outcome != "budget-exhausted" || st.capNote == "" || len(st.fates) != 0 {
			t.Fatalf("state = %+v, want a recorded cap and no fate", st)
		}
	})
}

// End to end: the lead of an investigation that failed is still reported,
// as an unconfirmed lead that says what went wrong.
func TestFailedInvestigationIsReportedAsAnUnconfirmedLead(t *testing.T) {
	fake := llm.NewFake()
	fake.Handler = func(req llm.Request, _ int) (llm.Response, error) {
		switch stageOf(req) {
		case "planner":
			return llm.Response{StopReason: llm.StopEnd, Text: planFor(leadID(sqlLead(), "fake")), Usage: llm.Usage{InputTokens: 100, OutputTokens: 50}}, nil
		case "correlate":
			return llm.Response{StopReason: llm.StopEnd, Text: `{"chains":[]}`}, nil
		}
		return llm.Response{}, errors.New("the provider answered 500")
	}
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != "completed" || len(res.Run.Findings) != 1 {
		t.Fatalf("outcome = %s, findings = %d", res.Run.Outcome, len(res.Run.Findings))
	}
	f := res.Run.Findings[0]
	if f.Status != finding.StatusOpen || f.Confidence.Level != finding.ConfidencePlausible ||
		!strings.Contains(f.Proof.Reason, "did not produce a usable result (the investigation failed: ") {
		t.Fatalf("finding = %s %s %q", f.Status, f.Confidence.Level, f.Proof.Reason)
	}
}
