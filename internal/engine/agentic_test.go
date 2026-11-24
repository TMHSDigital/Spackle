package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/seed"
)

const sqlVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

// stageOf tells which pipeline stage a request belongs to from its system
// prompt, so one fake can play every role.
func stageOf(req llm.Request) string {
	switch {
	case strings.Contains(req.System, "this step is planning"):
		return "planner"
	case strings.Contains(req.System, "adversarial review"):
		return "reviewer"
	case strings.Contains(req.System, "combine into a larger"):
		return "correlate"
	default:
		return "investigator"
	}
}

type script struct {
	plan, investigate, review string
	usage                     llm.Usage
}

func (s script) provider() *llm.Fake {
	f := llm.NewFake()
	f.Handler = func(req llm.Request, _ int) (llm.Response, error) {
		resp := llm.Response{StopReason: llm.StopEnd, Usage: s.usage}
		if resp.Usage.InputTokens == 0 {
			resp.Usage = llm.Usage{InputTokens: 100, OutputTokens: 50, CostKnown: true, CostUSD: 0.001}
		}
		switch stageOf(req) {
		case "planner":
			resp.Text = s.plan
		case "reviewer":
			resp.Text = s.review
		case "correlate":
			resp.Text = `{"chains":[]}`
		default:
			resp.Text = s.investigate
		}
		return resp, nil
	}
	return f
}

func goodDraft() string {
	d := map[string]any{"verdict": "finding", "finding": map[string]any{
		"title": "SQL injection in find", "class": "sql-injection", "cwe": []string{"CWE-89"},
		"file": "app.py", "start_line": 4, "end_line": 4, "symbol": "find",
		"cvss_vector": sqlVector, "severity_reasoning": "Network reachable.",
		"description":  "q is formatted into the SQL text.",
		"flow":         []map[string]any{{"role": "sink", "file": "app.py", "line": 4, "quote": `return db.execute(f"SELECT * FROM t WHERE a = '{q}'")`}},
		"attack_steps": []string{"Send a q value that closes the literal"}, "gains": []string{"Read the table"},
		"fix_summary": "Bind q as a parameter.", "confidence": "high", "confidence_reason": "Read the sink and its caller.",
	}}
	b, _ := json.Marshal(d)
	return string(b)
}

func agenticOpts(t *testing.T, fake *llm.Fake, seeders ...seed.Seeder) Options {
	t.Helper()
	o := opts(t, seeders...)
	o.Config.Model = config.Model{Provider: "ollama", Model: "fake-model"}
	o.ProviderFactory = func(config.Model) (llm.Provider, error) { return llm.NewRedacting(fake), nil }
	// Tests never touch a real container runtime unless they opt in.
	o.DetectRuntime = func(context.Context, string) (sandbox.Runtime, error) {
		return nil, fmt.Errorf("%w: disabled in tests", sandbox.ErrNoRuntime)
	}
	return o
}

func planFor(leadID string) string {
	return `{"intents":[{"title":"find query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["app.py"],"lead_ids":["` + leadID + `"],"priority":1}]}`
}

func leadID(l seed.Lead, source string) string {
	l.Source = source
	l.Finalize()
	return l.ID
}

func TestAgenticRunInvestigatesReviewsAndReports(t *testing.T) {
	other := seed.Lead{RuleID: "md5", Title: "MD5 used", Class: "weak-hash", Surface: finding.SurfaceCode, CWE: []string{"CWE-328"}, Severity: "medium", File: "app.py", Line: 1, Detail: "d", Fix: "Use SHA-256."}
	fake := script{
		plan:        planFor(leadID(sqlLead(), "fake")),
		investigate: goodDraft(),
		review:      `{"verdict":"confirmed","reason":"q is interpolated on line 4"}`,
	}.provider()
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), other}})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	run := res.Run
	if run.Mode != "agentic" || run.Provider != "fake" || run.Model != "fake-model" || run.Outcome != "completed" {
		t.Fatalf("run = mode %s provider %s model %s outcome %s", run.Mode, run.Provider, run.Model, run.Outcome)
	}
	if len(run.Findings) != 2 {
		t.Fatalf("findings = %d, want the investigated one and the untouched lead", len(run.Findings))
	}
	top := run.Findings[0]
	if top.Class != "sql-injection" || top.Confidence.Level != finding.ConfidenceHigh || top.Proof.Status != finding.ProofReasoned {
		t.Fatalf("top = %s confidence %s proof %s", top.Class, top.Confidence.Level, top.Proof.Status)
	}
	if !strings.Contains(top.Confidence.Reason, "independent review") {
		t.Fatalf("confidence reason = %q", top.Confidence.Reason)
	}
	if top.Severity.Score != 9.3 || len(top.Flaw.Flow) != 1 {
		t.Fatalf("top severity %+v flow %d", top.Severity, len(top.Flaw.Flow))
	}
	rest := run.Findings[1]
	if rest.Confidence.Level != finding.ConfidencePlausible || !strings.Contains(rest.Proof.Reason, "not selected for investigation") {
		t.Fatalf("uninvestigated lead = %s / %q", rest.Confidence.Level, rest.Proof.Reason)
	}
	// The fake is a local provider, so its cost is known to be zero.
	if run.Usage.ModelCalls < 4 || run.Usage.InputTokens == 0 || run.Usage.CostUSD != 0 || !run.Usage.CostKnown {
		t.Fatalf("usage = %+v", run.Usage)
	}
	events, _ := ledger.Read(res.RunDir)
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Type]++
	}
	if counts[ledger.TypeIntent] != 1 || counts[ledger.TypeVerdict] != 1 || counts[ledger.TypeModelCall] != run.Usage.ModelCalls {
		t.Fatalf("events = %v", counts)
	}
}

func TestReviewerRefutationDismissesWithReason(t *testing.T) {
	fake := script{
		plan: planFor(leadID(sqlLead(), "fake")), investigate: goodDraft(),
		review: `{"verdict":"refuted","reason":"find is only called from tests with a constant"}`,
	}.provider()
	res, err := Run(context.Background(), agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Run.Findings))
	}
	f := res.Run.Findings[0]
	if f.Status != finding.StatusDismissed || !strings.Contains(f.DismissReason, "only called from tests") {
		t.Fatalf("status=%s reason=%q", f.Status, f.DismissReason)
	}
	review, err := os.ReadFile(filepath.Join(res.RunDir, "findings", f.ID, "review.md"))
	if err != nil || !strings.Contains(string(review), "only called from tests") {
		t.Fatalf("review.md = %q err=%v", review, err)
	}
}

// An investigated finding is in the ledger as soon as it is finished, so the
// max-findings cap must keep it: cutting it would list it as skipped while
// the report still loads it. Here it ranks last (dismissed by the review)
// against a lead that was not investigated.
func TestMaxFindingsKeepsInvestigatedFindings(t *testing.T) {
	other := seed.Lead{RuleID: "md5", Title: "MD5 used", Class: "weak-hash", Surface: finding.SurfaceCode, CWE: []string{"CWE-328"}, Severity: "high", File: "app.py", Line: 1, Detail: "d", Fix: "Use SHA-256."}
	fake := script{
		plan: planFor(leadID(sqlLead(), "fake")), investigate: goodDraft(),
		review: `{"verdict":"refuted","reason":"find is only called from tests with a constant"}`,
	}.provider()
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), other}})
	o.Config.Budget.MaxFindings = 1
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 {
		t.Fatalf("findings = %d, want the cap of 1", len(res.Run.Findings))
	}
	kept := res.Run.Findings[0]
	if kept.Class != "sql-injection" || kept.Status != finding.StatusDismissed {
		t.Fatalf("kept %s (%s), want the investigated finding", kept.Class, kept.Status)
	}
	for _, s := range res.Run.Skipped {
		for _, line := range s.Skipped {
			if strings.HasPrefix(line, kept.ID+" ") {
				t.Errorf("%s is both reported and skipped: %q", kept.ID, line)
			}
		}
	}
}

func TestInvestigatorNoFindingDismissesTheLead(t *testing.T) {
	fake := script{
		plan:        planFor(leadID(sqlLead(), "fake")),
		investigate: `{"verdict":"no_finding","reason":"The value is a constant."}`,
	}.provider()
	res, err := Run(context.Background(), agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}}))
	if err != nil {
		t.Fatal(err)
	}
	f := res.Run.Findings[0]
	if f.Status != finding.StatusDismissed || !strings.Contains(f.DismissReason, "The value is a constant.") {
		t.Fatalf("status=%s reason=%q", f.Status, f.DismissReason)
	}
}

func TestPlannerFailureFallsBackToLeads(t *testing.T) {
	fake := script{plan: "I cannot help with that.", investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"ok"}`}.provider()
	res, err := Run(context.Background(), agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 || res.Run.Findings[0].Confidence.Level != finding.ConfidenceHigh {
		t.Fatalf("findings = %+v", res.Run.Findings)
	}
	if !strings.Contains(strings.Join(res.Run.Notes, "|"), "planned directly from scanner leads") {
		t.Fatalf("notes = %v", res.Run.Notes)
	}
}

func TestBudgetExhaustionDegradesAndSaysWhatWasSkipped(t *testing.T) {
	fake := script{
		plan: planFor(leadID(sqlLead(), "fake")), investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"ok"}`,
		usage: llm.Usage{InputTokens: 900, OutputTokens: 200, CostKnown: true},
	}.provider()
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	o.Config.Budget.Tokens = 1000 // the planner call alone uses it up
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != "budget-exhausted" {
		t.Fatalf("outcome = %s", res.Run.Outcome)
	}
	if len(res.Run.Skipped) == 0 || !strings.Contains(strings.Join(res.Run.Skipped[0].Skipped, "|"), "Not investigated: find query") {
		t.Fatalf("skipped = %+v", res.Run.Skipped)
	}
	// The lead is still reported, as an unconfirmed lead.
	if len(res.Run.Findings) != 1 || res.Run.Findings[0].Confidence.Level != finding.ConfidencePlausible {
		t.Fatalf("findings = %+v", res.Run.Findings)
	}
	if n := len(fake.Requests); n != 1 {
		t.Fatalf("%d model calls were made; only the planner call fits the budget", n)
	}
}

// A cap reached during the review of the last planned investigation makes
// the run budget-exhausted, as the same cut on an earlier one does, and the
// skip entry names the step that was cut.
func TestBudgetCutOnTheLastReviewIsBudgetExhausted(t *testing.T) {
	base := script{plan: planFor(leadID(sqlLead(), "fake")), investigate: goodDraft(), review: `{"verdict":"confirmed","reason":"ok"}`}.provider()
	fake := llm.NewFake()
	fake.Handler = func(req llm.Request, n int) (llm.Response, error) {
		resp, err := base.Handler(req, n)
		if stageOf(req) == "investigator" {
			// The investigation uses up what is left of the token cap.
			resp.Usage = llm.Usage{InputTokens: 100_000, OutputTokens: 100, CostKnown: true}
		}
		return resp, err
	}
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	o.Config.Budget.Tokens = 100_000
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 || !strings.Contains(res.Run.Findings[0].Confidence.Reason, "Not reviewed: the budget ran out first.") {
		t.Fatalf("findings = %+v, want the investigated finding, not reviewed", res.Run.Findings)
	}
	if res.Run.Outcome != ledger.OutcomeBudgetExhausted {
		t.Fatalf("outcome = %s, want budget-exhausted", res.Run.Outcome)
	}
	var skipped []string
	for _, s := range res.Run.Skipped {
		skipped = append(skipped, s.Skipped...)
	}
	if !strings.Contains(strings.Join(skipped, "|"), "Review: not done for SQL injection in find") {
		t.Fatalf("skipped = %q, want the review named", skipped)
	}
}

func TestSecretsNeverReachTheModelInAFullRun(t *testing.T) {
	secret := "tr0ub4dor-" + "fixture-9Zq2Lm7x"
	fake := script{plan: `{"intents":[]}`, investigate: `{"verdict":"no_finding","reason":"x"}`}.provider()
	o := agenticOpts(t, fake)
	o.Seeders = seed.Builtin()
	if err := os.WriteFile(filepath.Join(o.Target, "settings.py"), []byte("DB_PASSWORD = \""+secret+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(fake.Requests) == 0 {
		t.Fatal("the model was never called; the test proves nothing")
	}
	if strings.Contains(fake.Sent(), secret) {
		t.Fatal("a secret value from the target was sent to the model")
	}
}

func TestRefusalsLeaveNoRunDirectory(t *testing.T) {
	// Offline with a remote provider.
	o := opts(t)
	o.Config.Offline = true
	o.Config.Model = config.Model{Provider: "openai-compatible", Model: "m", BaseURL: "https://openrouter.ai/api/v1", APIKeyEnv: "SPACKLE_TEST_KEY"}
	t.Setenv("SPACKLE_TEST_KEY", "k")
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !errors.Is(err, llm.ErrOffline) {
		t.Fatalf("offline + remote provider: err = %v", err)
	}
	if entries, _ := os.ReadDir(RunsDir(o.Config.StateDir)); len(entries) != 0 {
		t.Fatal("a refused run left a run directory")
	}

	// A missing API key.
	o = opts(t)
	o.Config.Model = config.Model{Provider: "anthropic", Model: "claude-opus-5-5", APIKeyEnv: "SPACKLE_TEST_UNSET_KEY"}
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "SPACKLE_TEST_UNSET_KEY") {
		t.Fatalf("missing key: err = %v", err)
	}

	// The operator declines the estimate.
	fake := script{plan: `{"intents":[]}`}.provider()
	o = agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	var shown Estimate
	o.Confirm = func(e Estimate) bool { shown = e; return false }
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) {
		t.Fatalf("declined estimate: err = %v", err)
	}
	if shown.Investigations == 0 || !strings.Contains(shown.String(), "fake-model") {
		t.Fatalf("estimate = %+v", shown)
	}
	if len(fake.Requests) != 0 {
		t.Fatal("a model call was made before the operator confirmed")
	}
	if entries, _ := os.ReadDir(RunsDir(o.Config.StateDir)); len(entries) != 0 {
		t.Fatal("a declined run left a run directory")
	}
}

func TestEstimateWording(t *testing.T) {
	cases := map[string]Estimate{
		"No model spend":              {Investigations: 3, Model: "qwen", Local: true, CapTokens: 10},
		"price is not known":          {Investigations: 3, Model: "mystery", CapTokens: 10},
		"estimated up to $1.25. Hard": {Investigations: 3, Model: "claude-opus-5-5", CostKnown: true, USD: 1.25, CapUSD: 5, CapTokens: 10},
	}
	for want, e := range cases {
		if got := e.String(); !strings.Contains(got, want) {
			t.Errorf("%q does not contain %q", got, want)
		}
	}
}

// TestUnattendedDollarCapNeedsAPrice pins who is refused when the model has
// no price: only a run nobody confirms, with a dollar cap the operator set,
// that has not opted in and whose endpoint does not report its own cost.
func TestUnattendedDollarCapNeedsAPrice(t *testing.T) {
	unpriced := Estimate{Investigations: 3, Model: "mystery", CapUSD: 2, CapTokens: 10}
	set := config.Default()
	set.Budget.USD, set.Budget.USDSet = 2, true
	allowed := set
	allowed.Budget.AllowUnpriced = true
	yes := func(Estimate) bool { return true }

	cases := []struct {
		name    string
		cfg     config.Config
		model   config.Model
		est     Estimate
		confirm func(Estimate) bool
		refused bool
	}{
		{name: "cap set, nobody asked", cfg: set, est: unpriced, refused: true},
		{name: "default cap", cfg: config.Default(), est: unpriced},
		{name: "opted in", cfg: allowed, est: unpriced},
		{name: "operator confirmed", cfg: set, est: unpriced, confirm: yes},
		{name: "priced model", cfg: set, est: Estimate{Model: "claude-opus-5-5", CostKnown: true, CapUSD: 2}},
		{name: "local model", cfg: set, est: Estimate{Model: "qwen", Local: true, CapUSD: 2}},
		{name: "endpoint reports cost", cfg: set, model: config.Model{BaseURL: "https://openrouter.ai/api/v1"}, est: unpriced},
	}
	for _, c := range cases {
		err := confirmEstimate(c.cfg, c.model, c.est, c.confirm)
		if c.refused != errors.Is(err, ErrRefused) {
			t.Errorf("%s: err = %v, want refused = %v", c.name, err, c.refused)
		}
		if c.refused && !strings.Contains(err.Error(), `[pricing."mystery"]`) {
			t.Errorf("%s: the refusal does not show the table to add: %v", c.name, err)
		}
	}

	// End to end: the refusal comes before any model call or run directory.
	fake := script{plan: `{"intents":[]}`}.provider()
	fake.Remote = true
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	o.Config.Budget.USD, o.Config.Budget.USDSet = 2, true
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--allow-unpriced") {
		t.Fatalf("unpriced remote model with a dollar cap: err = %v", err)
	}
	if len(fake.Requests) != 0 {
		t.Fatal("a model call was made by a refused run")
	}
	if entries, _ := os.ReadDir(RunsDir(o.Config.StateDir)); len(entries) != 0 {
		t.Fatal("a refused run left a run directory")
	}
	o.Config.Budget.AllowUnpriced = true
	if _, err := Run(context.Background(), o); err != nil {
		t.Fatalf("with allow_unpriced: %v", err)
	}
}

// networkSeeder is a seeder that says it uses the network when it runs.
type networkSeeder struct{ fakeSeeder }

func (networkSeeder) UsesNetwork() bool { return true }

func TestOfflineSkipsNetworkScannersAndRefusesClones(t *testing.T) {
	// The real seeder set: which scanners use the network is declared on
	// each adapter, and offline mode skips exactly those.
	in := seed.All()
	out := offlineSeeders(in)
	if len(out) != len(in) {
		t.Fatalf("%d seeders in, %d out: a skipped scanner must still be listed", len(in), len(out))
	}
	skipped := map[string]bool{"semgrep": true, "osv-scanner": true, "trivy": true}
	for i, s := range out {
		if s.Name() != in[i].Name() {
			t.Fatalf("seeder %d is %s, want %s", i, s.Name(), in[i].Name())
		}
		ok, note := s.Available()
		byOffline := strings.Contains(note, "offline mode")
		if byOffline != skipped[s.Name()] {
			t.Errorf("%s: skipped by offline mode = %v, want %v (note %q)", s.Name(), byOffline, skipped[s.Name()], note)
		}
		if byOffline && ok {
			t.Errorf("%s is available in offline mode", s.Name())
		}
	}
	// A seeder that does not say whether it uses the network is left alone
	// only when it is not a scanner adapter at all, such as a built-in one.
	if kept := offlineSeeders([]seed.Seeder{fakeSeeder{name: "builtin-like"}}); len(kept) != 1 || kept[0].Name() != "builtin-like" {
		t.Fatalf("a seeder with no network property was replaced: %+v", kept)
	}

	o := opts(t)
	o.Config.Offline = true
	o.Target = "https://github.com/TMHSDigital/Spackle.git"
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !errors.Is(err, llm.ErrOffline) {
		t.Fatalf("offline clone: err = %v", err)
	}

	// The skipped scanners still appear in the report, with the reason.
	o = opts(t, networkSeeder{fakeSeeder{name: "semgrep", leads: []seed.Lead{sqlLead()}}})
	o.Config.Offline = true
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 0 || len(res.Run.Seeders) != 1 || res.Run.Seeders[0].Available || !strings.Contains(res.Run.Seeders[0].Note, "offline mode") {
		t.Fatalf("findings=%d seeders=%+v", len(res.Run.Findings), res.Run.Seeders)
	}
}

// An interrupt must not lose what the run already found: the finished
// finding is in the ledger and the report, and the outcome says interrupted.
func TestInterruptKeepsFinishedFindings(t *testing.T) {
	other := seed.Lead{RuleID: "md5", Title: "MD5 used", Class: "weak-hash", Surface: finding.SurfaceCode, CWE: []string{"CWE-328"}, Severity: "medium", File: "app.py", Line: 1, Detail: "d", Fix: "Use SHA-256."}
	plan := `{"intents":[` +
		`{"title":"find query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["app.py"],"lead_ids":["` + leadID(sqlLead(), "fake") + `"],"priority":1},` +
		`{"title":"hashing","class":"weak-hash","hypothesis":"Is MD5 used for secrets?","files":["app.py"],"lead_ids":["` + leadID(other, "fake") + `"],"priority":2}]}`
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	investigations := 0
	fake := llm.NewFake()
	fake.Handler = func(req llm.Request, _ int) (llm.Response, error) {
		resp := llm.Response{StopReason: llm.StopEnd, Usage: llm.Usage{InputTokens: 100, OutputTokens: 50, CostKnown: true}}
		switch stageOf(req) {
		case "planner":
			resp.Text = plan
		case "reviewer":
			resp.Text = `{"verdict":"confirmed","reason":"q is interpolated on line 4"}`
		case "correlate":
			t.Error("chain analysis ran after the interrupt")
		default:
			investigations++
			if investigations == 2 {
				cancel() // the operator presses Ctrl-C during the second investigation
				return llm.Response{}, context.Canceled
			}
			resp.Text = goodDraft()
		}
		return resp, nil
	}
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), other}})
	res, err := Run(ctx, o)
	if err != nil {
		t.Fatalf("an interrupted run must still produce a result: %v", err)
	}
	if res.Run.Outcome != "interrupted" {
		t.Fatalf("outcome = %s, want interrupted", res.Run.Outcome)
	}
	if len(res.Run.Findings) != 2 || res.Run.Findings[0].Class != "sql-injection" || res.Run.Findings[0].Confidence.Level != finding.ConfidenceHigh {
		t.Fatalf("the finished finding was lost: %+v", res.Run.Findings)
	}
	if len(res.Run.Skipped) != 1 || !strings.Contains(res.Run.Skipped[0].Cap, "interrupted") || !strings.Contains(strings.Join(res.Run.Skipped[0].Skipped, " "), "Not investigated: hashing") {
		t.Fatalf("skipped = %+v", res.Run.Skipped)
	}
	if _, err := os.Stat(filepath.Join(res.RunDir, "reports", "report.md")); err != nil {
		t.Fatalf("no report was written for the interrupted run: %v", err)
	}
}

func TestInterruptDuringPlanningIsNotReportedAsCompleted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := llm.NewFake()
	fake.Handler = func(llm.Request, int) (llm.Response, error) {
		cancel()
		return llm.Response{}, context.Canceled
	}
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	res, err := Run(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != "interrupted" || len(res.Run.Findings) != 1 {
		t.Fatalf("outcome = %s findings = %d", res.Run.Outcome, len(res.Run.Findings))
	}
}

// A dry run maps and seeds, reports the plan and the estimate, and stops:
// no model call, no run directory.
func TestDryRunCallsNoModelAndStoresNoRun(t *testing.T) {
	fake := llm.NewFake()
	fake.Handler = func(llm.Request, int) (llm.Response, error) {
		t.Error("a dry run called the model")
		return llm.Response{}, errors.New("no")
	}
	other := seed.Lead{RuleID: "md5", Title: "MD5 used", Class: "weak-hash", Surface: finding.SurfaceCode, CWE: []string{"CWE-328"}, Severity: "medium", File: "app.py", Line: 1, Detail: "d", Fix: "Use SHA-256."}
	o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), other}})
	o.DryRun = true
	o.Confirm = func(Estimate) bool { t.Error("a dry run asked for confirmation"); return false }
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	p := res.Plan
	if p == nil || res.RunID != "" || res.RunDir != "" {
		t.Fatalf("result = %+v", res)
	}
	if p.Mode != "agentic" || p.Leads != 2 || p.LeadsByClass["sql-injection"] != 1 || p.LeadsBySeverity["medium"] != 1 || p.Files != 1 || p.Investigations == 0 {
		t.Fatalf("plan = %+v", p)
	}
	if !strings.Contains(p.Estimate, "investigations") || len(p.Seeders) != 1 || p.Seeders[0].Leads != 2 {
		t.Fatalf("plan = %+v", p)
	}
	if _, err := os.Stat(RunsDir(o.Config.StateDir)); err == nil {
		t.Fatal("a dry run created the runs directory")
	}

	// Without a model the plan says the scan is free.
	d := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	d.DryRun = true
	res, err = Run(context.Background(), d)
	if err != nil || res.Plan == nil || res.Plan.Mode != "deterministic" || res.Plan.Investigations != 0 || !strings.Contains(res.Plan.Estimate, "costs nothing") {
		t.Fatalf("plan = %+v, err = %v", res.Plan, err)
	}
}

// A dry run says when the real run of the same command would be refused:
// nobody would confirm it, and its dollar cap cannot hold for the model.
func TestDryRunSaysWhenTheRealRunWouldBeRefused(t *testing.T) {
	plan := func(change func(*Options)) *Plan {
		t.Helper()
		fake := llm.NewFake()
		fake.Remote = true
		o := agenticOpts(t, fake, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
		o.DryRun = true
		o.Config.Budget.USD, o.Config.Budget.USDSet = 2, true
		if change != nil {
			change(&o)
		}
		res, err := Run(context.Background(), o)
		if err != nil || res.Plan == nil {
			t.Fatalf("plan = %+v, err = %v", res.Plan, err)
		}
		if len(fake.Requests) != 0 {
			t.Fatal("a dry run called the model")
		}
		return res.Plan
	}
	const want = "A real run with these settings would be refused: the dollar cap of $2.00 cannot be enforced"
	if p := plan(nil); !containsNote(p.Notes, want) || !containsNote(p.Notes, "--allow-unpriced") {
		t.Fatalf("notes = %q, want the refusal of the real run", p.Notes)
	}
	// The real run is not refused when the operator opted in, or when
	// somebody is there to confirm the estimate.
	if p := plan(func(o *Options) { o.Config.Budget.AllowUnpriced = true }); containsNote(p.Notes, "would be refused") {
		t.Fatalf("opted in: notes = %q", p.Notes)
	}
	if p := plan(func(o *Options) { o.Confirm = func(Estimate) bool { return true } }); containsNote(p.Notes, "would be refused") {
		t.Fatalf("with a confirmation: notes = %q", p.Notes)
	}
}
