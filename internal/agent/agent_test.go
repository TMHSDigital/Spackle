package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
)

const appPy = `import sqlite3

def search(conn, q):
    sql = f"SELECT id, title FROM notes WHERE title LIKE '%{q}%'"
    return conn.execute(sql).fetchall()

def get(conn, note_id):
    return conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
`

const critVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

type fixture struct {
	root   string
	runner *Runner
	fake   *llm.Fake
	sealer *envelope.Sealer
	reg    *tools.Registry
	ledDir string
	led    *ledger.Writer
}

func setup(t *testing.T, caps budget.Caps, script ...llm.Response) *fixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "my app")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte(appPy), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file next to the target that no tool may ever read.
	if err := os.WriteFile(filepath.Join(base, "outside-secret.txt"), []byte("TOP-SECRET-OUTSIDE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ledDir := filepath.Join(base, "run")
	led, err := ledger.Create(ledDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	if caps.Tokens == 0 {
		caps = budget.Caps{Tokens: 1_000_000, USD: 5, Wall: time.Hour, SandboxRuns: 5}
	}
	bud, err := budget.New(caps, nil)
	if err != nil {
		t.Fatal(err)
	}
	fake := llm.NewFake(script...)
	sealer := envelope.NewWithNonce("testnonce")
	return &fixture{
		root: root, fake: fake, sealer: sealer, ledDir: ledDir, led: led,
		reg:    tools.NewRegistry(tools.Env{Root: root, Sealer: sealer}),
		runner: &Runner{Provider: llm.NewRedacting(fake), Pricer: llm.NewPricer(nil), Budget: bud, Ledger: led, Stage: "investigator", MaxTurns: 6},
	}
}

func (f *fixture) events(t *testing.T) map[string]int {
	t.Helper()
	_ = f.led.Close()
	evs, err := ledger.Read(f.ledDir)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range evs {
		counts[e.Type]++
	}
	return counts
}

func draftJSON(mutate func(map[string]any)) string {
	d := map[string]any{
		"title": "SQL injection in note search", "class": "sql-injection", "cwe": []string{"CWE-89"},
		"file": "app.py", "start_line": 4, "end_line": 5, "symbol": "search",
		"cvss_vector": critVector, "severity_reasoning": "Reachable without authentication.",
		"description": "The q value is formatted into the SQL text.",
		"flow": []map[string]any{
			{"role": "source", "file": "app.py", "line": 3, "quote": "def search(conn, q):", "note": "q comes from the request"},
			{"role": "sink", "file": "app.py", "line": 4, "quote": `sql = f"SELECT id, title FROM notes WHERE title LIKE '%{q}%'"`, "note": "interpolated"},
		},
		"preconditions": []string{"Network access to the search endpoint"},
		"attack_steps":  []string{"Send a q value that closes the string literal"},
		"gains":         []string{"Read any table"},
		"fix_summary":   "Use a bound parameter for q.", "fix_why": "The value no longer changes the statement.",
		"confidence": "high", "confidence_reason": "Read source to sink.",
	}
	if mutate != nil {
		mutate(d)
	}
	b, _ := json.Marshal(map[string]any{"verdict": "finding", "finding": d})
	return string(b)
}

var intent = Intent{ID: "I-01", Title: "Search query", Hypothesis: "Does q reach SQL?", Files: []string{"app.py"}, LeadIDs: []string{"L-1"}}
var leads = []seed.Lead{{ID: "L-1", Source: "builtin-code", RuleID: "py-sql-fstring-var", Title: "SQL built with an f-string", Class: "sql-injection", File: "app.py", Line: 4}}

func investigate(t *testing.T, f *fixture) Investigation {
	t.Helper()
	inv, err := Investigate(context.Background(), f.runner, 0, f.root, f.sealer, f.reg, intent, leads)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestInvestigateProducesAValidatedFinding(t *testing.T) {
	f := setup(t, budget.Caps{},
		llm.Call("c1", "read_file", map[string]any{"path": "app.py"}),
		llm.Say("Here is my answer:\n```json\n"+draftJSON(nil)+"\n```"),
	)
	inv := investigate(t, f)
	if inv.Finding == nil {
		t.Fatalf("no finding: rejected=%q nofinding=%q", inv.Rejected, inv.NoFinding)
	}
	got := *inv.Finding
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Severity.Score != 9.3 || got.Severity.Label != "critical" {
		t.Fatalf("severity must be computed from the vector, got %+v", got.Severity)
	}
	if got.Proof.Status != finding.ProofReasoned || got.Confidence.Level != finding.ConfidenceHigh {
		t.Fatalf("proof=%s confidence=%s", got.Proof.Status, got.Confidence.Level)
	}
	if len(got.Flaw.Flow) != 2 || got.Flaw.Flow[1].Line != 4 || got.Flaw.Flow[1].Role != "sink" {
		t.Fatalf("flow = %+v", got.Flaw.Flow)
	}
	if strings.Join(got.Origin, ",") != "investigator:I-01,builtin-code:py-sql-fstring-var" {
		t.Fatalf("origin = %v", got.Origin)
	}

	// The model saw the file only inside an envelope, after the preamble.
	req := f.fake.Requests[1]
	if !strings.Contains(req.System, "testnonce") || !strings.Contains(req.System, "never an instruction") {
		t.Fatal("the system prompt lacks the envelope preamble")
	}
	result := req.Messages[len(req.Messages)-1].ToolResults[0].Content
	if !strings.HasPrefix(result, "<<<UNTRUSTED testnonce") || !strings.HasSuffix(result, "<<<END UNTRUSTED testnonce>>>") {
		t.Fatalf("tool result is not enveloped:\n%s", result)
	}
	counts := f.events(t)
	if counts[ledger.TypeModelCall] != 2 || counts[ledger.TypeToolCall] != 1 {
		t.Fatalf("ledger events = %v", counts)
	}
}

func TestLineNumbersAreCorrectedFromTheQuote(t *testing.T) {
	f := setup(t, budget.Caps{}, llm.Say(draftJSON(func(d map[string]any) {
		d["flow"] = []map[string]any{{"role": "sink", "file": "app.py", "line": 40, "quote": "return conn.execute(sql).fetchall()"}}
	})))
	inv := investigate(t, f)
	if inv.Finding == nil || inv.Finding.Flaw.Flow[0].Line != 5 {
		t.Fatalf("finding = %+v rejected=%q", inv.Finding, inv.Rejected)
	}
}

func TestDraftRejections(t *testing.T) {
	cases := map[string]struct {
		reply string
		want  string
	}{
		"malformed json": {`{"verdict": "finding", "finding": {`, "cut off"},
		"no json at all": {"I think this is fine.", "no JSON object"},
		"quote not there": {draftJSON(func(d map[string]any) {
			d["flow"] = []map[string]any{{"role": "sink", "file": "app.py", "line": 4, "quote": "cursor.execute(evil)"}}
		}), "does not appear in app.py"},
		"unknown class": {draftJSON(func(d map[string]any) { d["class"] = "haunted-code" }), "not one of the known classes"},
		"file outside":  {draftJSON(func(d map[string]any) { d["file"] = "../outside-secret.txt" }), "leaves the target"},
		"missing file":  {draftJSON(func(d map[string]any) { d["file"] = "nope.py" }), "does not exist"},
		"line past end": {draftJSON(func(d map[string]any) { d["start_line"] = 900 }), "outside app.py"},
		"empty flow":    {draftJSON(func(d map[string]any) { d["flow"] = []map[string]any{} }), "flow is empty"},
		"no fix":        {draftJSON(func(d map[string]any) { d["fix_summary"] = "" }), "fix_summary"},
		"bad verdict":   {`{"verdict":"maybe"}`, "not finding or no_finding"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// The same bad answer twice: once, then again after the correction.
			f := setup(t, budget.Caps{}, llm.Say(tc.reply), llm.Say(tc.reply))
			inv := investigate(t, f)
			if inv.Finding != nil || inv.NoFinding != "" {
				t.Fatalf("a bad draft produced a result: %+v", inv)
			}
			if !strings.Contains(inv.Rejected, tc.want) {
				t.Fatalf("rejected = %q, want it to contain %q", inv.Rejected, tc.want)
			}
			if strings.Contains(inv.Rejected, "TOP-SECRET-OUTSIDE") {
				t.Fatal("the rejection leaks content from outside the target")
			}
			// The second request told the model what was wrong.
			if len(f.fake.Requests) != 2 || !strings.Contains(f.fake.Requests[1].Messages[0].Text, "could not be used") {
				t.Fatalf("no correction request was sent (requests: %d)", len(f.fake.Requests))
			}
			if f.events(t)[ledger.TypeReject] != 1 {
				t.Fatal("the rejection was not written to the ledger")
			}
		})
	}
}

func TestInvalidVectorFallsBackToTheClassDefault(t *testing.T) {
	for _, vec := range []string{"CVSS:4.0/AV:Q", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ""} {
		f := setup(t, budget.Caps{}, llm.Say(draftJSON(func(d map[string]any) { d["cvss_vector"] = vec })))
		inv := investigate(t, f)
		if inv.Finding == nil {
			t.Fatalf("vector %q: the finding was discarded: %s", vec, inv.Rejected)
		}
		want, _ := finding.DefaultVector("sql-injection")
		if inv.Finding.Severity.Vector != want || !strings.Contains(inv.Finding.Severity.Reasoning, "invalid CVSS 4.0 vector") {
			t.Fatalf("vector %q: severity = %+v", vec, inv.Finding.Severity)
		}
	}
}

func TestCorrectionRoundCanSucceed(t *testing.T) {
	bad := draftJSON(func(d map[string]any) {
		d["flow"] = []map[string]any{{"role": "sink", "file": "app.py", "line": 4, "quote": "not in the file"}}
	})
	f := setup(t, budget.Caps{}, llm.Say(bad), llm.Say(draftJSON(nil)))
	if inv := investigate(t, f); inv.Finding == nil {
		t.Fatalf("the corrected draft was not accepted: %q", inv.Rejected)
	}
}

func TestNoFindingIsAResult(t *testing.T) {
	f := setup(t, budget.Caps{}, llm.Say(`{"verdict":"no_finding","reason":"The query on line 8 is parameterized."}`))
	inv := investigate(t, f)
	if inv.Finding != nil || inv.Rejected != "" || !strings.Contains(inv.NoFinding, "parameterized") {
		t.Fatalf("%+v", inv)
	}
}

func TestModelCannotAwardItselfDemonstrated(t *testing.T) {
	f := setup(t, budget.Caps{}, llm.Say(draftJSON(func(d map[string]any) { d["confidence"] = "demonstrated" })))
	inv := investigate(t, f)
	if inv.Finding == nil || inv.Finding.Confidence.Level != finding.ConfidencePlausible || inv.Finding.Proof.Status != finding.ProofReasoned {
		t.Fatalf("%+v", inv.Finding)
	}
}

// A compromised or confused model asks for things outside its sandbox. The
// loop must refuse each one, tell the model, and carry on.
func TestHostileToolRequestsAreRefusedAndTheRunContinues(t *testing.T) {
	f := setup(t, budget.Caps{},
		llm.Response{ToolCalls: []llm.ToolCall{
			{ID: "1", Name: "read_file", Args: json.RawMessage(`{"path":"../outside-secret.txt"}`)},
			{ID: "2", Name: "run_shell", Args: json.RawMessage(`{"cmd":"cat /etc/passwd"}`)},
			{ID: "3", Name: "read_file", Args: json.RawMessage(`{"path":"app.py","budget_usd":9999}`)},
			{ID: "4", Name: "read_file", Args: json.RawMessage(`not json`)},
		}},
		llm.Say(`{"verdict":"no_finding","reason":"nothing"}`),
	)
	inv := investigate(t, f)
	if inv.NoFinding == "" {
		t.Fatalf("the run did not continue: %+v", inv)
	}
	results := f.fake.Requests[1].Messages[2].ToolResults
	if len(results) != 4 {
		t.Fatalf("got %d tool results, want 4", len(results))
	}
	for i, r := range results {
		if !r.IsError {
			t.Errorf("request %d was not refused: %s", i+1, r.Content)
		}
	}
	if strings.Contains(f.fake.Sent(), "TOP-SECRET-OUTSIDE") {
		t.Fatal("content from outside the target reached the model")
	}
}

func TestTurnLimitAsksForAFinalAnswer(t *testing.T) {
	var script []llm.Response
	for i := 0; i < 6; i++ {
		script = append(script, llm.Call("c", "grep", map[string]any{"pattern": "x" + strings.Repeat("y", i)}))
	}
	script = append(script, llm.Say(`{"verdict":"no_finding","reason":"ran out of turns"}`))
	f := setup(t, budget.Caps{}, script...)
	inv := investigate(t, f)
	if inv.NoFinding == "" {
		t.Fatalf("%+v", inv)
	}
	last := f.fake.Requests[len(f.fake.Requests)-1]
	// The history holds tool calls, so the request must still define the
	// tools: a provider refuses it otherwise. The nudge asks for the answer.
	if len(last.Tools) == 0 || !strings.Contains(last.Messages[len(last.Messages)-1].Text, "Stop using tools") {
		t.Fatal("the final request should keep the tool definitions and ask for the answer")
	}
}

func TestStagnationStopsARepeatingModel(t *testing.T) {
	same := llm.Call("c", "grep", map[string]any{"pattern": "SELECT"})
	f := setup(t, budget.Caps{}, same, same, same, same, same, llm.Say(`{"verdict":"no_finding","reason":"stuck"}`))
	f.runner.MaxTurns = 50
	out, err := f.runner.Run(context.Background(), 0, "sys", "user", f.reg)
	if err != nil || out.Stopped != StopStagnation || out.Turns != 5 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestBudgetExhaustionStopsTheLoop(t *testing.T) {
	f := setup(t, budget.Caps{Tokens: 50, USD: 5, Wall: time.Hour, SandboxRuns: 1},
		llm.Response{ToolCalls: []llm.ToolCall{{ID: "1", Name: "read_file", Args: json.RawMessage(`{"path":"app.py"}`)}}, Usage: llm.Usage{InputTokens: 40, OutputTokens: 20, CostKnown: true}},
		llm.Say("never reached"),
	)
	_, err := Investigate(context.Background(), f.runner, 0, f.root, f.sealer, f.reg, intent, leads)
	if !errors.Is(err, budget.ErrExhausted) {
		t.Fatalf("err = %v, want ErrExhausted", err)
	}
	if len(f.fake.Requests) != 1 {
		t.Fatalf("made %d model calls after the cap was reached", len(f.fake.Requests)-1)
	}
}

func TestRefusalIsRecordedNotRetried(t *testing.T) {
	f := setup(t, budget.Caps{}, llm.Response{StopReason: llm.StopRefusal, RefusalNote: "cyber"})
	inv := investigate(t, f)
	if !strings.Contains(inv.Rejected, "declined") || len(f.fake.Requests) != 1 {
		t.Fatalf("inv=%+v requests=%d", inv, len(f.fake.Requests))
	}
}

func TestSecretsInTargetNeverReachTheModel(t *testing.T) {
	secret := "tr0ub4dor-" + "fixture-9Zq2Lm7x"
	f := setup(t, budget.Caps{},
		llm.Call("1", "read_file", map[string]any{"path": "settings.py"}),
		llm.Call("2", "grep", map[string]any{"pattern": "PASSWORD"}),
		llm.Say(`{"verdict":"no_finding","reason":"x"}`),
	)
	if err := os.WriteFile(filepath.Join(f.root, "settings.py"), []byte("DB_PASSWORD = \""+secret+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.reg = tools.NewRegistry(tools.Env{Root: f.root, Sealer: f.sealer})
	investigate(t, f)
	if strings.Contains(f.fake.Sent(), secret) {
		t.Fatal("a secret value from the target was sent to the model")
	}
	if !strings.Contains(f.fake.Sent(), "[REDACTED:") {
		t.Fatal("expected a redaction marker in what the model saw")
	}
}

func baseFinding(t *testing.T) finding.Finding {
	t.Helper()
	f := setup(t, budget.Caps{}, llm.Say(draftJSON(nil)))
	inv := investigate(t, f)
	if inv.Finding == nil {
		t.Fatal(inv.Rejected)
	}
	return *inv.Finding
}

func TestReviewVerdicts(t *testing.T) {
	fnd := baseFinding(t)
	lowVector := "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	cases := []struct {
		name, reply       string
		verdict, status   string
		confidence, inRsn string
	}{
		{"confirmed", `{"verdict":"confirmed","reason":"q is formatted into the query"}`, ReviewConfirmed, finding.StatusOpen, finding.ConfidenceHigh, "independent review"},
		{"refuted", `{"verdict":"refuted","reason":"search is never called with request data"}`, ReviewRefuted, finding.StatusDismissed, finding.ConfidenceHigh, ""},
		{"uncertain", `{"verdict":"uncertain","reason":"could not find the caller"}`, ReviewUncertain, finding.StatusOpen, finding.ConfidencePlausible, "could not confirm"},
		{"refuted with no reason is kept", `{"verdict":"refuted","reason":""}`, ReviewUncertain, finding.StatusOpen, finding.ConfidencePlausible, ""},
		{"garbage is uncertain", `LGTM`, ReviewUncertain, finding.StatusOpen, finding.ConfidencePlausible, ""},
		{"severity corrected", `{"verdict":"confirmed","reason":"needs admin","cvss_vector":"` + lowVector + `"}`, ReviewConfirmed, finding.StatusOpen, finding.ConfidenceHigh, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, budget.Caps{}, llm.Say(tc.reply))
			f.runner.Stage = "reviewer"
			rev, err := ReviewFinding(context.Background(), f.runner, 0, f.sealer, f.reg, fnd)
			if err != nil {
				t.Fatal(err)
			}
			got := ApplyReview(fnd, rev)
			if rev.Verdict != tc.verdict || got.Status != tc.status || got.Confidence.Level != tc.confidence {
				t.Fatalf("verdict=%s status=%s confidence=%s", rev.Verdict, got.Status, got.Confidence.Level)
			}
			if tc.inRsn != "" && !strings.Contains(got.Confidence.Reason, tc.inRsn) {
				t.Fatalf("confidence reason = %q", got.Confidence.Reason)
			}
			if got.Status == finding.StatusDismissed && got.DismissReason == "" {
				t.Fatal("a dismissal must keep its reason")
			}
			if tc.name == "severity corrected" && (got.Severity.Vector != lowVector || got.Severity.Label == "critical") {
				t.Fatalf("severity = %+v", got.Severity)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("reviewed finding is invalid: %v", err)
			}
			// The reviewer must not see the investigator's confidence or reasoning.
			sent := f.fake.Requests[0].Messages[0].Text
			if strings.Contains(sent, "Read source to sink") || strings.Contains(sent, "confidence") {
				t.Fatal("the reviewer was shown the investigator's confidence")
			}
		})
	}
}

func TestPlanValidatesAgainstTheRealTarget(t *testing.T) {
	reply := `{"intents":[
	 {"title":"Search","class":"sql-injection","hypothesis":"q to SQL?","files":["app.py","ghost.py"],"lead_ids":["L-1","L-999"],"priority":2},
	 {"title":"Imaginary","hypothesis":"x","files":["../../etc/passwd"],"priority":1},
	 {"title":"Odd class","class":"vibes","hypothesis":"y","files":["./app.py"],"priority":9}]}`
	f := setup(t, budget.Caps{}, llm.Say(reply))
	m, err := mapper.Build(context.Background(), f.root, mapper.Options{})
	if err != nil {
		t.Fatal(err)
	}
	intents, err := Plan(context.Background(), f.runner, 0, f.sealer, m, leads, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 2 {
		t.Fatalf("intents = %+v", intents)
	}
	if intents[0].Title != "Search" || strings.Join(intents[0].Files, ",") != "app.py" || strings.Join(intents[0].LeadIDs, ",") != "L-1" || intents[0].ID != "I-01" {
		t.Fatalf("first intent = %+v", intents[0])
	}
	if intents[1].Class != "" || intents[1].Priority != 3 || intents[1].Source != "planner" {
		t.Fatalf("second intent = %+v", intents[1])
	}
	// Planner input is enveloped: file names and snippets come from the target.
	if !strings.Contains(f.fake.Requests[0].Messages[0].Text, "<<<UNTRUSTED testnonce") {
		t.Fatal("planner input is not enveloped")
	}
}

func TestFallbackPlanGroupsLeads(t *testing.T) {
	f := setup(t, budget.Caps{})
	m, _ := mapper.Build(context.Background(), f.root, mapper.Options{})
	ls := []seed.Lead{
		{ID: "a", Title: "MD5", Class: "weak-hash", Severity: "medium", File: "app.py", Line: 2},
		{ID: "b", Title: "SQL", Class: "sql-injection", Severity: "critical", File: "app.py", Line: 4},
		{ID: "c", Title: "SQL again", Class: "sql-injection", Severity: "high", File: "app.py", Line: 5},
		{ID: "d", Title: "Elsewhere", Class: "xss", Severity: "high", File: "gone.py", Line: 1},
	}
	intents := FallbackPlan(m, ls, 10)
	if len(intents) != 2 || intents[0].Class != "sql-injection" || len(intents[0].LeadIDs) != 2 || intents[0].Source != "fallback" {
		t.Fatalf("intents = %+v", intents)
	}
}

func TestCorrelateLinksOnlyKnownFindings(t *testing.T) {
	a := baseFinding(t)
	b := a
	b.ID, b.Title = "SPK-BBBBBBBB", "Hardcoded key"
	reply := `{"chains":[{"ids":["` + a.ID + `","SPK-BBBBBBBB","SPK-NOPE"],"narrative":"Read the key with the injection, then forge tokens."},
	                      {"ids":["SPK-NOPE"],"narrative":"ignored"}]}`
	f := setup(t, budget.Caps{}, llm.Say(reply))
	out, err := Correlate(context.Background(), f.runner, 0, f.sealer, []finding.Finding{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].BlastRadius.KillChain == "" || strings.Join(out[0].BlastRadius.Related, ",") != "SPK-BBBBBBBB" || strings.Join(out[1].BlastRadius.Related, ",") != a.ID {
		t.Fatalf("%+v / %+v", out[0].BlastRadius, out[1].BlastRadius)
	}
}

func TestExtractJSON(t *testing.T) {
	good := map[string]string{
		`{"a":1}`:                               `{"a":1}`,
		"text before {\"a\":{\"b\":2}} after":   `{"a":{"b":2}}`,
		"```json\n{\"a\":\"}{\"}\n```":          `{"a":"}{"}`,
		`{"a":"quote \" and brace }"} trailing`: `{"a":"quote \" and brace }"}`,
	}
	for in, want := range good {
		got, err := extractJSON(in)
		if err != nil || string(got) != want {
			t.Errorf("extractJSON(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "no json", `{"a":`, `{"a": tru}`} {
		if _, err := extractJSON(in); err == nil {
			t.Errorf("extractJSON(%q) should fail", in)
		}
	}
}

func TestQuoteCheckUsesTheRedactedViewAndRefusesFragments(t *testing.T) {
	root := t.TempDir()
	secret := "sk_live_" + "9aB3xQ7mLp2Zr8Tn5Vw1Yc4D"
	src := "import os\n\nSECRET_KEY = \"" + secret + "\"\n\ndef sign(payload):\n    return hmac_sign(SECRET_KEY, payload)\n"
	if err := os.WriteFile(filepath.Join(root, "settings.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := readLines(root, "settings.py")
	if err != nil {
		t.Fatal(err)
	}
	shown := lines[2]
	if strings.Contains(shown, secret) || !strings.Contains(shown, "[REDACTED:") {
		t.Fatalf("the line is not redacted the way the tools show it: %q", shown)
	}
	// The line as the model saw it, marker included, validates.
	if line, ok := locateQuote(lines, shown, 3); !ok || line != 3 {
		t.Fatalf("a quote of the redacted line was refused (line %d, ok %v)", line, ok)
	}
	// A fragment that would match almost any file does not.
	for _, frag := range []string{")", "=", "os", "return"} {
		if _, ok := locateQuote(lines, frag, 6); ok {
			t.Errorf("the fragment %q was accepted as a quote", frag)
		}
	}
	// A short line can still be quoted whole, and most of a long line is enough.
	if _, ok := locateQuote(lines, "import os", 1); !ok {
		t.Error("a whole short line was refused")
	}
	if _, ok := locateQuote(lines, "hmac_sign(SECRET_KEY, payload)", 6); !ok {
		t.Error("most of a long line was refused")
	}
}

func TestOverLongQuotesAreRefusedBeforeSearching(t *testing.T) {
	lines := []string{"def f(x):", "    return run_query(x, limit=10)", ""}
	if _, ok := locateQuote(lines, strings.Repeat("return run_query(x, limit=10) ", 200), 2); ok {
		t.Error("a quote far longer than any line was accepted")
	}
	if _, ok := locateQuote(lines, strings.Repeat("x\n", maxQuoteLines+1), 1); ok {
		t.Error("a quote with too many lines was accepted")
	}
	// A two-line quote still matches across the line break.
	if line, ok := locateQuote(lines, "def f(x):\n    return run_query(x, limit=10)", 1); !ok || line != 1 {
		t.Errorf("a two-line quote was refused (line %d, ok %v)", line, ok)
	}
}

// A fix must change the code, not the check. Every layout of test code is
// refused, including a top-level test directory.
func TestFixMayNotEditTestFiles(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"test/api.js", "spec/user_spec.rb", "conftest.py", "src/app.js"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{"test/api.js", "spec/user_spec.rb", "conftest.py"} {
		if _, _, err := loadOriginals(root, map[string]string{rel: "new"}); err == nil || !strings.Contains(err.Error(), "test or proof file") {
			t.Errorf("a fix that edits %s was accepted: %v", rel, err)
		}
	}
	if _, _, err := loadOriginals(root, map[string]string{"src/app.js": "new"}); err != nil {
		t.Errorf("a fix to ordinary code was refused: %v", err)
	}
}
