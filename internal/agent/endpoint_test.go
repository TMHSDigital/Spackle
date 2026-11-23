package agent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
)

const (
	probeVector    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"
	probeArtifact  = "evidence/exchanges/X-0001.json"
	probeExchanges = `{"id":"X-0001","method":"GET","url":"http://127.0.0.1:8080/search?q=spk-marker","status":200}`
)

// endpointFinding is a running-target finding the way a probe reports it:
// located by endpoint and parameter, with one recorded exchange as its proof.
func endpointFinding(t *testing.T) finding.Finding {
	t.Helper()
	sev, err := finding.SeverityFromVector(probeVector, "The default for this class.")
	if err != nil {
		t.Fatal(err)
	}
	loc := finding.Location{Method: "GET", Endpoint: "/search", Parameter: "q"}
	f := finding.Finding{
		ID: finding.MakeID("xss", loc), Title: "A marker sent in q came back unescaped", Surface: finding.SurfaceDAST, Class: "xss",
		Location: loc, Severity: sev,
		Flaw: finding.Flaw{Description: "The value of q is written into the page without escaping."},
		Proof: finding.Proof{
			Status: finding.ProofDemonstrated, Kind: "http-sequence", Artifacts: []string{probeArtifact},
			Result: "Results for <spk-marker>", Summary: "The behavior was observed in the recorded exchange(s) X-0001.",
		},
		Remediation: finding.Remediation{Summary: "Escape the value before writing it into HTML.", Verification: "unverified"},
		Confidence:  finding.Confidence{Level: finding.ConfidenceDemonstrated, Reason: "Observed directly in the recorded exchange."},
		Origin:      []string{"dast-baseline:reflected-marker"},
		Status:      finding.StatusOpen,
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("the test's own finding is invalid: %v", err)
	}
	return f
}

// knownIDs is the "was this exchange recorded" check the engine passes in.
func knownIDs(ids ...string) func(string) bool {
	return func(id string) bool { return containsStr(ids, id) }
}

// endpointJSON is a complete "confirmed" reply, changed by mutate.
func endpointJSON(mutate func(map[string]any)) string {
	d := map[string]any{
		"verdict": "confirmed", "reason": "A second marker came back unescaped as well.",
		"title":       "Reflected XSS in q on GET /search",
		"cvss_vector": critVector, "severity_reasoning": "No login is needed.",
		"description":      "The q parameter is echoed into the HTML body with no escaping.",
		"preconditions":    []string{"The victim opens a crafted link"},
		"attack_steps":     []string{"Send GET /search?q=<marker>", "The marker comes back unescaped"},
		"chains_into":      []string{"Session theft"},
		"gains":            []string{"Script execution in the victim's session"},
		"exposed":          []string{"Anything the page can read"},
		"fix_summary":      "HTML-escape q in the search template.",
		"fix_why":          "The value is then text, not markup.",
		"defense_in_depth": []string{"Set a Content-Security-Policy"},
		"evidence":         []string{"X-0001"},
	}
	if mutate != nil {
		mutate(d)
	}
	b, _ := json.Marshal(d)
	return string(b)
}

func assess(t *testing.T, fx *fixture, f finding.Finding, known func(string) bool) EndpointReview {
	t.Helper()
	rev, err := InvestigateEndpoint(context.Background(), fx.runner, 0, fx.sealer, nil, f, probeExchanges, known)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// assertUnchanged fails when a review that did not confirm anything carries
// a finding other than the one the probe reported.
func assertUnchanged(t *testing.T, rev EndpointReview, want finding.Finding) {
	t.Helper()
	if rev.Confirmed {
		t.Errorf("the review is marked confirmed: %+v", rev)
	}
	if !reflect.DeepEqual(rev.Finding, want) {
		t.Errorf("the finding was changed:\n got %+v\nwant %+v", rev.Finding, want)
	}
}

func TestEndpointConfirmedEnrichesTheFinding(t *testing.T) {
	f := endpointFinding(t)
	fx := setup(t, budget.Caps{}, llm.Say("My assessment:\n```json\n"+endpointJSON(nil)+"\n```"))
	rev := assess(t, fx, f, knownIDs("X-0001"))
	if !rev.Confirmed || rev.Rejected != "" {
		t.Fatalf("confirmed=%v rejected=%q", rev.Confirmed, rev.Rejected)
	}
	if rev.Reason != "A second marker came back unescaped as well." {
		t.Errorf("reason = %q", rev.Reason)
	}
	g := rev.Finding
	if err := g.Validate(); err != nil {
		t.Fatalf("the enriched finding is invalid: %v", err)
	}
	if g.ID != f.ID || g.Location != f.Location || g.Class != f.Class || g.Surface != f.Surface || g.Status != finding.StatusOpen {
		t.Errorf("identity changed: id %s location %s class %s surface %s status %s", g.ID, g.Location, g.Class, g.Surface, g.Status)
	}
	if g.Title != "Reflected XSS in q on GET /search" || g.Flaw.Description != "The q parameter is echoed into the HTML body with no escaping." {
		t.Errorf("title %q description %q", g.Title, g.Flaw.Description)
	}
	want, err := finding.SeverityFromVector(critVector, "No login is needed.")
	if err != nil {
		t.Fatal(err)
	}
	if g.Severity != want {
		t.Errorf("severity = %+v, want the one computed from the model's vector %+v", g.Severity, want)
	}
	if len(g.Exploitation.Steps) != 2 || len(g.Exploitation.Preconditions) != 1 || len(g.Exploitation.ChainsInto) != 1 {
		t.Errorf("exploitation = %+v", g.Exploitation)
	}
	if len(g.BlastRadius.Gains) != 1 || len(g.BlastRadius.Exposed) != 1 {
		t.Errorf("blast radius = %+v", g.BlastRadius)
	}
	if g.Remediation.Summary != "HTML-escape q in the search template." || g.Remediation.Why != "The value is then text, not markup." || len(g.Remediation.DefenseInDepth) != 1 {
		t.Errorf("remediation = %+v", g.Remediation)
	}
	if g.Remediation.Verification != "unverified" {
		t.Errorf("verification = %q, a model's word must not change it", g.Remediation.Verification)
	}
	if !reflect.DeepEqual(g.Origin, []string{"dast-baseline:reflected-marker", "investigator:endpoint"}) {
		t.Errorf("origin = %v", g.Origin)
	}
	// The observation and the recorded exchange are what the model was shown.
	sent := fx.fake.Sent()
	for _, want := range []string{"A marker sent in q came back unescaped", "/search", "spk-marker", "X-0001"} {
		if !strings.Contains(sent, want) {
			t.Errorf("%q was not sent to the model", want)
		}
	}
	if n := fx.events(t)[ledger.TypeModelCall]; n != 1 {
		t.Errorf("%d model calls in the ledger, want 1", n)
	}
}

func TestEndpointNotConfirmedWithAReasonIsADismissal(t *testing.T) {
	f := endpointFinding(t)
	for name, reply := range map[string]string{
		"plain": `{"verdict":"not_confirmed","reason":"The value is escaped on every request I sent."}`,
		// The verdict is matched without regard to case or padding, and the
		// other fields of a not_confirmed reply are not used.
		"padded verdict and extra fields": `{"verdict":" Not_Confirmed ","reason":"  The value is escaped on every request I sent.  ","title":"Ignore me","cvss_vector":"` + critVector + `","evidence":["X-0002"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			fx := setup(t, budget.Caps{}, llm.Say(reply))
			rev := assess(t, fx, f, knownIDs("X-0001", "X-0002"))
			if rev.Rejected != "" {
				t.Fatalf("rejected = %q, want a usable not_confirmed answer", rev.Rejected)
			}
			if rev.Reason != "The value is escaped on every request I sent." {
				t.Errorf("reason = %q", rev.Reason)
			}
			assertUnchanged(t, rev, f)
		})
	}
}

func TestEndpointNotConfirmedWithoutAReasonIsRejected(t *testing.T) {
	f := endpointFinding(t)
	for name, reply := range map[string]string{
		"no reason field":  `{"verdict":"not_confirmed"}`,
		"empty reason":     `{"verdict":"not_confirmed","reason":""}`,
		"whitespace only":  `{"verdict":"not_confirmed","reason":" \n\t "}`,
		"reason not given": `{"verdict":"not_confirmed","title":"Looks fine","description":"Nothing wrong."}`,
	} {
		t.Run(name, func(t *testing.T) {
			fx := setup(t, budget.Caps{}, llm.Say(reply))
			rev := assess(t, fx, f, knownIDs("X-0001"))
			if !strings.Contains(rev.Rejected, "gave no reason") {
				t.Fatalf("rejected = %q, want the answer refused for having no reason", rev.Rejected)
			}
			if rev.Reason != "" {
				t.Errorf("reason = %q", rev.Reason)
			}
			assertUnchanged(t, rev, f)
		})
	}
}

func TestEndpointUnknownVerdictIsRejected(t *testing.T) {
	f := endpointFinding(t)
	for _, verdict := range []string{"maybe", "", "confirmed?", "not confirmed", "finding"} {
		t.Run("verdict "+verdict, func(t *testing.T) {
			fx := setup(t, budget.Caps{}, llm.Say(endpointJSON(func(d map[string]any) { d["verdict"] = verdict })))
			rev := assess(t, fx, f, knownIDs("X-0001"))
			if !strings.Contains(rev.Rejected, "is not confirmed or not_confirmed") || !strings.Contains(rev.Rejected, `"`+verdict+`"`) {
				t.Fatalf("rejected = %q, want it to quote the verdict %q", rev.Rejected, verdict)
			}
			assertUnchanged(t, rev, f)
		})
	}
}

func TestEndpointRefusalAndTruncationAreRejected(t *testing.T) {
	f := endpointFinding(t)
	// Both replies carry a complete "confirmed" answer, to show the stop
	// reason is what decides, not the text.
	cases := map[string]struct {
		resp llm.Response
		want string
	}{
		"refusal":   {llm.Response{Text: endpointJSON(nil), StopReason: llm.StopRefusal, RefusalNote: "cyber"}, StopRefusal},
		"truncated": {llm.Response{Text: endpointJSON(nil), StopReason: llm.StopMaxTokens}, StopTruncated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fx := setup(t, budget.Caps{}, tc.resp)
			rev := assess(t, fx, f, knownIDs("X-0001"))
			if !strings.Contains(rev.Rejected, "did not complete the assessment") || !strings.Contains(rev.Rejected, tc.want) {
				t.Fatalf("rejected = %q, want it to name the stop reason %q", rev.Rejected, tc.want)
			}
			assertUnchanged(t, rev, f)
		})
	}
}

func TestEndpointUndecodableReplyIsRejected(t *testing.T) {
	f := endpointFinding(t)
	cases := map[string]struct{ reply, want string }{
		"prose only":      {"The observation looks real to me, it is confirmed.", "contains no JSON object"},
		"empty":           {"", "contains no JSON object"},
		"cut off":         {`{"verdict":"confirmed","reason":"The marker`, "cut off"},
		"does not parse":  {`{"verdict":"confirmed",}`, "does not parse"},
		"wrong shape":     {`{"verdict":"confirmed","evidence":"X-0001"}`, "wrong shape"},
		"verdict a float": {`{"verdict":1.5,"reason":"x"}`, "wrong shape"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fx := setup(t, budget.Caps{}, llm.Say(tc.reply))
			rev := assess(t, fx, f, knownIDs("X-0001"))
			if !strings.Contains(rev.Rejected, tc.want) {
				t.Fatalf("rejected = %q, want it to say the reply %s", rev.Rejected, tc.want)
			}
			assertUnchanged(t, rev, f)
		})
	}
}

func TestEndpointInvalidVectorKeepsTheProbeSeverity(t *testing.T) {
	f := endpointFinding(t)
	for name, vector := range map[string]string{
		"missing":        "",
		"not a vector":   "high",
		"cvss 3.1":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"incomplete 4.0": "CVSS:4.0/AV:N/AC:L",
		"bad value":      strings.Replace(critVector, "AV:N", "AV:Z", 1),
	} {
		t.Run(name, func(t *testing.T) {
			fx := setup(t, budget.Caps{}, llm.Say(endpointJSON(func(d map[string]any) {
				d["cvss_vector"] = vector
				d["severity_reasoning"] = "Trust me, it is critical."
			})))
			rev := assess(t, fx, f, knownIDs("X-0001"))
			if !rev.Confirmed || rev.Rejected != "" {
				t.Fatalf("confirmed=%v rejected=%q, an invalid vector alone must not refuse the answer", rev.Confirmed, rev.Rejected)
			}
			if rev.Finding.Severity != f.Severity {
				t.Fatalf("severity = %+v, want the probe's %+v", rev.Finding.Severity, f.Severity)
			}
			// The rest of the answer is still used.
			if rev.Finding.Title != "Reflected XSS in q on GET /search" {
				t.Errorf("title = %q", rev.Finding.Title)
			}
			if err := rev.Finding.Validate(); err != nil {
				t.Errorf("invalid: %v", err)
			}
		})
	}
}

func TestEndpointEvidenceMustBeRecordedAndIsNotDuplicated(t *testing.T) {
	f := endpointFinding(t)
	fx := setup(t, budget.Caps{}, llm.Say(endpointJSON(func(d map[string]any) {
		d["evidence"] = []string{
			"X-0001",                  // already cited by the probe
			"X-9999",                  // never recorded
			"X-0002",                  // recorded by a follow-up request
			" X-0002 ",                // the same id again, padded
			"X-0003",                  // recorded
			"../../ledger",            // not an id at all
			"",                        // empty
			"X-0003",                  // again
			"evidence/exchanges/X-04", // a path, not an id
		}
	})))
	asked := map[string]int{}
	known := func(id string) bool {
		asked[id]++
		return id == "X-0001" || id == "X-0002" || id == "X-0003"
	}
	rev := assess(t, fx, f, known)
	if !rev.Confirmed {
		t.Fatalf("rejected = %q", rev.Rejected)
	}
	want := []string{probeArtifact, "evidence/exchanges/X-0002.json", "evidence/exchanges/X-0003.json"}
	if !reflect.DeepEqual(rev.Finding.Proof.Artifacts, want) {
		t.Fatalf("artifacts = %v, want %v", rev.Finding.Proof.Artifacts, want)
	}
	// Ids are trimmed before they are looked up.
	if asked[" X-0002 "] != 0 || asked["X-0002"] != 2 {
		t.Errorf("lookups = %v, want the padded id looked up without its padding", asked)
	}
	if !reflect.DeepEqual(f.Proof.Artifacts, []string{probeArtifact}) {
		t.Errorf("the caller's finding was changed: %v", f.Proof.Artifacts)
	}

	t.Run("nothing known", func(t *testing.T) {
		fx := setup(t, budget.Caps{}, llm.Say(endpointJSON(func(d map[string]any) { d["evidence"] = []string{"X-0002", "X-0003"} })))
		rev := assess(t, fx, f, knownIDs())
		if !rev.Confirmed || !reflect.DeepEqual(rev.Finding.Proof.Artifacts, []string{probeArtifact}) {
			t.Fatalf("confirmed=%v artifacts=%v, want only the probe's own evidence", rev.Confirmed, rev.Finding.Proof.Artifacts)
		}
	})
}

func TestEndpointOverlongAnswerIsClipped(t *testing.T) {
	f := endpointFinding(t)
	long := func(n int) string { return strings.Repeat("a", n) }
	// Each list is over its item limit, holds blanks that must be dropped,
	// and has one item over the per-item length limit.
	list := func(n, itemLen int) []string {
		out := []string{"", "   ", long(itemLen + 50)}
		for len(out) < n+5 {
			out = append(out, "  short item  ")
		}
		return out
	}
	fx := setup(t, budget.Caps{}, llm.Say(endpointJSON(func(d map[string]any) {
		d["reason"] = long(1500)
		d["title"] = long(300)
		d["description"] = long(2500)
		d["severity_reasoning"] = long(900)
		d["fix_summary"] = long(1300)
		d["fix_why"] = long(1300)
		d["preconditions"] = list(8, 400)
		d["attack_steps"] = list(12, 600)
		d["chains_into"] = list(6, 400)
		d["gains"] = list(8, 400)
		d["exposed"] = list(8, 400)
		d["defense_in_depth"] = list(6, 400)
	})))
	rev := assess(t, fx, f, knownIDs("X-0001"))
	if !rev.Confirmed {
		t.Fatalf("rejected = %q", rev.Rejected)
	}
	g := rev.Finding
	if err := g.Validate(); err != nil {
		t.Fatalf("invalid: %v", err)
	}
	// A clipped text is its limit plus the three-character mark.
	texts := []struct {
		name  string
		got   string
		limit int
	}{
		{"reason", rev.Reason, 1000},
		{"title", g.Title, 200},
		{"description", g.Flaw.Description, 2000},
		{"severity reasoning", g.Severity.Reasoning, 800},
		{"fix summary", g.Remediation.Summary, 1200},
		{"fix why", g.Remediation.Why, 1200},
	}
	for _, c := range texts {
		if want := long(c.limit) + "..."; c.got != want {
			t.Errorf("%s is %d bytes, want it clipped to %d plus the mark", c.name, len(c.got), c.limit)
		}
	}
	lists := []struct {
		name     string
		got      []string
		maxItems int
		maxLen   int
	}{
		{"preconditions", g.Exploitation.Preconditions, 8, 400},
		{"attack steps", g.Exploitation.Steps, 12, 600},
		{"chains into", g.Exploitation.ChainsInto, 6, 400},
		{"gains", g.BlastRadius.Gains, 8, 400},
		{"exposed", g.BlastRadius.Exposed, 8, 400},
		{"defense in depth", g.Remediation.DefenseInDepth, 6, 400},
	}
	for _, c := range lists {
		if len(c.got) != c.maxItems {
			t.Errorf("%s has %d items, want %d", c.name, len(c.got), c.maxItems)
			continue
		}
		if want := long(c.maxLen) + "..."; c.got[0] != want {
			t.Errorf("%s[0] is %d bytes, want it clipped to %d plus the mark", c.name, len(c.got[0]), c.maxLen)
		}
		for i, item := range c.got[1:] {
			if item != "short item" {
				t.Errorf("%s[%d] = %q, want blanks dropped and items trimmed", c.name, i+1, item)
			}
		}
	}
}

func TestEndpointEmptyFieldsKeepWhatTheProbeReported(t *testing.T) {
	f := endpointFinding(t)
	fx := setup(t, budget.Caps{}, llm.Say(`{"verdict":"confirmed","reason":"Seen again.","title":"  ","description":"","fix_summary":" "}`))
	rev := assess(t, fx, f, knownIDs("X-0001"))
	if !rev.Confirmed {
		t.Fatalf("rejected = %q", rev.Rejected)
	}
	g := rev.Finding
	if g.Title != f.Title || g.Flaw.Description != f.Flaw.Description || g.Remediation.Summary != f.Remediation.Summary || g.Severity != f.Severity {
		t.Errorf("an empty field replaced the probe's value: title %q description %q fix %q severity %+v", g.Title, g.Flaw.Description, g.Remediation.Summary, g.Severity)
	}
	if !reflect.DeepEqual(g.Proof, f.Proof) {
		t.Errorf("proof = %+v", g.Proof)
	}
	if err := g.Validate(); err != nil {
		t.Errorf("invalid: %v", err)
	}
}

func TestEndpointInvalidFindingAfterEnrichmentIsRejected(t *testing.T) {
	// Nothing a model can write makes a valid probe finding invalid, so the
	// check is reached with a finding that was already incomplete.
	f := endpointFinding(t)
	f.Confidence.Reason = ""
	fx := setup(t, budget.Caps{}, llm.Say(endpointJSON(nil)))
	rev := assess(t, fx, f, knownIDs("X-0001"))
	if !strings.HasPrefix(rev.Rejected, "the assessment produced an invalid finding: ") || !strings.Contains(rev.Rejected, "confidence has no reason") {
		t.Fatalf("rejected = %q", rev.Rejected)
	}
	// The enriched copy is thrown away, not half-applied.
	assertUnchanged(t, rev, f)
}

func TestEndpointProviderAndBudgetErrorsAreReturned(t *testing.T) {
	f := endpointFinding(t)

	t.Run("provider error", func(t *testing.T) {
		fx := setup(t, budget.Caps{}) // an empty script fails the first call
		rev, err := InvestigateEndpoint(context.Background(), fx.runner, 0, fx.sealer, nil, f, probeExchanges, knownIDs("X-0001"))
		if err == nil || !strings.Contains(err.Error(), "script exhausted") {
			t.Fatalf("err = %v, want the provider's error", err)
		}
		if rev.Rejected != "" {
			t.Errorf("rejected = %q", rev.Rejected)
		}
		assertUnchanged(t, rev, f)
	})

	t.Run("budget used up during the conversation", func(t *testing.T) {
		// The first call spends the whole token cap, so the call that would
		// carry the tool result back is never made.
		fx := setup(t, budget.Caps{Tokens: 10, USD: 5, Wall: time.Hour, SandboxRuns: 1},
			llm.Call("c1", "read_file", map[string]any{"path": "app.py"}),
			llm.Say(endpointJSON(nil)),
		)
		rev, err := InvestigateEndpoint(context.Background(), fx.runner, 0, fx.sealer, fx.reg, f, probeExchanges, knownIDs("X-0001"))
		if !errors.Is(err, budget.ErrExhausted) {
			t.Fatalf("err = %v, want budget exhaustion", err)
		}
		if fx.fake.Remaining() != 1 {
			t.Errorf("%d scripted replies left, want the second call never made", fx.fake.Remaining())
		}
		assertUnchanged(t, rev, f)
	})

	t.Run("cancelled", func(t *testing.T) {
		fx := setup(t, budget.Caps{}, llm.Say(endpointJSON(nil)))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := InvestigateEndpoint(ctx, fx.runner, 0, fx.sealer, nil, f, probeExchanges, knownIDs("X-0001"))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
		if len(fx.fake.Requests) != 0 {
			t.Errorf("%d requests were sent after cancellation", len(fx.fake.Requests))
		}
	})
}

func TestEndpointRecordedExchangesAreClippedBeforeSending(t *testing.T) {
	f := endpointFinding(t)
	fx := setup(t, budget.Caps{}, llm.Say(`{"verdict":"not_confirmed","reason":"Nothing to see."}`))
	exchanges := strings.Repeat("e", 12000) + "TAIL-BEYOND-THE-LIMIT"
	if _, err := InvestigateEndpoint(context.Background(), fx.runner, 0, fx.sealer, nil, f, exchanges, knownIDs()); err != nil {
		t.Fatal(err)
	}
	sent := fx.fake.Sent()
	if !strings.Contains(sent, strings.Repeat("e", 12000)) {
		t.Error("the first 12000 bytes of the exchanges were not sent")
	}
	if strings.Contains(sent, "TAIL-BEYOND-THE-LIMIT") {
		t.Error("exchange text past the 12000 byte limit was sent")
	}
}
