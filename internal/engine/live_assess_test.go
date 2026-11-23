package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
)

const (
	assessedTitle  = "Confirmed by assessment"
	notAssessed    = "Not assessed by a model: "
	dismissPrefix  = "Assessed against the running target and not confirmed: "
	confirmedReply = `{"verdict":"confirmed","reason":"The marker is reflected unescaped.","title":"` + assessedTitle + `",
		"cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N","description":"Reflected.",
		"attack_steps":["Send a link"],"fix_summary":"Escape output."}`
)

// assessOpts is a live scan of appURL, inside an authorized scope, with the
// fake standing in for the model that assesses each finding.
func assessOpts(t *testing.T, appURL string, fake *llm.Fake) Options {
	t.Helper()
	o := liveOpts(t, appURL)
	o.ScopeFile = scopeFile(t, appURL)
	o.Yes = true
	o.Config.Model = config.Model{Provider: "ollama", Model: "fake-model"}
	o.ProviderFactory = func(config.Model) (llm.Provider, error) { return llm.NewRedacting(fake), nil }
	return o
}

// probeFindings scans appURL with no model and returns what the probe alone
// reports, by finding id.
func probeFindings(t *testing.T, appURL string) map[string]finding.Finding {
	t.Helper()
	o := liveOpts(t, appURL)
	o.ScopeFile = scopeFile(t, appURL)
	o.Yes = true
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) < 2 {
		t.Fatalf("the probe reported %d findings; these tests need at least two", len(res.Run.Findings))
	}
	out := map[string]finding.Finding{}
	for _, f := range res.Run.Findings {
		out[f.ID] = f
	}
	return out
}

// answer is a final model reply with a fixed, known token count.
func answer(text string) llm.Response {
	return llm.Response{Text: text, StopReason: llm.StopEnd, Usage: llm.Usage{InputTokens: 50, OutputTokens: 20, CostKnown: true}}
}

// eventsOf decodes every ledger event of one type.
func eventsOf[T any](t *testing.T, runDir, typ string) []T {
	t.Helper()
	events, err := ledger.Read(runDir)
	if err != nil {
		t.Fatal(err)
	}
	var out []T
	for _, e := range events {
		if e.Type != typ {
			continue
		}
		var d T
		if err := e.Decode(&d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func runOutcome(t *testing.T, runDir string) string {
	t.Helper()
	ends := eventsOf[ledger.RunEnd](t, runDir, ledger.TypeRunEnd)
	if len(ends) != 1 {
		t.Fatalf("%d run.end events", len(ends))
	}
	return ends[0].Outcome
}

// sameAsProbe fails unless the run reports exactly the probe's findings,
// unchanged.
func sameAsProbe(t *testing.T, got []finding.Finding, probe map[string]finding.Finding) {
	t.Helper()
	if len(got) != len(probe) {
		t.Errorf("%d findings reported, the probe found %d", len(got), len(probe))
	}
	for _, f := range got {
		want, ok := probe[f.ID]
		if !ok {
			t.Errorf("finding %s (%s) was not reported by the probe", f.ID, f.Title)
			continue
		}
		if got, want := normalized(t, f), normalized(t, want); got != want {
			t.Errorf("finding %s is not as the probe reported it:\n got %s\nwant %s", f.ID, got, want)
		}
	}
}

// probeNonce matches the random part of a probe marker. It differs on every
// scan, and it appears in the text of the findings the marker produced.
var probeNonce = regexp.MustCompile(`[0-9a-f]{12,}`)

// normalized renders a finding so that two scans of the same application
// can be compared: everything is kept except the random marker values.
func normalized(t *testing.T, f finding.Finding) string {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return probeNonce.ReplaceAllString(string(b), "NONCE")
}

func TestLiveAssessmentDismissesConfirmsAndRejectsPerFinding(t *testing.T) {
	outside, _ := outsideServer(t)
	app, _ := flawedApp(t, outside.URL)
	probe := probeFindings(t, app.URL)

	// The model confirms the reflected XSS, rules out the open redirect with
	// a reason, and for everything else says "not confirmed" without one.
	const why = "The redirect target is checked against an allowlist on every request I sent."
	fake := llm.NewFake()
	fake.Handler = func(req llm.Request, _ int) (llm.Response, error) {
		brief := req.Messages[0].Text
		switch {
		case strings.Contains(brief, `"class": "xss"`):
			return answer(confirmedReply), nil
		case strings.Contains(brief, `"class": "open-redirect"`):
			return answer(`{"verdict":"not_confirmed","reason":"` + why + `"}`), nil
		}
		return answer(`{"verdict":"not_confirmed","reason":"  "}`), nil
	}
	res, err := Run(context.Background(), assessOpts(t, app.URL, fake))
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != "completed" || runOutcome(t, res.RunDir) != "completed" {
		t.Fatalf("outcome = %s", res.Run.Outcome)
	}
	if len(res.Run.Findings) != len(probe) {
		t.Fatalf("%d findings reported, the probe found %d: an assessment must not drop a finding", len(res.Run.Findings), len(probe))
	}
	if len(fake.Requests) != len(probe) {
		t.Errorf("%d model calls for %d findings", len(fake.Requests), len(probe))
	}

	var dismissedIDs, confirmedIDs, untouchedIDs []string
	for _, f := range res.Run.Findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s invalid: %v", f.ID, err)
		}
		was := probe[f.ID]
		switch f.Class {
		case "open-redirect":
			dismissedIDs = append(dismissedIDs, f.ID)
			if f.Status != finding.StatusDismissed || f.DismissReason != dismissPrefix+why {
				t.Errorf("open redirect: status %s reason %q", f.Status, f.DismissReason)
			}
			// Only the standing changes. What the probe saw is kept.
			f.Status, f.DismissReason = was.Status, was.DismissReason
			if got, want := normalized(t, f), normalized(t, was); got != want {
				t.Errorf("the dismissed finding lost what the probe reported:\n got %s\nwant %s", got, want)
			}
		case "xss":
			confirmedIDs = append(confirmedIDs, f.ID)
			if f.Status != finding.StatusOpen || f.Title != assessedTitle || f.Origin[len(f.Origin)-1] != "investigator:endpoint" {
				t.Errorf("xss: status %s title %q origin %v", f.Status, f.Title, f.Origin)
			}
		default:
			untouchedIDs = append(untouchedIDs, f.ID)
			if got, want := normalized(t, f), normalized(t, was); got != want {
				t.Errorf("finding %s had no usable answer and must stay as the probe reported it:\n got %s\nwant %s", f.ID, got, want)
			}
		}
	}
	if len(dismissedIDs) == 0 || len(confirmedIDs) == 0 {
		t.Fatalf("dismissed %v confirmed %v: the app has both an open redirect and a reflected XSS", dismissedIDs, confirmedIDs)
	}

	gotVerdicts := map[string][]string{}
	for _, v := range eventsOf[ledger.Verdict](t, res.RunDir, ledger.TypeVerdict) {
		if v.Stage != "investigator" {
			t.Errorf("verdict stage = %q", v.Stage)
		}
		gotVerdicts[v.Outcome] = append(gotVerdicts[v.Outcome], v.FindingID)
		if v.Outcome == "dismissed" && v.Reason != why {
			t.Errorf("dismissed verdict reason = %q", v.Reason)
		}
	}
	wantVerdicts := map[string][]string{"dismissed": dismissedIDs, "confirmed": confirmedIDs}
	for outcome, ids := range wantVerdicts {
		if !sameSet(gotVerdicts[outcome], ids) {
			t.Errorf("%s verdicts are for %v, want %v", outcome, gotVerdicts[outcome], ids)
		}
	}
	if len(gotVerdicts) != len(wantVerdicts) {
		t.Errorf("verdicts = %v", gotVerdicts)
	}

	// "Not confirmed" with no reason is an unusable answer, not a dismissal.
	var rejectedIDs []string
	for _, r := range res.Run.Rejected {
		if r.Stage != "investigator" || !strings.Contains(r.Reason, "gave no reason") {
			t.Errorf("reject = %+v", r)
		}
		rejectedIDs = append(rejectedIDs, r.Intent)
	}
	if !sameSet(rejectedIDs, untouchedIDs) {
		t.Errorf("rejects are for %v, want %v", rejectedIDs, untouchedIDs)
	}
	if len(res.Run.Skipped) != 0 {
		t.Errorf("skipped = %+v", res.Run.Skipped)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestLiveAssessmentDismissesEveryFindingTheModelRulesOut(t *testing.T) {
	outside, _ := outsideServer(t)
	app, _ := flawedApp(t, outside.URL)
	probe := probeFindings(t, app.URL)

	fake := llm.NewFake()
	fake.Handler = func(llm.Request, int) (llm.Response, error) {
		return answer(`{"verdict":"not_confirmed","reason":"Could not reproduce it."}`), nil
	}
	res, err := Run(context.Background(), assessOpts(t, app.URL, fake))
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Outcome != "completed" {
		t.Fatalf("outcome = %s", res.Run.Outcome)
	}
	if len(res.Run.Findings) != len(probe) {
		t.Fatalf("%d findings reported, the probe found %d: a dismissed finding is still reported", len(res.Run.Findings), len(probe))
	}
	for _, f := range res.Run.Findings {
		if f.Status != finding.StatusDismissed {
			t.Errorf("finding %s status = %s", f.ID, f.Status)
		}
		if !strings.HasPrefix(f.DismissReason, "Assessed against the running target") || !strings.HasSuffix(f.DismissReason, "Could not reproduce it.") {
			t.Errorf("finding %s dismiss reason = %q", f.ID, f.DismissReason)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s invalid: %v", f.ID, err)
		}
	}
	verdicts := eventsOf[ledger.Verdict](t, res.RunDir, ledger.TypeVerdict)
	if len(verdicts) != len(probe) {
		t.Fatalf("%d verdicts for %d findings", len(verdicts), len(probe))
	}
	for _, v := range verdicts {
		if _, ok := probe[v.FindingID]; !ok || v.Outcome != "dismissed" || v.Stage != "investigator" || v.Reason != "Could not reproduce it." {
			t.Errorf("verdict = %+v", v)
		}
	}
	if len(res.Run.Rejected) != 0 {
		t.Errorf("rejected = %+v", res.Run.Rejected)
	}
	// The stored finding files say the same as the ledger.
	for id := range probe {
		b, err := os.ReadFile(filepath.Join(res.RunDir, "findings", id, "finding.json"))
		if err != nil {
			t.Fatal(err)
		}
		var f finding.Finding
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		if f.Status != finding.StatusDismissed {
			t.Errorf("finding.json for %s has status %s", id, f.Status)
		}
	}
}

func TestLiveAssessmentUnusableAnswersLeaveTheProbeFindings(t *testing.T) {
	outside, _ := outsideServer(t)
	app, _ := flawedApp(t, outside.URL)
	probe := probeFindings(t, app.URL)

	cases := map[string]struct {
		resp llm.Response
		want string
	}{
		"not confirmed without a reason": {answer(`{"verdict":"not_confirmed"}`), "gave no reason"},
		"unknown verdict":                {answer(strings.Replace(confirmedReply, `"confirmed"`, `"maybe"`, 1)), `verdict "maybe"`},
		"prose instead of JSON":          {answer("It looks real to me."), "no JSON object"},
		"refusal": {
			llm.Response{Text: confirmedReply, StopReason: llm.StopRefusal, Usage: llm.Usage{InputTokens: 50, OutputTokens: 20, CostKnown: true}},
			"did not complete the assessment (provider refusal)",
		},
		"truncated": {
			llm.Response{Text: confirmedReply, StopReason: llm.StopMaxTokens, Usage: llm.Usage{InputTokens: 50, OutputTokens: 20, CostKnown: true}},
			"did not complete the assessment (output truncated)",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := llm.NewFake()
			fake.Handler = func(llm.Request, int) (llm.Response, error) { return tc.resp, nil }
			res, err := Run(context.Background(), assessOpts(t, app.URL, fake))
			if err != nil {
				t.Fatal(err)
			}
			if res.Run.Outcome != "completed" {
				t.Fatalf("outcome = %s", res.Run.Outcome)
			}
			sameAsProbe(t, res.Run.Findings, probe)
			var ids []string
			for _, r := range res.Run.Rejected {
				if r.Stage != "investigator" || !strings.Contains(r.Reason, tc.want) {
					t.Errorf("reject = %+v, want a reason containing %q", r, tc.want)
				}
				ids = append(ids, r.Intent)
			}
			if !sameSet(ids, findingIDs(probe)) {
				t.Errorf("rejects are for %v, want one for each of %v", ids, findingIDs(probe))
			}
			if v := eventsOf[ledger.Verdict](t, res.RunDir, ledger.TypeVerdict); len(v) != 0 {
				t.Errorf("verdicts = %+v, an unusable answer must not change a finding's standing", v)
			}
		})
	}
}

func findingIDs(m map[string]finding.Finding) []string {
	var out []string
	for id := range m {
		out = append(out, id)
	}
	return out
}

func TestLiveAssessmentProviderErrorKeepsTheProbeFindings(t *testing.T) {
	outside, _ := outsideServer(t)
	app, _ := flawedApp(t, outside.URL)
	probe := probeFindings(t, app.URL)

	fake := llm.NewFake()
	fake.Handler = func(llm.Request, int) (llm.Response, error) {
		return llm.Response{}, errors.New("upstream connect error or disconnect/reset before headers")
	}
	res, err := Run(context.Background(), assessOpts(t, app.URL, fake))
	if err != nil {
		t.Fatalf("a failed model call must not fail the run: %v", err)
	}
	if res.Run.Outcome != "completed" || res.Run.Mode != "agentic" {
		t.Fatalf("outcome = %s mode = %s", res.Run.Outcome, res.Run.Mode)
	}
	sameAsProbe(t, res.Run.Findings, probe)
	var ids []string
	for _, r := range res.Run.Rejected {
		if r.Stage != "investigator" || !strings.HasPrefix(r.Reason, "the assessment failed: ") || !strings.Contains(r.Reason, "upstream connect error") {
			t.Errorf("reject = %+v", r)
		}
		ids = append(ids, r.Intent)
	}
	if !sameSet(ids, findingIDs(probe)) {
		t.Errorf("rejects are for %v, want one for each of %v", ids, findingIDs(probe))
	}
	// One failure does not stop the others from being tried, and each
	// failed call is on the record.
	if len(fake.Requests) != len(probe) {
		t.Errorf("%d model calls for %d findings", len(fake.Requests), len(probe))
	}
	calls := eventsOf[ledger.ModelCall](t, res.RunDir, ledger.TypeModelCall)
	if len(calls) != len(probe) {
		t.Errorf("%d model.call events for %d findings", len(calls), len(probe))
	}
	for _, c := range calls {
		if !strings.Contains(c.Error, "upstream connect error") {
			t.Errorf("model.call error = %q", c.Error)
		}
	}
	if len(res.Run.Skipped) != 0 || len(eventsOf[ledger.Verdict](t, res.RunDir, ledger.TypeVerdict)) != 0 {
		t.Errorf("skipped = %+v", res.Run.Skipped)
	}
}

// skippedLine is how an unassessed finding is listed in a budget skip.
func skippedLine(f finding.Finding) string {
	return notAssessed + f.Title + " (" + f.Location.String() + ")"
}

func TestLiveAssessmentTokenBudgetOfOneCall(t *testing.T) {
	outside, _ := outsideServer(t)
	app, _ := flawedApp(t, outside.URL)
	probe := probeFindings(t, app.URL)

	t.Run("spent by the first finding's answer", func(t *testing.T) {
		fake := llm.NewFake()
		fake.Handler = func(llm.Request, int) (llm.Response, error) { return answer(confirmedReply), nil }
		o := assessOpts(t, app.URL, fake)
		o.Config.Budget.Tokens = 60 // one call uses 70
		res, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if res.Run.Outcome != "budget-exhausted" || runOutcome(t, res.RunDir) != "budget-exhausted" {
			t.Fatalf("outcome = %s", res.Run.Outcome)
		}
		if len(fake.Requests) != 1 {
			t.Fatalf("%d model calls were made; only one fits the budget", len(fake.Requests))
		}
		if len(res.Run.Findings) != len(probe) {
			t.Fatalf("%d findings reported, the probe found %d", len(res.Run.Findings), len(probe))
		}
		// The one finding that was assessed keeps its assessment. Every
		// other finding is reported as the probe found it and is listed.
		var want []string
		assessed := 0
		for _, f := range res.Run.Findings {
			if f.Title == assessedTitle {
				assessed++
				continue
			}
			if normalized(t, f) != normalized(t, probe[f.ID]) {
				t.Errorf("unassessed finding %s is not as the probe reported it", f.ID)
			}
			want = append(want, skippedLine(f))
		}
		if assessed != 1 {
			t.Fatalf("%d findings were assessed, want 1", assessed)
		}
		assertOneBudgetSkip(t, res, "token cap of 60", want)
		if len(res.Run.Rejected) != 0 {
			t.Errorf("rejected = %+v", res.Run.Rejected)
		}
	})

	t.Run("spent in the middle of the first finding's conversation", func(t *testing.T) {
		fake := llm.NewFake()
		fake.Handler = func(llm.Request, int) (llm.Response, error) {
			return llm.Response{
				StopReason: llm.StopToolUse, Usage: llm.Usage{InputTokens: 50, OutputTokens: 20, CostKnown: true},
				ToolCalls: []llm.ToolCall{{ID: "1", Name: "http_request", Args: json.RawMessage(`{"url":"/search?q=again"}`)}},
			}, nil
		}
		o := assessOpts(t, app.URL, fake)
		o.Config.Budget.Tokens = 60
		res, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if res.Run.Outcome != "budget-exhausted" {
			t.Fatalf("outcome = %s", res.Run.Outcome)
		}
		if len(fake.Requests) != 1 {
			t.Fatalf("%d model calls were made; only one fits the budget", len(fake.Requests))
		}
		// No finding got an answer, so every one of them is listed.
		sameAsProbe(t, res.Run.Findings, probe)
		var want []string
		for _, f := range probe {
			want = append(want, skippedLine(f))
		}
		assertOneBudgetSkip(t, res, "token cap of 60", want)
		if len(res.Run.Rejected) != 0 {
			t.Errorf("rejected = %+v, running out of budget is a skip, not a failed assessment", res.Run.Rejected)
		}
		// The request the model did send is still recorded as evidence.
		found := false
		for _, ex := range eventsOf[ledger.HTTPExchange](t, res.RunDir, ledger.TypeHTTPExchange) {
			found = found || strings.HasSuffix(ex.URL, "/search?q=again")
		}
		if !found {
			t.Error("the model's follow-up request is not in the ledger")
		}
	})
}

func assertOneBudgetSkip(t *testing.T, res Result, capText string, want []string) {
	t.Helper()
	skips := eventsOf[ledger.BudgetSkip](t, res.RunDir, ledger.TypeBudgetSkip)
	if len(skips) != 1 || !reflect.DeepEqual(res.Run.Skipped, skips) {
		t.Fatalf("budget skips: ledger %+v, run %+v, want exactly one", skips, res.Run.Skipped)
	}
	if !strings.Contains(skips[0].Cap, capText) {
		t.Errorf("cap = %q, want it to name %q", skips[0].Cap, capText)
	}
	if !sameSet(skips[0].Skipped, want) {
		t.Errorf("skipped:\n got %q\nwant %q", skips[0].Skipped, want)
	}
}

// cappedScopeFile is scopeFile with a request cap.
func cappedScopeFile(t *testing.T, rawURL string, maxRequests int) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "scope.toml")
	body := fmt.Sprintf("hosts = [%q]\nrequests_per_second = 50\nmax_requests = %d\n", u.Host, maxRequests)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The request cap holds against the model's own requests: once the scope's
// max_requests have been sent, nothing more reaches the target however many
// tool calls the model makes. What the run reports about a cap reached this
// way (its outcome and any budget skip) is not asserted here.
func TestLiveAssessmentToolCallsCannotExceedTheRequestCap(t *testing.T) {
	outside, outsideHits := outsideServer(t)
	app, hits := flawedApp(t, outside.URL)
	probe := probeFindings(t, app.URL)
	baseline := int(hits.Load())
	const room = 15 // requests left for the model after the probe; enough that the probe itself is not cut short
	maxRequests := baseline + room

	attempted := 0
	fake := llm.NewFake()
	fake.Handler = func(req llm.Request, _ int) (llm.Response, error) {
		resp := llm.Response{Usage: llm.Usage{InputTokens: 50, OutputTokens: 20, CostKnown: true}}
		last := req.Messages[len(req.Messages)-1]
		refused := false
		for _, tr := range last.ToolResults {
			refused = refused || tr.IsError
		}
		// Answer once a request was refused, or when asked to stop.
		if refused || (len(req.Messages) > 1 && last.Role == llm.RoleUser) {
			resp.StopReason = llm.StopEnd
			resp.Text = confirmedReply
			return resp, nil
		}
		resp.StopReason = llm.StopToolUse
		for i := 0; i < 5; i++ {
			attempted++
			resp.ToolCalls = append(resp.ToolCalls, llm.ToolCall{
				ID: fmt.Sprint(attempted), Name: "http_request",
				Args: json.RawMessage(fmt.Sprintf(`{"url":"/search?q=%d"}`, attempted)),
			})
		}
		return resp, nil
	}
	o := assessOpts(t, app.URL, fake)
	o.ScopeFile = cappedScopeFile(t, app.URL, maxRequests)
	hits.Store(0)
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if attempted <= room {
		t.Fatalf("the model attempted %d requests, which does not exceed the %d the cap leaves", attempted, room)
	}
	sent := int(hits.Load())
	if sent > maxRequests {
		t.Fatalf("%d requests reached the target; the scope allows %d", sent, maxRequests)
	}
	if sent <= baseline {
		t.Fatalf("%d requests reached the target, no more than the probe's %d: the model's requests were never sent", sent, baseline)
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("%d requests left the authorized scope", outsideHits.Load())
	}
	if n := len(eventsOf[ledger.HTTPExchange](t, res.RunDir, ledger.TypeHTTPExchange)); n != sent {
		t.Errorf("%d requests reached the target but %d exchanges are in the ledger", sent, n)
	}
	if len(res.Run.Findings) != len(probe) {
		t.Errorf("%d findings reported, the probe found %d", len(res.Run.Findings), len(probe))
	}
}
