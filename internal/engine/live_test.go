package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TMHSDigital/spackle/internal/authz"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
)

// flawedApp is a small deliberately flawed web app for live-target tests.
// outside is another server it links and redirects to, which must never be
// contacted.
func flawedApp(t *testing.T, outside string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="/search?q=hello">search</a> <a href="%s/elsewhere">other site</a> <a href="/go?next=/">go</a></body></html>`, outside)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Results for %s</body></html>", r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func outsideServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "you should never have reached this server")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func scopeFile(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "scope.toml")
	body := fmt.Sprintf("hosts = [%q]\nrequests_per_second = 50\nstatement = \"My own test server.\"\n", u.Host)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func liveOpts(t *testing.T, target string) Options {
	t.Helper()
	cfg := config.Default()
	cfg.StateDir = filepath.Join(t.TempDir(), ".spackle")
	return Options{Target: target, Config: cfg, Clock: fixedClock(), RunID: "20261122-120000-abcdef"}
}

func TestLiveTargetIsRefusedWithoutAuthorizedScope(t *testing.T) {
	outside, _ := outsideServer(t)
	app, hits := flawedApp(t, outside.URL)

	cases := map[string]func(*Options){
		"no scope, not interactive": func(*Options) {},
		"--yes with no scope":       func(o *Options) { o.Yes = true },
		"interactive, wrong answer": func(o *Options) { o.Interactive = true; o.Stdin = strings.NewReader("yes\n") },
		"scope file for another host": func(o *Options) {
			o.ScopeFile = scopeFile(t, "http://some-other-host.test:8080")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := liveOpts(t, app.URL)
			mutate(&o)
			_, err := Run(context.Background(), o)
			if !errors.Is(err, ErrRefused) || !errors.Is(err, authz.ErrNotAuthorized) {
				t.Fatalf("err = %v, want a refusal for missing authorization", err)
			}
			if hits.Load() != 0 {
				t.Fatalf("%d requests reached the target before authorization", hits.Load())
			}
			if entries, _ := os.ReadDir(RunsDir(o.Config.StateDir)); len(entries) != 0 {
				t.Fatal("a refused run left a run directory")
			}
		})
	}
}

func TestLiveScanStaysInScopeAndRecordsEvidence(t *testing.T) {
	outside, outsideHits := outsideServer(t)
	app, hits := flawedApp(t, outside.URL)
	o := liveOpts(t, app.URL)
	o.ScopeFile = scopeFile(t, app.URL)
	o.Yes = true
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() == 0 {
		t.Fatal("the target was never probed")
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("%d requests left the authorized scope (a link and an open redirect point there)", outsideHits.Load())
	}
	run := res.Run
	if run.TargetKind != "url" || run.ScopeSource != "scope-file" || !strings.Contains(run.Scope, strings.TrimPrefix(app.URL, "http://")) {
		t.Fatalf("run kind=%s scope=%q source=%s", run.TargetKind, run.Scope, run.ScopeSource)
	}
	if !strings.Contains(strings.Join(run.Notes, "|"), "My own test server.") {
		t.Fatalf("the authorization statement was not recorded: %v", run.Notes)
	}
	byClass := map[string]finding.Finding{}
	for _, f := range run.Findings {
		byClass[f.Class] = f
		if f.Surface != finding.SurfaceDAST || f.Location.Endpoint == "" {
			t.Errorf("finding %s is not located by endpoint: %+v", f.ID, f.Location)
		}
		for _, ref := range f.Proof.Artifacts {
			if _, err := os.Stat(filepath.Join(res.RunDir, filepath.FromSlash(ref))); err != nil {
				t.Errorf("finding %s cites evidence that does not exist: %s", f.ID, ref)
			}
		}
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s invalid: %v", f.ID, err)
		}
	}
	xss, ok := byClass["xss"]
	if !ok {
		t.Fatalf("reflected XSS on /search was not found; classes: %v", keys(byClass))
	}
	if xss.Proof.Status != finding.ProofDemonstrated || xss.Proof.Kind != "http-sequence" || xss.Confidence.Level != finding.ConfidenceDemonstrated || xss.Location.Parameter != "q" {
		t.Fatalf("xss = proof %s kind %s confidence %s param %q", xss.Proof.Status, xss.Proof.Kind, xss.Confidence.Level, xss.Location.Parameter)
	}
	if _, ok := byClass["open-redirect"]; !ok {
		t.Errorf("the open redirect on /go was not found; classes: %v", keys(byClass))
	}
	events, _ := ledger.Read(res.RunDir)
	exchanges := 0
	for _, e := range events {
		if e.Type == ledger.TypeHTTPExchange {
			exchanges++
			var d ledger.HTTPExchange
			_ = e.Decode(&d)
			if !strings.HasPrefix(d.URL, app.URL) {
				t.Errorf("an exchange was recorded for an out-of-scope URL: %s", d.URL)
			}
		}
	}
	if int32(exchanges) != hits.Load() {
		t.Errorf("%d requests reached the target but %d exchanges are in the ledger", hits.Load(), exchanges)
	}
}

func keys(m map[string]finding.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLiveModelAssessmentCannotLeaveScope(t *testing.T) {
	outside, outsideHits := outsideServer(t)
	app, _ := flawedApp(t, outside.URL)

	fake := llm.NewFake()
	fake.Handler = func(req llm.Request, _ int) (llm.Response, error) {
		resp := llm.Response{Usage: llm.Usage{InputTokens: 50, OutputTokens: 20, CostKnown: true}}
		last := req.Messages[len(req.Messages)-1]
		if last.Role == llm.RoleUser {
			// A hostile or confused model tries the other server and an unsafe method.
			resp.StopReason = llm.StopToolUse
			resp.ToolCalls = []llm.ToolCall{
				{ID: "1", Name: "http_request", Args: json.RawMessage(`{"method":"GET","url":"` + outside.URL + `/steal"}`)},
				{ID: "2", Name: "http_request", Args: json.RawMessage(`{"method":"DELETE","url":"/search?q=1"}`)},
				{ID: "3", Name: "read_file", Args: json.RawMessage(`{"path":"/etc/passwd"}`)},
			}
			return resp, nil
		}
		for _, tr := range last.ToolResults {
			if !tr.IsError {
				return resp, fmt.Errorf("tool call %s was allowed: %s", tr.CallID, tr.Content)
			}
		}
		resp.StopReason = llm.StopEnd
		resp.Text = `{"verdict":"confirmed","reason":"The marker is reflected unescaped.","title":"Confirmed by assessment",
		 "cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N","description":"Reflected.",
		 "attack_steps":["Send a link"],"fix_summary":"Escape output.","evidence":["X-0001","X-9999"]}`
		return resp, nil
	}
	o := liveOpts(t, app.URL)
	o.ScopeFile = scopeFile(t, app.URL)
	o.Yes = true
	o.Config.Model = config.Model{Provider: "ollama", Model: "fake-model"}
	o.ProviderFactory = func(config.Model) (llm.Provider, error) { return llm.NewRedacting(fake), nil }
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("the model's tool call reached the out-of-scope server %d times", outsideHits.Load())
	}
	confirmed := 0
	for _, f := range res.Run.Findings {
		if f.Title == "Confirmed by assessment" {
			confirmed++
			for _, ref := range f.Proof.Artifacts {
				if strings.Contains(ref, "X-9999") {
					t.Fatal("evidence that was never recorded was accepted from the model")
				}
			}
		}
	}
	if confirmed == 0 {
		t.Fatal("no finding was enriched by the assessment")
	}
	if res.Run.Mode != "agentic" || res.Run.Usage.ModelCalls == 0 {
		t.Fatalf("mode=%s calls=%d", res.Run.Mode, res.Run.Usage.ModelCalls)
	}
}

func TestOfflineRefusesARemoteLiveTarget(t *testing.T) {
	// 192.0.2.1 is reserved for documentation and is never routed.
	o := liveOpts(t, "http://192.0.2.1:8080/")
	o.ScopeFile = scopeFile(t, "http://192.0.2.1:8080/")
	o.Yes = true
	o.Config.Offline = true
	_, err := Run(context.Background(), o)
	if !errors.Is(err, ErrRefused) || !errors.Is(err, llm.ErrOffline) {
		t.Fatalf("err = %v", err)
	}
}
