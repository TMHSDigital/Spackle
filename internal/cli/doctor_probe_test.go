package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/llm"
)

// A provider that rejects the key is a failed check, and the row carries
// the hint that says what to fix.
func TestDoctorProbeShowsARejectedKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SPACKLE_TEST_KEY", "placeholder-"+"not-a-key")

	dir := t.TempDir()
	cfg := filepath.Join(dir, "spackle.toml")
	body := "state_dir = " + strconv.Quote(filepath.ToSlash(filepath.Join(dir, "state"))) + "\n\n" +
		"[sandbox]\nruntime = \"none\"\n\n" +
		"[model]\nprovider = \"openai-compatible\"\nmodel = \"some-model\"\n" +
		"base_url = " + strconv.Quote(srv.URL+"/v1") + "\napi_key_env = \"SPACKLE_TEST_KEY\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := run("doctor", "--config", cfg)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitUsage, stdout)
	}
	for _, want := range []string{"[fail]     model (default)", "the API key was rejected", "api_key_env", "Result: a required check failed."} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "placeholder-") {
		t.Error("the key value was printed")
	}
}

// probeStub is a remote provider whose free check passes with note.
type probeStub struct {
	note string
}

func (probeStub) Name() string  { return "openai-compatible" }
func (probeStub) Model() string { return "unpriced-test-model" }
func (probeStub) Local() bool   { return false }
func (probeStub) Complete(context.Context, llm.Request) (llm.Response, error) {
	return llm.Response{}, errors.New("a probe test makes no completion")
}
func (p probeStub) Probe(context.Context) (string, []string, error) { return p.note, nil, nil }

// A remote model that answers the probe but has no known price passes with
// a warning that the dollar cap cannot hold; a priced one gets no warning.
func TestDoctorProbeWarnsAboutAnUnpricedRemoteModel(t *testing.T) {
	old := newProvider
	newProvider = func(config.Model, llm.Options) (llm.Provider, error) {
		return probeStub{note: "model found at models.example.test"}, nil
	}
	t.Cleanup(func() { newProvider = old })

	cfg := config.Default()
	m := config.Model{Provider: "openai-compatible", Model: "unpriced-test-model", BaseURL: "https://models.example.test/v1"}
	checks := doctorProbe(context.Background(), cfg, "default", m)
	if len(checks) != 2 || checks[0].status != "ok" || !strings.Contains(checks[0].note, "(remote)") {
		t.Fatalf("checks = %+v, want an ok row and a warning", checks)
	}
	if checks[1].status != "warn" || !strings.Contains(checks[1].note, "no price is known") || !strings.Contains(checks[1].note, `[pricing."unpriced-test-model"]`) {
		t.Fatalf("warning = %+v", checks[1])
	}

	cfg.Pricing = map[string]config.Price{"unpriced-test-model": {InputPerMTok: 1, OutputPerMTok: 2}}
	if checks := doctorProbe(context.Background(), cfg, "default", m); len(checks) != 1 || checks[0].status != "ok" {
		t.Fatalf("priced model: checks = %+v, want one ok row", checks)
	}
}
