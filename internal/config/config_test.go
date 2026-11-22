package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "spackle.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreValidAndBounded(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Budget.USD <= 0 || cfg.Budget.Tokens <= 0 || cfg.Budget.WallTime.Duration <= 0 || cfg.Budget.SandboxRuns <= 0 {
		t.Fatalf("every budget cap must have a non-zero default: %+v", cfg.Budget)
	}
	if cfg.Sandbox.Network != "none" {
		t.Fatalf("sandbox network default = %q, want none", cfg.Sandbox.Network)
	}
	if !cfg.Fix.On() {
		t.Fatal("fixing should default to on")
	}
}

func TestLoadMissingDefaultFileIsNotAnError(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg, used, err := Load("")
	if err != nil || used != "" || cfg.StateDir != ".spackle" {
		t.Fatalf("cfg=%+v used=%q err=%v", cfg, used, err)
	}
}

func TestLoadMissingExplicitFileIsAnError(t *testing.T) {
	_, _, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadMergesOverDefaults(t *testing.T) {
	p := writeConfig(t, `
offline = true

[model]
provider = "openai-compatible"
model = "some/model"
base_url = "https://openrouter.ai/api/v1"
api_key_env = "OPENROUTER_API_KEY"

[stages.mechanical]
provider = "ollama"
model = "qwen3:8b"

[stages.reviewer]
provider = "openai-compatible"

[budget]
usd = 1.5
wall_time = "10m"

[scope]
hosts = ["localhost:8081"]

[sandbox]
memory_mb = 512
[sandbox.images]
python = "python:3.12-slim"

[fix]
enabled = false

[pricing."some/model"]
input_per_mtok = 1.0
output_per_mtok = 2.0
`)
	cfg, used, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if used != p || !cfg.Offline {
		t.Fatalf("used=%q offline=%v", used, cfg.Offline)
	}
	if cfg.Budget.USD != 1.5 || cfg.Budget.WallTime.Duration != 10*time.Minute || cfg.Budget.Tokens != 2_000_000 {
		t.Fatalf("budget = %+v", cfg.Budget)
	}
	if cfg.Sandbox.MemoryMB != 512 || cfg.Sandbox.Images["python"] != "python:3.12-slim" || cfg.Sandbox.Images["go"] == "" {
		t.Fatalf("sandbox = %+v", cfg.Sandbox)
	}
	if cfg.Fix.On() {
		t.Fatal("fix.enabled = false was ignored")
	}
	if got := cfg.ForStage("mechanical"); got.Provider != "ollama" || got.Model != "qwen3:8b" || got.BaseURL != "" {
		t.Fatalf("mechanical = %+v", got)
	}
	// Same provider as the default: empty fields are inherited.
	if got := cfg.ForStage("reviewer"); got.Model != "some/model" || got.APIKeyEnv != "OPENROUTER_API_KEY" {
		t.Fatalf("reviewer = %+v", got)
	}
	if got := cfg.ForStage("investigator"); got != cfg.Model {
		t.Fatalf("investigator = %+v, want the default model", got)
	}
	if cfg.Pricing["some/model"].OutputPerMTok != 2.0 {
		t.Fatalf("pricing = %+v", cfg.Pricing)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	p := writeConfig(t, "[budget]\nusd = 1\ntokenz = 5\n")
	_, _, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "budget.tokenz") {
		t.Fatalf("got %v", err)
	}
}

func TestValidationProblems(t *testing.T) {
	cases := map[string]string{
		"[model]\nprovider = \"gemini\"\nmodel = \"x\"\n":                              "unknown provider",
		"[model]\nprovider = \"openai-compatible\"\nmodel = \"x\"\n":                   "needs base_url",
		"[model]\nprovider = \"anthropic\"\n":                                          "no model name",
		"[model]\nmodel = \"x\"\n":                                                     "no provider",
		"[model]\nprovider = \"openai\"\nmodel = \"x\"\napi_key_env = \"sk-abc123\"\n": "NAME of an environment variable",
		"[stages.wizard]\nprovider = \"ollama\"\nmodel = \"x\"\n":                      "is not a stage",
		"[sandbox]\nruntime = \"lxc\"\n":                                               "runtime",
		"[sandbox]\nnetwork = \"host\"\n":                                              "network",
		"[output]\nfail_on = \"info\"\n":                                               "fail_on",
		"[scope]\nhosts = [\"https://example.test/\"]\n":                               "plain host",
		"[scope]\nhosts = [\"*.example.test\"]\n":                                      "plain host",
		"[scope]\npath_prefixes = [\"api\"]\n":                                         "must start with /",
		"[budget]\nwall_time = \"soon\"\n":                                             "not a duration",
		"[budget]\nusd = -1\n":                                                         "cannot be negative",
	}
	for body, want := range cases {
		_, _, err := Load(writeConfig(t, body))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("config %q: want error containing %q, got %v", body, want, err)
		}
	}
}

func TestNoAPIKeyFieldExists(t *testing.T) {
	// The config has no field that can hold a key value. A file that tries
	// to set one is rejected as an unknown key.
	p := writeConfig(t, "[model]\nprovider = \"openai\"\nmodel = \"x\"\napi_key = \"secret\"\n")
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "model.api_key") {
		t.Fatalf("got %v", err)
	}
}
