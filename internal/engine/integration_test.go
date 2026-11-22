package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/seed"
)

const integVulnerable = `import sqlite3


def find(conn, q):
    return conn.execute(f"SELECT a FROM t WHERE a = '{q}'").fetchall()
`

const integFixed = `import sqlite3


def find(conn, q):
    return conn.execute("SELECT a FROM t WHERE a = ?", (q,)).fetchall()
`

// integPoC is a real proof of concept: it calls the target function with a
// value that changes the query and asserts that rows come back that the
// search term does not match. MARKER is replaced with the run's marker.
const integPoC = `import sqlite3
import sys

sys.path.insert(0, ".")
import app

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE t (a TEXT)")
conn.execute("INSERT INTO t VALUES ('private-row')")
rows = app.find(conn, "no-such-value' OR '1'='1")
assert rows == [("private-row",)], "the injected condition did not change the query"
print("MARKER")
`

// TestIntegrationRealSandboxProofAndFix runs the prove and fix stages
// against a real container runtime. The model is scripted, but everything
// the sandbox does is real: the proof runs in a container with no network
// against a read-only copy of the target, and the fix is accepted only
// because the same proof then fails.
func TestIntegrationRealSandboxProofAndFix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	rt, err := sandbox.Detect(ctx, "auto")
	if err != nil {
		if os.Getenv("SPACKLE_REQUIRE_RUNTIME") == "1" {
			t.Fatalf("a container runtime is required here: %v", err)
		}
		t.Skip("no container runtime found; install Docker or Podman to run sandbox tests")
	}
	image := config.Default().Sandbox.Images["python"]
	if !rt.ImagePresent(ctx, image) {
		if err := rt.Pull(ctx, image); err != nil {
			if os.Getenv("SPACKLE_REQUIRE_RUNTIME") == "1" {
				t.Fatalf("pull %s: %v", image, err)
			}
			t.Skipf("sandbox image %s could not be pulled: %v", image, err)
		}
	}

	root := filepath.Join(t.TempDir(), "my app")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte(integVulnerable), 0o644); err != nil {
		t.Fatal(err)
	}
	lead := seed.Lead{
		RuleID: "py-sql-fstring", Title: "SQL statement built with an f-string", Class: "sql-injection",
		Surface: finding.SurfaceCode, CWE: []string{"CWE-89"}, Severity: "critical",
		File: "app.py", Line: 5, Detail: "The query text includes q.", Fix: "Bind q as a parameter.",
	}

	fake := llm.NewFake()
	fake.Handler = func(req llm.Request, _ int) (llm.Response, error) {
		resp := llm.Response{StopReason: llm.StopEnd, Usage: llm.Usage{InputTokens: 100, OutputTokens: 50, CostKnown: true}}
		switch {
		case strings.Contains(req.System, "this step is planning"):
			resp.Text = planFor(leadID(lead, "fake"))
		case strings.Contains(req.System, "adversarial review"):
			resp.Text = `{"verdict":"confirmed","reason":"q is formatted into the statement"}`
		case strings.Contains(req.System, "combine into a larger"):
			resp.Text = `{"chains":[]}`
		case strings.Contains(req.System, "demonstrate one finding"):
			marker := markerRe.FindString(req.Messages[0].Text)
			b, _ := json.Marshal(map[string]any{
				"can_prove": true, "files": map[string]string{"spackle_poc/poc.py": strings.ReplaceAll(integPoC, "MARKER", marker)},
				"command": []string{"python", "spackle_poc/poc.py"}, "explanation": "Calls find with a value that widens the WHERE clause.",
			})
			resp.Text = string(b)
		case strings.Contains(req.System, "fix one finding"):
			b, _ := json.Marshal(map[string]any{"files": map[string]string{"app.py": integFixed}, "why": "The value is bound instead of formatted."})
			resp.Text = string(b)
		default:
			b, _ := json.Marshal(map[string]any{"verdict": "finding", "finding": map[string]any{
				"title": "SQL injection in find", "class": "sql-injection", "cwe": []string{"CWE-89"},
				"file": "app.py", "start_line": 5, "end_line": 5, "symbol": "find",
				"cvss_vector": sqlVector, "description": "q is formatted into the SQL text.",
				"flow":        []map[string]any{{"role": "sink", "file": "app.py", "line": 5, "quote": `return conn.execute(f"SELECT a FROM t WHERE a = '{q}'").fetchall()`}},
				"fix_summary": "Bind q as a parameter.", "confidence": "high", "confidence_reason": "Read the sink.",
			}})
			resp.Text = string(b)
		}
		return resp, nil
	}

	cfg := config.Default()
	cfg.StateDir = filepath.Join(t.TempDir(), ".spackle")
	cfg.Model = config.Model{Provider: "ollama", Model: "scripted"}
	res, err := Run(ctx, Options{
		Target: root, Config: cfg, Seeders: []seed.Seeder{fakeSeeder{name: "fake", leads: []seed.Lead{lead}}},
		ProviderFactory: func(config.Model) (llm.Provider, error) { return llm.NewRedacting(fake), nil },
		DetectRuntime:   func(context.Context, string) (sandbox.Runtime, error) { return rt, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Run.Findings))
	}
	f := res.Run.Findings[0]
	if f.Proof.Status != finding.ProofDemonstrated {
		t.Fatalf("the proof was not demonstrated in a real container: %+v", f.Proof)
	}
	if f.Status != finding.StatusFixed || !strings.HasPrefix(f.Remediation.Verification, "verified: ") {
		t.Fatalf("the fix was not verified: status=%s verification=%q", f.Status, f.Remediation.Verification)
	}
	if !strings.Contains(f.Proof.Isolation, "network none") {
		t.Fatalf("isolation = %q", f.Proof.Isolation)
	}
	// The target on the host is exactly as it was.
	if got, _ := os.ReadFile(filepath.Join(root, "app.py")); string(got) != integVulnerable {
		t.Fatal("the target was modified on the host")
	}
	if entries, _ := os.ReadDir(root); len(entries) != 1 {
		t.Fatalf("the sandbox left files in the target: %v", entries)
	}
}
