package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// benchCorpus writes a one-fixture corpus: a clean decoy, so the
// deterministic run is fast and needs no optional scanner.
func benchCorpus(t *testing.T) string {
	t.Helper()
	corpus := t.TempDir()
	dir := filepath.Join(corpus, "py-clean-99")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"SPACKLE_FIXTURE": "Test data for Spackle.\n",
		"README.md":       "# py-clean-99\n\nNothing is planted.\n",
		"truth.json":      `{"fixture":"py-clean-99","language":"python","difficulty":"easy","clean":true,"description":"Clean decoy.","vulnerabilities":[]}`,
		"app.py":          "def add(a, b):\n    return a + b\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return corpus
}

// emptyConfig returns a config file with no model, so a spackle.toml in the
// working directory or a developer's environment cannot turn a test into a
// paid run.
func emptyConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spackle.toml")
	if err := os.WriteFile(path, []byte("# no model: deterministic only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBenchIsNotInHelp(t *testing.T) {
	_, out, _ := run("help")
	if strings.Contains(out, "bench") {
		t.Fatalf("bench is a maintainer command and must not be listed:\n%s", out)
	}
}

func TestBenchHelpStatesTheHonestyRule(t *testing.T) {
	code, _, errOut := run("bench", "--help")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"never edited by hand", "--corpus", "--force", "--table", "(default bench/results)", "(default bench/corpus)"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("help lacks %q:\n%s", want, errOut)
		}
	}
}

func TestBenchTableWithNoResults(t *testing.T) {
	code, out, errOut := run("bench", "--table", "--out", filepath.Join(t.TempDir(), "results"))
	if code != ExitOK || !strings.Contains(out, "no committed results yet") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestBenchDeterministicRunWritesAFile(t *testing.T) {
	corpus, out := benchCorpus(t), filepath.Join(t.TempDir(), "results")
	args := []string{"bench", "--config", emptyConfig(t), "--corpus", corpus, "--out", out}

	code, stdout, stderr := run(args...)
	if code != ExitOK {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"Precision:", "Recall:", "Verified-fix rate: n/a", "Cost per finding:  n/a", "Decoys flagged:", "Results file:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("summary lacks %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "[1/1] py-clean-99") {
		t.Errorf("no per-fixture progress line on stderr:\n%s", stderr)
	}
	files, err := filepath.Glob(filepath.Join(out, "*-none.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("results files = %v (%v)", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema": "spackle.bench/v1"`, `"mode": "deterministic"`, `"model": "none"`, `"fixture": "py-clean-99"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("results file lacks %s:\n%s", want, raw)
		}
	}

	// The table now has one row.
	code, stdout, _ = run("bench", "--table", "--out", out)
	if code != ExitOK || !strings.Contains(stdout, "| none | deterministic |") {
		t.Fatalf("table: code=%d\n%s", code, stdout)
	}

	// A second run on the same day must not replace the file silently.
	code, _, stderr = run(args...)
	if code == ExitOK || !strings.Contains(stderr, "--force") {
		t.Fatalf("second run: code=%d stderr=%q", code, stderr)
	}
	if after, _ := os.ReadFile(files[0]); string(after) != string(raw) {
		t.Fatal("the refused run changed the results file")
	}
	if code, _, stderr = run(append(args, "--force")...); code != ExitOK {
		t.Fatalf("--force: code=%d stderr=%q", code, stderr)
	}
}

func TestBenchUsageErrors(t *testing.T) {
	cfg := emptyConfig(t)
	if code, _, errOut := run("bench", "--config", cfg, "extra"); code != ExitUsage || !strings.Contains(errOut, "--corpus") {
		t.Fatalf("positional argument: code=%d stderr=%q", code, errOut)
	}
	if code, _, errOut := run("bench", "--config", cfg, "--corpus", filepath.Join(t.TempDir(), "absent")); code != ExitUsage || !strings.Contains(errOut, "--corpus") {
		t.Fatalf("missing corpus: code=%d stderr=%q", code, errOut)
	}
	if code, _, _ := run("bench", "--no-such-flag"); code != ExitUsage {
		t.Fatalf("unknown flag: code=%d", code)
	}
}

// TestBenchPaidRunNeedsConsent checks that a remote model is never called
// without --yes or a terminal. The run is refused before any scan, so no
// request is made; the key is a placeholder that is never sent anywhere.
func TestBenchPaidRunNeedsConsent(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "placeholder-"+"not-a-key")
	corpus, out := benchCorpus(t), filepath.Join(t.TempDir(), "results")
	code, stdout, stderr := run("bench", "--config", emptyConfig(t), "--corpus", corpus, "--out", out,
		"--provider", "anthropic", "--model", "some-model", "--budget-usd", "2")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitUsage, stderr)
	}
	for _, want := range []string{"1 fixture scan(s)", "$2.00", "--yes", "no model was called"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if stdout != "" {
		t.Errorf("nothing should be reported for a refused run, got %q", stdout)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a refused run created the results directory")
	}
}

// Bench takes only the flags it reads: one that would do nothing is a
// usage error.
func TestBenchRefusesFlagsItIgnores(t *testing.T) {
	code, _, stderr := run("bench", "--help")
	for _, gone := range []string{"-authorize", "-fail-on", "-fail-on-confidence", "-format", "-pr "} {
		if strings.Contains(stderr, gone) {
			t.Errorf("bench --help lists %s", gone)
		}
	}
	if !strings.Contains(stderr, "-out") || !strings.Contains(stderr, "results file") {
		t.Errorf("bench --help lacks --out:\n%s (exit %d)", stderr, code)
	}
	for _, flag := range []string{"--fail-on=low", "--format=json", "--pr", "--authorize=scope.toml", "--fail-on-confidence=high"} {
		if code, _, _ := run("bench", flag, "--table"); code != ExitUsage {
			t.Errorf("bench %s exited %d, want %d", flag, code, ExitUsage)
		}
	}
}
