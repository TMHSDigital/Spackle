package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/finding"
)

// The baseline workflow end to end: a scan fails on a high finding,
// spackle baseline accepts it, and the next scan with --baseline still
// reports it, as accepted, but exits 0. An entry that matches nothing is
// listed, and a regenerated file keeps the reason it had.
func TestBaselineAcceptsFindingsWithoutHidingThem(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	t.Setenv("PATH", t.TempDir()) // no external scanners
	file := filepath.Join(t.TempDir(), "baseline.json")

	if code, _, stderr := run("scan", target, "--config", cfg, "--format", "json", "--fail-on", "high"); code != ExitFindings {
		t.Fatalf("scan before the baseline: exit = %d, want %d\nstderr: %s", code, ExitFindings, stderr)
	}
	code, out, stderr := run("baseline", "--config", cfg, "--out", file, "--reason", "legacy code, tracked elsewhere")
	if code != ExitOK || !strings.Contains(out, "Wrote 1 entries") {
		t.Fatalf("baseline: exit = %d\nstdout: %s\nstderr: %s", code, out, stderr)
	}
	b, err := finding.LoadBaseline(file)
	if err != nil || len(b.Entries) != 1 || b.Entries[0].Fingerprint == "" || b.Entries[0].Reason != "legacy code, tracked elsewhere" {
		t.Fatalf("baseline file = %+v, err = %v", b, err)
	}

	for format, want := range map[string][]string{
		"json":     {`"status": "accepted"`, `"accept_reason": "legacy code, tracked elsewhere"`, `"accepted": 1`},
		"sarif":    {`"suppressions"`, `"kind": "external"`, `"justification": "legacy code, tracked elsewhere"`},
		"terminal": {"accepted", "Accepted because"},
	} {
		code, out, stderr := run("scan", target, "--config", cfg, "--format", format, "--fail-on", "high", "--baseline", file)
		if code != ExitOK {
			t.Fatalf("%s: scan with the baseline: exit = %d, want %d\nstderr: %s", format, code, ExitOK, stderr)
		}
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("%s output lacks %q:\n%s", format, w, out)
			}
		}
	}

	// An entry that matches nothing is listed in the run's notes.
	b.Entries = append(b.Entries, finding.BaselineEntry{ID: "SPK-00000000", Fingerprint: "ffffffffffffffff", Title: "Gone finding", Location: "old.py:1"})
	writeBaseline(t, file, b)
	if code, out, stderr := run("scan", target, "--config", cfg, "--format", "terminal", "--baseline", file); code != ExitOK || !strings.Contains(out, "1 baseline entries matched no finding") || !strings.Contains(out, "Gone finding") {
		t.Fatalf("stale entry: exit = %d\nstdout: %s\nstderr: %s", code, out, stderr)
	}

	// Regenerating from the latest run, where the finding is accepted,
	// keeps its entry and reason and drops the stale one.
	code, out, stderr = run("baseline", "--config", cfg, "--out", file, "--reason", "new reason")
	if code != ExitOK || !strings.Contains(out, "1 kept their reason") {
		t.Fatalf("regenerate: exit = %d\nstdout: %s\nstderr: %s", code, out, stderr)
	}
	if b, err = finding.LoadBaseline(file); err != nil || len(b.Entries) != 1 || b.Entries[0].Reason != "legacy code, tracked elsewhere" {
		t.Fatalf("regenerated baseline = %+v, err = %v", b, err)
	}

	// A baseline that cannot be read refuses the scan before a run exists.
	before := len(runDirs(t, stateDir))
	code, _, stderr = run("scan", target, "--config", cfg, "--baseline", filepath.Join(t.TempDir(), "missing.json"))
	if code != ExitUsage || !strings.Contains(stderr, "spackle baseline") {
		t.Fatalf("missing baseline: exit = %d\nstderr: %s", code, stderr)
	}
	if after := len(runDirs(t, stateDir)); after != before {
		t.Errorf("a refused scan left a run behind: %d runs, want %d", after, before)
	}
}

// --out - writes the baseline to stdout and no file.
func TestBaselineToStdout(t *testing.T) {
	cfg, _ := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	t.Setenv("PATH", t.TempDir())
	if code, _, stderr := run("scan", target, "--config", cfg, "--format", "json"); code != ExitFindings {
		t.Fatalf("scan: exit = %d\nstderr: %s", code, stderr)
	}
	code, out, stderr := run("baseline", "latest", "--config", cfg, "--out", "-")
	if code != ExitOK {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr)
	}
	if _, err := finding.ParseBaseline([]byte(out)); err != nil {
		t.Fatalf("stdout is not a baseline: %v\n%s", err, out)
	}
}

func writeBaseline(t *testing.T, path string, b finding.Baseline) {
	t.Helper()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
