package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
)

func TestSummaryIsTrustedOnlyWhileTheLedgerIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	if _, ok := LoadSummary(dir); ok {
		t.Fatal("a run directory without a summary gave one")
	}
	led := filepath.Join(dir, ledger.FileName)
	if err := os.WriteFile(led, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	open := finding.Finding{ID: "SPK-00000001", Status: finding.StatusOpen}
	open.Severity.Label = "high"
	run := Run{ID: "20261122-120000-abcdef", Target: "./app", Outcome: "completed",
		StartedAt: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC), Findings: []finding.Finding{open}}
	if err := WriteSummary(dir, run); err != nil {
		t.Fatal(err)
	}
	s, ok := LoadSummary(dir)
	if !ok || s.RunID != run.ID || s.Target != "./app" || s.Outcome != "completed" || s.Findings != 1 || s.Counts != run.Count() || !s.Started.Equal(run.StartedAt) {
		t.Fatalf("summary = %+v, ok = %v", s, ok)
	}

	// The ledger is appended to (spackle verify does that): the summary no
	// longer stands for it.
	f, err := os.OpenFile(led, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadSummary(dir); ok {
		t.Fatal("a summary older than its ledger was trusted")
	}
	// Writing it again makes it current.
	if err := WriteSummary(dir, run); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadSummary(dir); !ok {
		t.Fatal("a rewritten summary was not trusted")
	}
	if err := os.WriteFile(filepath.Join(dir, SummaryFile), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadSummary(dir); ok {
		t.Fatal("a damaged summary was trusted")
	}
}
