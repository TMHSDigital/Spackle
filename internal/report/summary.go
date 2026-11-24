package report

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/TMHSDigital/spackle/internal/ledger"
)

// SummaryFile is the name of the run summary inside a run directory.
const SummaryFile = "summary.json"

// Summary is the part of a run that a listing of runs shows. It is written
// next to the ledger when the run's reports are written, so that listing
// many runs does not read and decode every ledger. The ledger stays the
// only source of truth: a summary is used only while the ledger still has
// the size it had when the summary was written.
type Summary struct {
	RunID    string    `json:"run_id"`
	Target   string    `json:"target"`
	Outcome  string    `json:"outcome"`
	Started  time.Time `json:"started"`
	Findings int       `json:"findings"`
	Counts   Counts    `json:"counts"`
	// LedgerBytes is the size of the ledger this summary was made from.
	LedgerBytes int64 `json:"ledger_bytes"`
}

// WriteSummary writes the summary of run into runDir.
func WriteSummary(runDir string, run Run) error {
	st, err := os.Stat(filepath.Join(runDir, ledger.FileName))
	if err != nil {
		return err
	}
	s := Summary{
		RunID: run.ID, Target: run.Target, Outcome: run.Outcome, Started: run.StartedAt,
		Findings: len(run.Findings), Counts: run.Count(), LedgerBytes: st.Size(),
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runDir, SummaryFile), append(b, '\n'), 0o600)
}

// RunNames returns the names of the run directories in runsDir, newest
// first. Run ids start with a UTC timestamp, so that is reverse name order.
// A runs directory that does not exist yet holds no runs.
func RunNames(runsDir string) ([]string, error) {
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// SummaryOf returns the summary of the run in runDir: the stored one while
// it is current, otherwise one built from the ledger. It is what a listing
// of runs shows, so both listings (the CLI and MCP) read runs the same way.
func SummaryOf(runDir string) (Summary, error) {
	if s, ok := LoadSummary(runDir); ok {
		return s, nil
	}
	run, err := Load(runDir)
	if err != nil {
		return Summary{}, err
	}
	return Summary{
		RunID: run.ID, Target: run.Target, Outcome: run.Outcome, Started: run.StartedAt,
		Findings: len(run.Findings), Counts: run.Count(),
	}, nil
}

// LoadSummary returns the summary of the run in runDir. ok is false when
// there is none, when it cannot be read, or when the ledger has changed
// since it was written; the caller then loads the run from the ledger.
func LoadSummary(runDir string) (s Summary, ok bool) {
	b, err := os.ReadFile(filepath.Join(runDir, SummaryFile)) //nolint:gosec // path is built from the run directory
	if err != nil || json.Unmarshal(b, &s) != nil {
		return Summary{}, false
	}
	st, err := os.Stat(filepath.Join(runDir, ledger.FileName))
	if err != nil || st.Size() != s.LedgerBytes {
		return Summary{}, false
	}
	return s, true
}
