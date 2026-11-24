package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TMHSDigital/spackle/internal/agent"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/report"
)

// notInvestigatedPrefix starts the budget skip entry of a planned
// investigation that a run did not reach. A resumed run counts these
// entries to find where the earlier run stopped, so the two must agree.
const notInvestigatedPrefix = "Not investigated: "

// resumeState is what a resumed scan takes from the run it continues.
type resumeState struct {
	runID string
	// intents are the investigations the earlier run planned and did not
	// reach, in plan order.
	intents []agent.Intent
	// handled holds the lead ids of the investigations it did reach. Their
	// outcome is in findings, so this run does not report them again as
	// leads nobody looked at.
	handled map[string]bool
	// findings are the earlier run's findings. They are carried into the
	// new report unless this run reaches its own conclusion about one.
	findings []finding.Finding
}

// loadResume reads the run a scan of root continues. It refuses a run that
// has nothing left to investigate, a run of another target, and, without
// force, a target whose commit changed since: the plan and the findings of
// the earlier run describe that code.
func loadResume(ctx context.Context, stateDir, id, root string, force bool) (*resumeState, error) {
	dir, err := ResolveRun(stateDir, id)
	if err != nil {
		return nil, fmt.Errorf("--resume: %w", err)
	}
	run, err := report.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("--resume: %w", err)
	}
	events, err := ledger.Read(dir)
	if err != nil {
		return nil, fmt.Errorf("--resume: %w", err)
	}
	if run.Command != "scan" || run.Mode != "agentic" {
		return nil, fmt.Errorf("--resume: run %s planned no investigations (it was a %s %s), so there is nothing to continue", run.ID, run.Mode, run.Command)
	}
	if run.TargetPath == "" || !sameDir(run.TargetPath, root) {
		return nil, fmt.Errorf("--resume: run %s scanned %s, not %s. Resume it with the directory it scanned", run.ID, run.Target, root)
	}
	commit := ""
	if gitx.HasTracked(ctx, root) {
		commit, _ = gitx.HeadSHA(ctx, root)
	}
	if commit != run.Commit && !force {
		return nil, fmt.Errorf("--resume: the target is at commit %s and run %s scanned commit %s. Its plan and findings describe that code. Check out that commit, start a new scan, or pass --force to continue anyway",
			orNone(commit), run.ID, orNone(run.Commit))
	}

	var intents []agent.Intent
	for _, e := range events {
		if e.Type != ledger.TypeIntent {
			continue
		}
		var it agent.Intent
		if err := e.Decode(&it); err != nil {
			return nil, fmt.Errorf("--resume: %w", err)
		}
		intents = append(intents, it)
	}
	// A run stops at one point in its plan, so the investigations it did
	// not reach are the last ones.
	left := 0
	for _, skip := range run.Skipped {
		for _, s := range skip.Skipped {
			if strings.HasPrefix(s, notInvestigatedPrefix) {
				left++
			}
		}
	}
	if left > len(intents) {
		left = len(intents)
	}
	if left == 0 {
		return nil, fmt.Errorf("--resume: run %s (%s) has no planned investigation left to continue. Start a new scan instead", run.ID, run.Outcome)
	}
	st := &resumeState{runID: run.ID, intents: intents[len(intents)-left:], handled: map[string]bool{}, findings: run.Findings}
	for _, it := range intents[:len(intents)-left] {
		for _, id := range it.LeadIDs {
			st.handled[id] = true
		}
	}
	return st, nil
}

// Resumable reports whether a stored run stopped on its budget with planned
// investigations it did not reach, which scan --resume can continue.
func Resumable(run report.Run) bool {
	if run.Command != "scan" || run.Mode != "agentic" || run.Outcome != ledger.OutcomeBudgetExhausted {
		return false
	}
	for _, skip := range run.Skipped {
		for _, s := range skip.Skipped {
			if strings.HasPrefix(s, notInvestigatedPrefix) {
				return true
			}
		}
	}
	return false
}

func orNone(commit string) string {
	if commit == "" {
		return "(none)"
	}
	return commit
}

// sameDir reports whether two paths are the same directory. It compares
// file identity, not spelling, so a short Windows name or a different case
// does not matter.
func sameDir(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return os.SameFile(sa, sb)
}
