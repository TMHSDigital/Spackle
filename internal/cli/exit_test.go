package cli

import (
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/report"
)

// The exit code answers "is the scanned code still flawed". A patch that
// was written and checked is not applied, so it must not clear the gate.
func TestExitForCountsUnappliedPatches(t *testing.T) {
	cfg := config.Default()
	cfg.Output.FailOn = "high"
	high := func(status string) report.Run {
		return report.Run{Findings: []finding.Finding{{Status: status, Severity: finding.Severity{Label: "high"}}}}
	}
	cases := map[string]int{
		finding.StatusOpen:           ExitFindings,
		finding.StatusPatchAvailable: ExitFindings,
		finding.StatusFixed:          ExitOK,
		finding.StatusDismissed:      ExitOK,
	}
	for status, want := range cases {
		if got := exitFor(cfg, high(status)); got != want {
			t.Errorf("status %s: exit %d, want %d", status, got, want)
		}
	}
	low := report.Run{Findings: []finding.Finding{{Status: finding.StatusPatchAvailable, Severity: finding.Severity{Label: "low"}}}}
	if got := exitFor(cfg, low); got != ExitOK {
		t.Errorf("a finding below the threshold failed the run: exit %d", got)
	}
	cfg.Output.FailOn = "never"
	if got := exitFor(cfg, high(finding.StatusOpen)); got != ExitOK {
		t.Errorf("fail_on never: exit %d", got)
	}
}
