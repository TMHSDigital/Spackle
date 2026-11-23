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

// TestExitForEveryThresholdSeverityAndStatus walks the whole grid: each
// --fail-on value against each severity and each status. The expected code
// is derived from the order of the severities list, not from the ranking
// function under test.
func TestExitForEveryThresholdSeverityAndStatus(t *testing.T) {
	severities := []string{"low", "medium", "high", "critical"} // least to most severe
	unresolved := map[string]bool{
		finding.StatusOpen:           true,
		finding.StatusPatchAvailable: true,
		finding.StatusFixed:          false,
		finding.StatusDismissed:      false,
	}
	for _, failOn := range []string{"critical", "high", "medium", "low", "never"} {
		threshold := -1
		for i, s := range severities {
			if s == failOn {
				threshold = i
			}
		}
		cfg := config.Default()
		cfg.Output.FailOn = failOn
		if err := cfg.Validate(); err != nil {
			t.Fatalf("fail_on %s is not a valid setting: %v", failOn, err)
		}
		for rank, severity := range severities {
			for status, open := range unresolved {
				want := ExitOK
				if failOn != "never" && open && rank >= threshold {
					want = ExitFindings
				}
				run := report.Run{Findings: []finding.Finding{{Status: status, Severity: finding.Severity{Label: severity}}}}
				if got := exitFor(cfg, run); got != want {
					t.Errorf("fail_on %s, %s finding with status %s: exit %d, want %d", failOn, severity, status, got, want)
				}
			}
		}
		if got := exitFor(cfg, report.Run{}); got != ExitOK {
			t.Errorf("fail_on %s with no findings: exit %d, want %d", failOn, got, ExitOK)
		}
	}
}

// One finding over the threshold is enough, wherever it sits in the list,
// and resolved findings of any severity never count.
func TestExitForLooksAtEveryFinding(t *testing.T) {
	f := func(status, severity string) finding.Finding {
		return finding.Finding{Status: status, Severity: finding.Severity{Label: severity}}
	}
	cfg := config.Default()
	cfg.Output.FailOn = "high"
	cases := []struct {
		name     string
		findings []finding.Finding
		want     int
	}{
		{"resolved critical findings and an open low one", []finding.Finding{
			f(finding.StatusDismissed, "critical"), f(finding.StatusFixed, "critical"), f(finding.StatusOpen, "low"),
		}, ExitOK},
		{"the last finding is the one over the threshold", []finding.Finding{
			f(finding.StatusOpen, "low"), f(finding.StatusDismissed, "critical"), f(finding.StatusOpen, "medium"), f(finding.StatusPatchAvailable, "high"),
		}, ExitFindings},
		{"only fixed and dismissed findings", []finding.Finding{
			f(finding.StatusFixed, "high"), f(finding.StatusDismissed, "high"),
		}, ExitOK},
		{"a finding with no severity", []finding.Finding{f(finding.StatusOpen, "none")}, ExitOK},
	}
	for _, c := range cases {
		if got := exitFor(cfg, report.Run{Findings: c.findings}); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}
