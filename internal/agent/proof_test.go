package agent

import (
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/sandbox"
)

func TestJudgeProof(t *testing.T) {
	const marker = "SPACKLE-PROOF-0123456789abcdef"
	for _, c := range []struct {
		name string
		res  sandbox.Result
		want ProofOutcome
		why  string
	}{
		{"marker and exit 0", sandbox.Result{Stdout: "ok " + marker}, ProofSucceeded, ""},
		{"marker on stderr and exit 0", sandbox.Result{Stderr: marker}, ProofSucceeded, ""},
		{"no marker, exit 0", sandbox.Result{Stdout: "nothing"}, ProofNotShown, ""},
		{"no marker, exit 1", sandbox.Result{ExitCode: 1, Stderr: "AssertionError"}, ProofNotShown, ""},
		{"marker, then exit 1", sandbox.Result{ExitCode: 1, Stdout: marker}, ProofInconclusive, "printed its marker and then exited with code 1"},
		{"timed out", sandbox.Result{TimedOut: true, ExitCode: -1}, ProofInconclusive, "timed out"},
		{"timed out after the marker", sandbox.Result{TimedOut: true, Stdout: marker}, ProofInconclusive, "timed out"},
		{"killed", sandbox.Result{ExitCode: 137}, ProofInconclusive, "was killed"},
		{"killed after the marker", sandbox.Result{ExitCode: 137, Stdout: marker}, ProofInconclusive, "was killed"},
	} {
		got := JudgeProof(c.res, marker)
		if got != c.want {
			t.Errorf("%s: outcome = %d, want %d", c.name, got, c.want)
		}
		if got == ProofInconclusive && !strings.Contains(InconclusiveWhy(c.res), c.why) {
			t.Errorf("%s: why = %q, want it to contain %q", c.name, InconclusiveWhy(c.res), c.why)
		}
	}
	// An empty marker is in every output and must never count as shown.
	if got := JudgeProof(sandbox.Result{Stdout: "anything"}, ""); got != ProofNotShown {
		t.Errorf("empty marker: outcome = %d, want not shown", got)
	}
}
