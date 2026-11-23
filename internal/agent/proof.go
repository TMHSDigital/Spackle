package agent

import (
	"fmt"
	"strings"

	"github.com/TMHSDigital/spackle/internal/sandbox"
)

// ProofOutcome is what one run of a proof of concept showed.
type ProofOutcome int

const (
	// ProofNotShown means the proof ran to an end and did not print its
	// marker: the flaw's effect was not observed.
	ProofNotShown ProofOutcome = iota
	// ProofSucceeded means the proof printed its marker and exited with
	// code 0: the flaw's effect was observed.
	ProofSucceeded
	// ProofInconclusive means the run shows neither: the proof timed out,
	// was killed, or printed its marker and then failed. A caller must not
	// read it as "demonstrated" and must not read it as "fixed".
	ProofInconclusive
)

// JudgeProof decides what one run of a proof showed. It is the one rule for
// the prover, the debugger's reproduction, the fixer's check of a patch and
// spackle verify, so "demonstrated" and "fixed" mean the same everywhere.
func JudgeProof(res sandbox.Result, marker string) ProofOutcome {
	printed := marker != "" && strings.Contains(res.Stdout+res.Stderr, marker)
	switch {
	case res.Inconclusive():
		return ProofInconclusive
	case printed && res.ExitCode == 0:
		return ProofSucceeded
	case printed:
		return ProofInconclusive
	}
	return ProofNotShown
}

// InconclusiveWhy says, for a sentence, why a proof run was inconclusive:
// "the proof <why>".
func InconclusiveWhy(res sandbox.Result) string {
	switch {
	case res.TimedOut:
		return "timed out"
	case res.ExitCode == 137:
		return "was killed (exit code 137, usually the memory limit)"
	}
	return fmt.Sprintf("printed its marker and then exited with code %d", res.ExitCode)
}
