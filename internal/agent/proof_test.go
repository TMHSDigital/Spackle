package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/llm"
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

// TestProveAndReproduceShareOneLoop pins what the two callers of the shared
// loop say to the model and to the reader. They differ only in their words:
// a rejected attempt and a run without the marker are each sent back once,
// with the reason, and the task is repeated in the same envelope.
func TestProveAndReproduceShareOneLoop(t *testing.T) {
	flaw := finding.Finding{Title: "SQL injection in search", Class: "sql-injection"}
	for _, c := range []struct {
		name, claim, purpose                     string
		rejected, notShown, output, advice, task string
		run                                      func(f *fixture, box *Box) (ProofResult, error)
	}{
		{
			name: "prove", claim: "can_prove", purpose: "poc",
			rejected: "Your proof was rejected before running: ",
			notShown: "The proof ran (exit code 1) and did not show the flaw.",
			output:   `source="proof output"`,
			advice:   "reply with can_prove false and say so",
			task:     `source="finding to demonstrate"`,
			run: func(f *fixture, box *Box) (ProofResult, error) {
				return Prove(context.Background(), f.runner, 0, f.sealer, f.reg, box, "python", "img", flaw)
			},
		},
		{
			name: "reproduce", claim: "can_reproduce", purpose: "repro",
			rejected: "Your reproduction was rejected before running: ",
			notShown: "The reproduction ran (exit code 1) and did not show the problem.",
			output:   `source="reproduction output"`,
			advice:   "reply with can_reproduce false and say so",
			task:     `source="issue description"`,
			run: func(f *fixture, box *Box) (ProofResult, error) {
				return Reproduce(context.Background(), f.runner, 0, f.sealer, f.reg, box, "python", "img", "it breaks")
			},
		},
	} {
		bad := jsonText(t, map[string]any{c.claim: true, "files": map[string]string{"app.py": "print(1)\n"}, "command": []string{"python", "app.py"}})
		good := jsonText(t, map[string]any{c.claim: true, "files": map[string]string{"spackle_poc/p.py": "raise SystemExit(1)\n"}, "command": []string{"python", "spackle_poc/p.py"}})

		// Rejected before running, then a run that does not show the marker.
		f := setup(t, budget.Caps{}, llm.Say(bad), llm.Say(good))
		rt := &dbgRuntime{fn: func(sandbox.Spec) sandbox.Result { return sandbox.Result{ExitCode: 1, Stderr: "no luck"} }}
		var purposes []string
		res, err := c.run(f, dbgBox(f, rt, &purposes))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.Demonstrated || res.Attempts != 2 || res.Reason != c.notShown || res.PoC == nil || !strings.Contains(res.Output, "no luck") {
			t.Errorf("%s: result = %+v", c.name, res)
		}
		if strings.Join(purposes, ",") != c.purpose {
			t.Errorf("%s: sandbox runs = %v, want one %s run", c.name, purposes, c.purpose)
		}
		second := f.fake.Requests[1].Messages[0].Text
		for _, want := range []string{c.rejected, "must be inside spackle_poc/", "reply again in the same JSON format", c.task} {
			if !strings.Contains(second, want) {
				t.Errorf("%s: the prompt after a rejection lacks %q:\n%s", c.name, want, second)
			}
		}

		// Two runs without the marker: the first is sent back with its output.
		f = setup(t, budget.Caps{}, llm.Say(good), llm.Say(good))
		if res, err = c.run(f, dbgBox(f, rt, &purposes)); err != nil || res.Attempts != 2 || res.Reason != c.notShown {
			t.Fatalf("%s: result = %+v, err = %v", c.name, res, err)
		}
		second = f.fake.Requests[1].Messages[0].Text
		for _, want := range []string{c.notShown + " Its output was:", c.output, "no luck", c.advice, c.task} {
			if !strings.Contains(second, want) {
				t.Errorf("%s: the prompt after a failed run lacks %q:\n%s", c.name, want, second)
			}
		}
	}
}
