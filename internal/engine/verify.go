package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/agent"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/report"
	"github.com/TMHSDigital/spackle/internal/sandbox"
)

// VerifyOptions configure a verify run.
type VerifyOptions struct {
	Config   config.Config
	RunDir   string
	Progress io.Writer
	Clock    func() time.Time
	// DetectRuntime overrides container runtime detection, for tests.
	DetectRuntime func(ctx context.Context, preferred string) (sandbox.Runtime, error)
}

// VerifyOutcome is the result of re-running one stored proof.
type VerifyOutcome struct {
	FindingID  string
	Title      string
	Reproduces bool
	// Inconclusive is true when the proof could not be run to an answer
	// (it timed out, was killed, or the sandbox failed). The finding's
	// status is then left as it was.
	Inconclusive bool
	Note         string
}

// Verify re-runs the stored proof of concept of every finding the scan
// demonstrated against the target as it is now, appends the outcomes to the
// run's ledger, and rewrites the reports. A proof that no longer succeeds
// marks its finding fixed. A stored proof that never succeeded is skipped. Nothing
// is executed outside the sandbox, so without a container runtime Verify
// refuses instead of guessing.
func Verify(ctx context.Context, opts VerifyOptions) ([]VerifyOutcome, error) {
	run, err := report.Load(opts.RunDir)
	if err != nil {
		return nil, err
	}
	if run.TargetKind != "path" {
		return nil, fmt.Errorf("%w: run %s scanned a %s target. Verify re-runs proofs against a local directory; scan the directory to verify it", ErrRefused, run.ID, run.TargetKind)
	}
	// Proofs run against the directory that was scanned. A run stored
	// before the absolute path was recorded only has the target as it was
	// typed, which is resolved against the current directory.
	targetDir := run.TargetPath
	if targetDir == "" {
		targetDir = run.Target
		if !filepath.IsAbs(targetDir) && opts.Progress != nil {
			fmt.Fprintf(opts.Progress, "Run %s recorded its target as %q, relative to where the scan was run. Verify uses that path relative to the current directory: run it from the directory the scan was run from.\n", run.ID, run.Target)
		}
	}
	if st, serr := os.Stat(targetDir); serr != nil || !st.IsDir() {
		return nil, fmt.Errorf("%w: the target of run %s (%s) is no longer a directory here. Run verify where the scanned directory still exists, or scan again", ErrRefused, run.ID, targetDir)
	}
	detect := opts.DetectRuntime
	if detect == nil {
		detect = sandbox.Detect
	}
	rt, err := detect(ctx, opts.Config.Sandbox.Runtime)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	profile := sandbox.Profile{
		Network: opts.Config.Sandbox.Network, MemoryMB: opts.Config.Sandbox.MemoryMB, CPUs: opts.Config.Sandbox.CPUs,
		PIDs: opts.Config.Sandbox.PIDs, Timeout: opts.Config.Sandbox.Timeout.Duration,
	}.WithDefaults()

	type job struct {
		f   finding.Finding
		man pocManifest
	}
	var jobs []job
	for _, f := range run.Findings {
		raw, rerr := os.ReadFile(filepath.Join(opts.RunDir, "findings", f.ID, "poc", "poc.json")) //nolint:gosec // inside the run directory
		if rerr != nil {
			continue // no stored proof for this finding
		}
		var man pocManifest
		if json.Unmarshal(raw, &man) != nil || man.FindingID != f.ID || len(man.Command) == 0 || man.Marker == "" {
			return nil, fmt.Errorf("the stored proof for %s is damaged: re-run the scan to produce a new one", f.ID)
		}
		if f.Proof.Status != finding.ProofDemonstrated {
			// The scan also stores a proof that ran and did not show the
			// flaw. Running it again fails the same way, which says nothing
			// about a fix, so the finding is left as it is.
			if opts.Progress != nil {
				fmt.Fprintf(opts.Progress, "Skipping %s: its proof did not succeed during the scan, so re-running it cannot show a fix\n", f.ID)
			}
			continue
		}
		jobs = append(jobs, job{f, man})
	}
	if len(jobs) == 0 {
		return nil, fmt.Errorf("%w: run %s has no stored proofs to re-run. Proofs are stored when a scan demonstrates a finding in the sandbox", ErrRefused, run.ID)
	}

	led, err := ledger.Open(opts.RunDir, opts.Clock)
	if err != nil {
		return nil, err
	}
	defer func() { _ = led.Close() }()

	var outcomes []VerifyOutcome
	for _, j := range jobs {
		if err := ctx.Err(); err != nil {
			return outcomes, err
		}
		if opts.Progress != nil {
			fmt.Fprintf(opts.Progress, "Re-running the proof for %s\n", j.f.ID)
		}
		files := map[string]string{}
		for _, name := range j.man.Files {
			b, rerr := os.ReadFile(filepath.Join(opts.RunDir, "findings", j.f.ID, "poc", filepath.FromSlash(name))) //nolint:gosec // name comes from Spackle's own manifest in the run directory
			if rerr != nil {
				return outcomes, fmt.Errorf("the stored proof for %s is missing %s: re-run the scan", j.f.ID, name)
			}
			files[name] = string(b)
		}
		if !rt.ImagePresent(ctx, j.man.Image) {
			if opts.Config.Offline {
				return outcomes, fmt.Errorf("%w: sandbox image %s is not on this machine and offline mode does not pull images; pull it once while online", ErrRefused, j.man.Image)
			}
			if perr := rt.Pull(ctx, j.man.Image); perr != nil {
				return outcomes, fmt.Errorf("sandbox image %s is not available: %w", j.man.Image, perr)
			}
		}
		spec := sandbox.Spec{Image: j.man.Image, Cmd: j.man.Command, SourceDir: targetDir, Files: files, Profile: profile}
		res, rerr := rt.Run(ctx, spec)
		if rerr != nil {
			var note string
			if errors.Is(rerr, context.Canceled) || errors.Is(rerr, context.DeadlineExceeded) {
				return outcomes, rerr
			}
			note = "The proof could not be run: " + clipText(rerr.Error(), 200)
			outcomes = append(outcomes, VerifyOutcome{FindingID: j.f.ID, Title: j.f.Title, Reproduces: j.f.Status != finding.StatusFixed, Inconclusive: true, Note: note})
			continue
		}
		seq, aerr := led.Append(0, ledger.TypeSandboxRun, ledger.SandboxRun{
			FindingID: j.f.ID, Purpose: "verify", Image: spec.Image, Command: strings.Join(spec.Cmd, " "),
			ExitCode: res.ExitCode, TimedOut: res.TimedOut, Isolation: res.Isolation,
		})
		if aerr != nil {
			return outcomes, aerr
		}
		verdict := agent.JudgeProof(res, j.man.Marker)
		if verdict == agent.ProofInconclusive {
			// A proof that hangs or is killed shows nothing either way:
			// keep the finding as it is and say so.
			note := fmt.Sprintf("The proof could not be verified: it %s before it finished, so the finding keeps its status (%s). Raise the [sandbox] timeout or memory limit and run verify again.", agent.InconclusiveWhy(res), j.f.Status)
			if !res.Inconclusive() {
				// The marker was printed and the proof then failed. That
				// is not the proof succeeding, and it is not a fix.
				note = fmt.Sprintf("The proof could not be verified: it %s, which shows neither that the flaw is still there nor that it is gone, so the finding keeps its status (%s). Read the proof's output to see what failed.", agent.InconclusiveWhy(res), j.f.Status)
			}
			if _, err := led.Append(seq, ledger.TypeVerdict, ledger.Verdict{FindingID: j.f.ID, Stage: "verify", Outcome: "inconclusive", Reason: note}); err != nil {
				return outcomes, err
			}
			outcomes = append(outcomes, VerifyOutcome{FindingID: j.f.ID, Title: j.f.Title, Reproduces: j.f.Status != finding.StatusFixed, Inconclusive: true, Note: note})
			continue
		}
		reproduces := verdict == agent.ProofSucceeded
		f := j.f
		out := VerifyOutcome{FindingID: f.ID, Title: f.Title, Reproduces: reproduces}
		output, _ := redact.Apply(strings.TrimSpace(res.Stdout + "\n" + res.Stderr))
		if reproduces {
			out.Note = "The proof still succeeds against the current code."
			f.Status = finding.StatusOpen
			f.Proof.Result = clipText(output, 4000)
			if f.Remediation.Patch != "" {
				f.Remediation.Verification = "not applied: the proof still succeeds against the current code, so the patch has not been merged or does not hold there"
			}
		} else {
			out.Note = "The proof no longer succeeds against the current code."
			f.Status = finding.StatusFixed
			f.Remediation.Verification = "verified by spackle verify: the stored proof of concept no longer succeeds against the current code"
		}
		outcomeName := "still-reproduces"
		if !reproduces {
			outcomeName = "no-longer-reproduces"
		}
		if _, err := led.Append(seq, ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: "verify", Outcome: outcomeName, Reason: out.Note}); err != nil {
			return outcomes, err
		}
		if verr := f.Validate(); verr != nil {
			return outcomes, fmt.Errorf("verify produced an invalid finding for %s: %w", f.ID, verr)
		}
		if _, err := led.Append(seq, ledger.TypeFinding, f); err != nil {
			return outcomes, err
		}
		outcomes = append(outcomes, out)
	}
	if err := led.Close(); err != nil {
		return outcomes, err
	}
	updated, err := report.Load(opts.RunDir)
	if err != nil {
		return outcomes, err
	}
	return outcomes, WriteArtifacts(opts.RunDir, updated)
}
