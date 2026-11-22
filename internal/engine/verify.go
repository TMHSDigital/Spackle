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
	Note       string
}

// Verify re-runs every stored proof of concept of a run against the target
// as it is now, appends the outcomes to the run's ledger, and rewrites the
// reports. A proof that no longer succeeds marks its finding fixed. Nothing
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
	if st, serr := os.Stat(run.Target); serr != nil || !st.IsDir() {
		return nil, fmt.Errorf("%w: the target of run %s (%s) is no longer a directory here. Run verify from the directory the scan was run from", ErrRefused, run.ID, run.Target)
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
		spec := sandbox.Spec{Image: j.man.Image, Cmd: j.man.Command, SourceDir: run.Target, Files: files, Profile: profile}
		res, rerr := rt.Run(ctx, spec)
		if rerr != nil {
			var note string
			if errors.Is(rerr, context.Canceled) || errors.Is(rerr, context.DeadlineExceeded) {
				return outcomes, rerr
			}
			note = "The proof could not be run: " + clipText(rerr.Error(), 200)
			outcomes = append(outcomes, VerifyOutcome{FindingID: j.f.ID, Title: j.f.Title, Reproduces: j.f.Status != finding.StatusFixed, Note: note})
			continue
		}
		seq, aerr := led.Append(0, ledger.TypeSandboxRun, ledger.SandboxRun{
			FindingID: j.f.ID, Purpose: "verify", Image: spec.Image, Command: strings.Join(spec.Cmd, " "),
			ExitCode: res.ExitCode, TimedOut: res.TimedOut, Isolation: res.Isolation,
		})
		if aerr != nil {
			return outcomes, aerr
		}
		reproduces := !res.TimedOut && res.ExitCode == 0 && strings.Contains(res.Stdout+res.Stderr, j.man.Marker)
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
