package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/agent"
	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/gitx"
	proglang "github.com/TMHSDigital/spackle/internal/lang"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/textx"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// lab holds what the proof and fix stages share for one run.
type lab struct {
	r        *runner
	root     string
	runtime  sandbox.Runtime // nil when no container runtime is available
	why      string          // why runtime is nil
	profile  sandbox.Profile
	tests    mapper.Harness
	baseline *bool // nil until the unmodified test suite has been run
	images   map[string]bool
	// fixes collects accepted patches for the fix branch, in order.
	fixes []acceptedFix
	// worktree is where the fix branch is checked out, once created.
	worktree string
	// branched holds the ids of the findings whose fix was committed to
	// the fix branch.
	branched map[string]bool
}

// openPR pushes the fix branch and opens a draft pull request. It runs only
// when the operator asked for it with --pr.
func (l *lab) openPR(ctx context.Context, branch string, fixed []finding.Finding) string {
	open := l.r.opts.OpenPR
	if open == nil {
		open = gitx.OpenPR
	}
	var body strings.Builder
	body.WriteString("Fixes written and checked by [Spackle](https://github.com/TMHSDigital/Spackle). Read each change before merging.\n\n")
	body.WriteString("| Finding | Severity | What was checked |\n| :--- | :--- | :--- |\n")
	for _, f := range fixed {
		fmt.Fprintf(&body, "| %s %s (`%s`) | %s | %s |\n", f.ID, strings.ReplaceAll(f.Title, "|", "/"), f.Location.String(), f.Severity.Label, strings.ReplaceAll(f.Remediation.Verification, "|", "/"))
	}
	fmt.Fprintf(&body, "\nRun `spackle report %s` for the full findings, and `spackle verify %s` after merging to re-run the proofs.\n", l.r.runID, l.r.runID)
	title := fmt.Sprintf("fix: %d security finding(s) from Spackle run %s", len(fixed), l.r.runID)
	if len(fixed) == 1 {
		title = "fix: " + fixed[0].Title
	}
	url, err := open(ctx, gitx.PRRequest{Dir: l.worktree, Branch: branch, Title: textx.Clip(title, 120), Body: body.String()})
	if err != nil {
		return "The pull request was not opened: " + textx.Clip(err.Error(), 300)
	}
	return "Draft pull request opened: " + url
}

type acceptedFix struct {
	id, title string
	files     map[string]string
}

func (r *runner) newLab(root string, tests mapper.Harness, rt sandbox.Runtime, why string) *lab {
	return &lab{
		r: r, root: root, runtime: rt, why: why, tests: tests, images: map[string]bool{},
		profile: r.cfg.Sandbox.Profile().WithDefaults(),
	}
}

// detectRuntime finds the container runtime. override replaces the
// detection in tests; nil means the real one.
func detectRuntime(ctx context.Context, override func(context.Context, string) (sandbox.Runtime, error), preferred string) (sandbox.Runtime, error) {
	if override == nil {
		override = sandbox.Detect
	}
	return override(ctx, preferred)
}

// offlineImageError says that an image would have to be pulled and offline
// mode does not pull.
type offlineImageError struct{ image string }

func (e offlineImageError) Error() string {
	return fmt.Sprintf("sandbox image %s is not on this machine and offline mode does not pull images; pull it once while online", e.image)
}

// ensureImage makes a sandbox image present on this machine. An image that
// is missing is pulled, except in offline mode, where it is an
// offlineImageError.
func ensureImage(ctx context.Context, rt sandbox.Runtime, img string, offline bool, progress io.Writer) error {
	if rt.ImagePresent(ctx, img) {
		return nil
	}
	if offline {
		return offlineImageError{image: img}
	}
	progressf(progress, "Pulling sandbox image %s", img)
	if err := rt.Pull(ctx, img); err != nil {
		return fmt.Errorf("sandbox image %s is not available: %w", img, err)
	}
	return nil
}

// isolation describes the sandbox for the run summary.
func (l *lab) isolation() string {
	if l.runtime == nil {
		return "no container runtime: proofs and fixes were not run (" + l.why + ")"
	}
	return l.runtime.Name() + ": " + l.profile.Summary()
}

// image returns the sandbox image for a language, pulling it on first use.
func (l *lab) image(ctx context.Context, lang string) (string, error) {
	img := l.r.cfg.Sandbox.Images[lang]
	if img == "" {
		return "", fmt.Errorf("no sandbox image is configured for %s", lang)
	}
	if l.images[img] {
		return img, nil
	}
	if err := ensureImage(ctx, l.runtime, img, l.r.cfg.Offline, l.r.progress); err != nil {
		return "", err
	}
	l.images[img] = true
	return img, nil
}

// box builds the sandbox handle for one finding. Every run it makes is
// written to the ledger and to the finding's evidence folder.
func (l *lab) box(findingID string, parent int64) *agent.Box {
	n := 0
	return &agent.Box{
		Runtime: l.runtime, Profile: l.profile, Budget: l.r.budget, Root: l.root,
		Record: func(purpose string, spec sandbox.Spec, res sandbox.Result) error {
			n++
			dir := filepath.Join(l.r.runDir, "findings", findingID, "evidence")
			if findingID == "" {
				dir = filepath.Join(l.r.runDir, "evidence")
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("write evidence: %w", err)
			}
			name := fmt.Sprintf("%02d-%s.txt", n, purpose)
			out, _ := redact.Apply(res.Stdout)
			errOut, _ := redact.Apply(res.Stderr)
			body := fmt.Sprintf("purpose: %s\nimage: %s\ncommand: %s\nisolation: %s\nexit code: %d\ntimed out: %v\n\n--- stdout ---\n%s\n--- stderr ---\n%s\n",
				purpose, spec.Image, strings.Join(spec.Cmd, " "), res.Isolation, res.ExitCode, res.TimedOut, out, errOut)
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				return fmt.Errorf("write evidence: %w", err)
			}
			rel := filepath.ToSlash(filepath.Join("findings", findingID, "evidence", name))
			if findingID == "" {
				rel = "evidence/" + name
			}
			_, err := l.r.led.Append(parent, ledger.TypeSandboxRun, ledger.SandboxRun{
				FindingID: findingID, Purpose: purpose, Image: spec.Image, Command: strings.Join(spec.Cmd, " "),
				ExitCode: res.ExitCode, TimedOut: res.TimedOut, Isolation: res.Isolation, OutputRef: rel,
			})
			return err
		},
	}
}

// baselineTests runs the project's own test suite once on the unmodified
// code, so the fixer knows whether a later failure is a regression.
func (l *lab) baselineTests(ctx context.Context, parent int64, lang, image string) (cmd []string, pass bool, err error) {
	if l.tests.TestCommand == "" || l.tests.Language != lang {
		return nil, false, nil
	}
	// The test command is one of a fixed set the mapper chooses; it is
	// never taken from target content.
	cmd = strings.Fields(l.tests.TestCommand)
	if l.baseline != nil {
		return cmd, *l.baseline, nil
	}
	l.r.say("Running the project's tests once as a baseline")
	box := l.box("", parent)
	if err := l.r.budget.UseSandbox(); err != nil {
		return cmd, false, err
	}
	spec := sandbox.Spec{Image: image, Cmd: cmd, SourceDir: l.root, Profile: l.profile}
	res, rerr := l.runtime.Run(ctx, spec)
	if rerr != nil {
		return cmd, false, rerr
	}
	if err := box.Record("tests-baseline", spec, res); err != nil {
		return cmd, false, err
	}
	ok := res.ExitCode == 0 && !res.TimedOut
	l.baseline = &ok
	return cmd, ok, nil
}

// proveAndFix tries to demonstrate one finding and then to fix it. It
// returns the updated finding. Budget exhaustion is returned as an error
// wrapping budget.ErrExhausted with the finding as far as it got.
func (l *lab) proveAndFix(ctx context.Context, f finding.Finding, parent int64, prover, fixer *agent.Runner, newRegistry func() *tools.Registry) (finding.Finding, error) {
	lang := walk.LangOf(f.Location.File)
	if l.runtime == nil {
		f.Proof.Reason = "Traced by reading the code. No container runtime was available, so no proof of concept was run and no fix was verified."
		return f, nil
	}
	if !proglang.Supported(lang) {
		f.Proof.Reason = "Traced by reading the code. Proofs are run automatically for " + proglang.DisplayList() + " only in this version."
		return f, nil
	}
	image, err := l.image(ctx, lang)
	if err != nil {
		f.Proof.Reason = "Traced by reading the code. The proof was not run: " + err.Error() + "."
		return f, nil
	}

	l.r.say("  Demonstrating %s", f.ID)
	box := l.box(f.ID, parent)
	proof, perr := agent.Prove(ctx, prover, parent, l.r.sealer, newRegistry(), box, lang, image, f)
	if perr != nil && !errors.Is(perr, budget.ErrExhausted) {
		if ctx.Err() != nil {
			return f, ctx.Err()
		}
		f.Proof.Reason = "Traced by reading the code. The proof step failed: " + textx.Clip(perr.Error(), 200)
		perr = nil
	}
	if proof.PoC != nil {
		if err := l.writePoC(f.ID, proof.PoC); err != nil {
			return f, err
		}
	}
	switch {
	case proof.Demonstrated:
		f.Proof = finding.Proof{
			Status: finding.ProofDemonstrated, Kind: "script", Summary: proof.PoC.Explanation,
			Command: strings.Join(proof.PoC.Command, " "), Result: proof.Output, Isolation: l.runtime.Name() + ": " + proof.Isolation,
		}
		for _, name := range proof.PoC.SortedFiles() {
			f.Proof.Artifacts = append(f.Proof.Artifacts, "findings/"+f.ID+"/poc/"+name)
		}
		f.Confidence = finding.Confidence{
			Level:  finding.ConfidenceDemonstrated,
			Reason: "A proof of concept ran in the sandbox and showed the flaw's effect. Read the proof to see exactly what it asserts.",
		}
		if _, err := l.r.led.Append(parent, ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: config.StageProver, Outcome: ledger.VerdictDemonstrated}); err != nil {
			return f, err
		}
	case proof.PoC != nil:
		// A proof ran and did not show the flaw. That is information, and
		// it is reported as such rather than hidden.
		f.Proof.Status = finding.ProofFailed
		f.Proof.Reason = proof.Reason + " The finding stands on the code reading alone."
		f.Proof.Result = proof.Output
		f.Proof.Isolation = l.runtime.Name() + ": " + proof.Isolation
		if _, err := l.r.led.Append(parent, ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: config.StageProver, Outcome: ledger.VerdictNotReproduced, Reason: proof.Reason}); err != nil {
			return f, err
		}
	case proof.Reason != "":
		f.Proof.Reason = "Traced by reading the code. " + proof.Reason
	}
	if perr != nil {
		return f, perr
	}

	if !l.r.cfg.Fix.On() {
		return f, nil
	}
	testCmd, basePass, terr := l.baselineTests(ctx, parent, lang, image)
	if terr != nil {
		if errors.Is(terr, budget.ErrExhausted) {
			return f, terr
		}
		testCmd, basePass = nil, false
	}
	l.r.say("  Fixing %s", f.ID)
	in := agent.FixInput{Language: lang, Image: image, TestCmd: testCmd, BaselineTestsPass: basePass, MaxAttempts: l.r.cfg.Fix.MaxAttempts}
	if proof.Demonstrated {
		in.PoC = proof.PoC
	}
	fix, ferr := agent.Fix(ctx, fixer, parent, l.r.sealer, newRegistry(), box, in, f)
	if ferr != nil && !errors.Is(ferr, budget.ErrExhausted) {
		if ctx.Err() != nil {
			return f, ctx.Err()
		}
		f.Remediation.Verification = "no patch: the fix step failed (" + textx.Clip(ferr.Error(), 200) + ")"
		return f, nil
	}
	switch {
	case fix.Patch != "":
		f.Remediation.Patch = fix.Patch
		f.Remediation.Verification = fix.Verification
		if fix.Why != "" {
			f.Remediation.Why = fix.Why
		}
		outcome := ledger.VerdictFixUnverified
		if fix.Verified {
			// The patch is checked but not applied: the scanned tree is
			// never changed, so the flaw is still in the code.
			f.Status = finding.StatusPatchAvailable
			outcome = ledger.VerdictFixed
		}
		l.fixes = append(l.fixes, acceptedFix{id: f.ID, title: f.Title, files: fix.Files})
		if _, err := l.r.led.Append(parent, ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: config.StageFixer, Outcome: outcome, Reason: fix.Verification}); err != nil {
			return f, err
		}
	case fix.Reason != "":
		f.Remediation.Verification = "no patch: " + fix.Reason
		if _, err := l.r.led.Append(parent, ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: config.StageFixer, Outcome: ledger.VerdictFixRejected, Reason: fix.Reason}); err != nil {
			return f, err
		}
	}
	return f, ferr
}

// pocManifest is stored next to a proof so "spackle verify" can re-run it.
type pocManifest struct {
	FindingID string   `json:"finding_id"`
	Command   []string `json:"command"`
	Marker    string   `json:"marker"`
	Language  string   `json:"language"`
	Image     string   `json:"image"`
	Files     []string `json:"files"`
}

func (l *lab) writePoC(id string, poc *agent.PoC) error {
	dir := filepath.Join(l.r.runDir, "findings", id, "poc")
	for name, content := range poc.Files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return fmt.Errorf("write proof: %w", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return fmt.Errorf("write proof: %w", err)
		}
	}
	man := pocManifest{FindingID: id, Command: poc.Command, Marker: poc.Marker, Language: poc.Language, Image: poc.Image, Files: poc.SortedFiles()}
	b, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("write proof: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "poc.json"), append(b, '\n'), 0o600)
}

// branchFixes commits the accepted patches to a new branch in a new git
// worktree and returns the branch name, or "" with a note when the target
// is not a git repository. The operator's working tree, index and current
// branch are not touched.
func (l *lab) branchFixes(ctx context.Context) (branch, note string) {
	if len(l.fixes) == 0 {
		return "", ""
	}
	defer func() {
		if branch == "" {
			l.worktree = ""
		}
	}()
	top, err := gitx.TopLevel(ctx, l.root)
	if err != nil {
		return "", "The target is not in a git repository, so fixes were written as patch files only (findings/<id>/fix.patch)."
	}
	// Only branch when the files being fixed are tracked. Otherwise the
	// target merely sits under some unrelated repository, and creating a
	// branch there would touch a repository the operator did not point at.
	var changed []string
	for _, fx := range l.fixes {
		for name := range fx.files {
			changed = append(changed, name)
		}
	}
	if !gitx.Tracked(ctx, l.root, changed...) {
		return "", "The fixed files are not tracked by git, so fixes were written as patch files only (findings/<id>/fix.patch)."
	}
	rel, rerr := gitx.Prefix(ctx, l.root)
	if rerr != nil {
		return "", "The target's git repository could not be located reliably, so fixes were written as patch files only."
	}
	rel = filepath.FromSlash(rel)

	// A fix is the whole new content of each file, built from the file as
	// it is in the working tree. Writing that over HEAD would commit the
	// operator's uncommitted edits to that file under the fix's message, so
	// such a fix stays a patch file only.
	var skipped []string
	var fixes []acceptedFix
	for _, fx := range l.fixes {
		names := make([]string, 0, len(fx.files))
		for name := range fx.files {
			names = append(names, name)
		}
		sort.Strings(names)
		dirty, derr := gitx.Dirty(ctx, l.root, names...)
		switch {
		case derr != nil:
			skipped = append(skipped, fmt.Sprintf("%s could not be compared with the last commit: %s", fx.id, textx.Clip(derr.Error(), 200)))
		case dirty:
			skipped = append(skipped, fmt.Sprintf("%s changes %s, which has uncommitted changes in your working tree; commit or stash them and scan again to get this fix on a branch", fx.id, strings.Join(names, ", ")))
		default:
			fixes = append(fixes, fx)
		}
	}
	if len(fixes) == 0 {
		return "", "No fix branch was created. Not on a branch (apply the patch file by hand): " + strings.Join(skipped, "; ") + "."
	}
	branch = "spackle/" + l.r.runID
	absState, _ := filepath.Abs(l.r.cfg.StateDir)
	wt := filepath.Join(absState, "worktrees", l.r.runID)
	l.worktree = wt
	if err := os.MkdirAll(filepath.Dir(wt), 0o700); err != nil {
		return "", "The fix branch could not be created: " + err.Error()
	}
	if err := gitx.AddWorktree(ctx, top, wt, branch); err != nil {
		return "", "The fix branch could not be created (" + textx.Clip(err.Error(), 200) + "), so fixes were written as patch files only."
	}
	touched := map[string]string{}
	committed := 0
	// undo puts the worktree back to the last commit after a fix failed
	// part way, so its files are not swept into the next fix's commit.
	undo := func(fx acceptedFix) {
		for name, owner := range touched {
			if owner == fx.id {
				delete(touched, name)
			}
		}
		if rerr := gitx.ResetWorktree(ctx, wt); rerr != nil {
			skipped = append(skipped, fmt.Sprintf("the fix worktree could not be restored after %s failed: %v", fx.id, rerr))
		}
	}
	for _, fx := range fixes {
		conflict := ""
		for name := range fx.files {
			if owner, ok := touched[name]; ok {
				conflict = fmt.Sprintf("%s also changes %s, which the fix for %s already changed", fx.id, name, owner)
			}
		}
		if conflict != "" {
			skipped = append(skipped, conflict)
			continue
		}
		ok := true
		for name, content := range fx.files {
			p := filepath.Join(wt, rel, filepath.FromSlash(name))
			err := os.MkdirAll(filepath.Dir(p), 0o700)
			if err == nil {
				err = os.WriteFile(p, []byte(content), 0o600) //nolint:gosec // name was validated by walk.Resolve against the target
			}
			if err != nil {
				ok = false
				skipped = append(skipped, fmt.Sprintf("%s could not be written to the fix branch: %v", fx.id, err))
				break
			}
			touched[name] = fx.id
		}
		if !ok {
			undo(fx)
			continue
		}
		if err := gitx.CommitAll(ctx, wt, fmt.Sprintf("fix: %s (%s)\n\nPatch written and checked by Spackle. Review before merging.", fx.title, fx.id)); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s could not be committed: %v", fx.id, err))
			undo(fx)
			continue
		}
		committed++
		if l.branched == nil {
			l.branched = map[string]bool{}
		}
		l.branched[fx.id] = true
	}
	note = fmt.Sprintf("%d fix(es) committed to branch %s in worktree %s. Your working tree was not changed.", committed, branch, filepath.ToSlash(wt))
	if len(skipped) > 0 {
		note += " Not on the branch (apply the patch file by hand): " + strings.Join(skipped, "; ") + "."
	}
	if committed == 0 {
		return "", note
	}
	return branch, note
}
