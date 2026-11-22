package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/diffx"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// FixResult is the outcome of trying to fix a finding.
type FixResult struct {
	// Files maps a target-relative path to its full new content.
	Files map[string]string
	// Patch is the unified diff Spackle computed from Files.
	Patch string
	Why   string
	// Verified is true only when a proof of concept that used to succeed no
	// longer does, and nothing that was checked got worse.
	Verified bool
	// Verification says, in a sentence, exactly what was and was not checked.
	Verification string
	Attempts     int
	// Reason explains a failure to produce any acceptable patch.
	Reason string
}

// FixInput is what the fixer needs besides the finding.
type FixInput struct {
	Language string
	Image    string
	// PoC is the proof that demonstrated the finding, or nil.
	PoC *PoC
	// TestCmd is the project's test command as an argument vector, or nil.
	TestCmd []string
	// BaselineTestsPass says whether TestCmd passed on the unmodified code.
	// A patch is only held to the suite when the suite was green to begin
	// with: a suite that already fails cannot tell a regression from noise.
	BaselineTestsPass bool
	MaxAttempts       int
}

func fixerSystem(s *envelope.Sealer) string {
	return roleFrame + "\n\n" + s.Preamble() + `

Your job in this step is to fix one finding. Write the smallest change that removes the flaw at
its cause: parameterize the query, pass an argument vector instead of a shell string, resolve and
confine the path, verify the signature. Do not refactor, rename, reformat or "improve" anything
else, and do not weaken or delete tests. Keep the code's existing style and behavior for
legitimate input. A change that makes the program stop working is not a fix.

Your patch is checked in a sandbox: the changed files must still compile or parse, the project's
tests must still pass when it has a passing suite, and when a proof of concept demonstrated the
flaw, that same proof must stop working.

Reply with one JSON object and nothing else:
{"files":{"relative/path.py":"the COMPLETE new content of that file"},
 "why":"why this change closes the flaw, in one or two sentences"}
Give the whole file for each file you change, not a diff and not an excerpt. Change at most three
files, and only files that already exist.`
}

type fixerReply struct {
	Files map[string]string `json:"files"`
	Why   string            `json:"why"`
}

// compileCheck returns a cheap command that fails when a changed file no
// longer compiles or parses. It guards against a "fix" that only stops the
// proof by breaking the program.
func compileCheck(language string, changed []string) []string {
	switch language {
	case "python":
		return append([]string{"python", "-m", "py_compile"}, changed...)
	case "go":
		return []string{"go", "build", "./..."}
	case "javascript":
		if len(changed) == 1 {
			return []string{"node", "--check", changed[0]}
		}
	}
	return nil
}

// loadOriginals validates the fixer's files and returns the original content
// of each, read as raw bytes so line endings are preserved.
func loadOriginals(root string, files map[string]string) (clean, originals map[string]string, err error) {
	if len(files) == 0 {
		return nil, nil, errors.New("the reply changes no files")
	}
	if len(files) > 3 {
		return nil, nil, fmt.Errorf("the reply changes %d files; at most 3 are allowed", len(files))
	}
	clean, originals = map[string]string{}, map[string]string{}
	for name, content := range files {
		rel := path.Clean(strings.ReplaceAll(strings.TrimSpace(name), `\`, "/"))
		abs, rerr := walk.Resolve(root, rel)
		if rerr != nil {
			return nil, nil, fmt.Errorf("file %q: %w. A fix may only change files that exist in the target", name, rerr)
		}
		if strings.HasPrefix(rel, pocPrefix) || isTestPath(rel) {
			return nil, nil, fmt.Errorf("file %q is a test or proof file; fix the code, not the check", name)
		}
		if len(content) > walk.MaxFileSize {
			return nil, nil, fmt.Errorf("file %q is larger than the %d byte limit", name, walk.MaxFileSize)
		}
		raw, oerr := os.ReadFile(abs) //nolint:gosec // abs comes from walk.Resolve
		if oerr != nil {
			return nil, nil, fmt.Errorf("file %q cannot be read", name)
		}
		orig := string(raw)
		// Keep the file's own line endings so the patch touches only what
		// the fix changes.
		content = strings.ReplaceAll(content, "\r\n", "\n")
		if strings.Contains(orig, "\r\n") {
			content = strings.ReplaceAll(content, "\n", "\r\n")
		}
		if orig != "" && strings.HasSuffix(orig, "\n") && !strings.HasSuffix(content, "\n") {
			content += "\n"
			if strings.Contains(orig, "\r\n") {
				content = strings.TrimSuffix(content, "\n") + "\r\n"
			}
		}
		if content == orig {
			return nil, nil, fmt.Errorf("file %q is unchanged", name)
		}
		clean[rel], originals[rel] = content, orig
	}
	return clean, originals, nil
}

func isTestPath(rel string) bool {
	lower := strings.ToLower(rel)
	base := path.Base(lower)
	return strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, "_test.py") || strings.HasPrefix(base, "test_") ||
		strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
		strings.HasPrefix(lower, "tests/") || strings.Contains(lower, "/tests/") || strings.Contains(lower, "/__tests__/")
}

// Fix asks the model for a patch and verifies it in the sandbox, up to
// MaxAttempts times. Each rejected attempt is sent back with the reason. A
// patch that fails verification is never returned.
func Fix(ctx context.Context, r *Runner, parent int64, sealer *envelope.Sealer, reg *tools.Registry, box *Box, in FixInput, f finding.Finding) (FixResult, error) {
	res := FixResult{}
	attempts := in.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}
	brief := map[string]any{
		"title": f.Title, "class": f.Class, "location": f.Location.String(), "description": f.Flaw.Description,
		"flow": f.Flaw.Flow, "suggested_fix": f.Remediation.Summary,
	}
	raw, err := json.MarshalIndent(brief, "", " ")
	if err != nil {
		return res, err
	}
	system := fixerSystem(sealer)
	base := "Fix this finding.\n\n" + sealer.Wrap("finding to fix", string(raw))
	user := base

	for attempt := 1; attempt <= attempts; attempt++ {
		res.Attempts = attempt
		out, err := r.Run(ctx, parent, system, user, reg)
		if err != nil {
			return res, err
		}
		if out.Stopped == StopRefusal || out.Stopped == StopTruncated {
			res.Reason = "The model did not produce a patch (" + out.Stopped + ")."
			return res, nil
		}
		problem, files, patch, verification, verified, err := verifyFix(ctx, box, in, out.Text)
		if err != nil {
			return res, err
		}
		if problem == "" {
			var reply fixerReply
			_ = decodeReply(out.Text, &reply)
			res.Files, res.Patch, res.Why = files, patch, clip(strings.TrimSpace(reply.Why), 800)
			res.Verified, res.Verification, res.Reason = verified, verification, ""
			return res, nil
		}
		res.Reason = fmt.Sprintf("No patch passed verification in %d attempt(s). Last problem: %s", attempt, clip(problem, 400))
		user = "Your previous patch was rejected: " + clip(problem, 1500) +
			"\n\nWrite a different patch and reply again in the same JSON format.\n\n" + base
	}
	return res, nil
}

// verifyFix parses a fixer reply and checks it in the sandbox. A non-empty
// problem means the patch is rejected and why.
func verifyFix(ctx context.Context, box *Box, in FixInput, replyText string) (problem string, files map[string]string, patch, verification string, verified bool, err error) {
	var reply fixerReply
	if derr := decodeReply(replyText, &reply); derr != nil {
		return derr.Error(), nil, "", "", false, nil
	}
	files, originals, lerr := loadOriginals(box.Root, reply.Files)
	if lerr != nil {
		return lerr.Error(), nil, "", "", false, nil
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var diff strings.Builder
	for _, n := range names {
		diff.WriteString(diffx.Unified(n, originals[n], files[n]))
	}
	patch = diff.String()
	added, removed := diffx.Stat(patch)
	if added+removed > 400 {
		return fmt.Sprintf("the patch changes %d lines; a fix for one finding should be far smaller. Change only what removes the flaw", added+removed), nil, "", "", false, nil
	}

	var checked []string
	if cmd := compileCheck(in.Language, names); cmd != nil {
		run, rerr := box.run(ctx, "fix-compile", in.Image, cmd, files)
		if rerr != nil {
			return "", nil, "", "", false, rerr
		}
		if run.ExitCode != 0 || run.TimedOut {
			out, _ := redact.Apply(strings.TrimSpace(run.Stdout + "\n" + run.Stderr))
			return "the patched code does not compile or parse:\n" + clip(out, 1200), nil, "", "", false, nil
		}
		checked = append(checked, "the changed files compile")
	}

	proofClosed := false
	if in.PoC != nil {
		withPoC := map[string]string{}
		for k, v := range files {
			withPoC[k] = v
		}
		for k, v := range in.PoC.Files {
			withPoC[k] = v
		}
		run, rerr := box.run(ctx, "fix-verify", in.Image, in.PoC.Command, withPoC)
		if rerr != nil {
			return "", nil, "", "", false, rerr
		}
		if !run.TimedOut && strings.Contains(run.Stdout+run.Stderr, in.PoC.Marker) {
			return "the proof of concept still succeeds against the patched code, so the flaw is still there", nil, "", "", false, nil
		}
		proofClosed = true
		checked = append(checked, "the proof of concept no longer succeeds")
	}

	switch {
	case len(in.TestCmd) > 0 && in.BaselineTestsPass:
		run, rerr := box.run(ctx, "fix-tests", in.Image, in.TestCmd, files)
		if rerr != nil {
			return "", nil, "", "", false, rerr
		}
		if run.ExitCode != 0 || run.TimedOut {
			out, _ := redact.Apply(strings.TrimSpace(run.Stdout + "\n" + run.Stderr))
			return "the project's tests passed before the patch and fail after it:\n" + clip(out, 1500), nil, "", "", false, nil
		}
		checked = append(checked, "the test suite still passes")
	case len(in.TestCmd) > 0:
		checked = append(checked, "the test suite was not used because it does not pass on the unmodified code")
	default:
		checked = append(checked, "no test suite was found to run")
	}

	summary := strings.Join(checked, "; ")
	if proofClosed {
		return "", files, patch, "verified: " + summary, true, nil
	}
	return "", files, patch, "unverified: there was no proof of concept to re-run, so the patch is offered but not proven (" + summary + ")", false, nil
}
