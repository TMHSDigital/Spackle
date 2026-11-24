package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
)

// maxIssueFile is how much of an issue file is read. An issue is a
// description, not a log archive, and all of it is sent to a model.
const maxIssueFile = 64 << 10

func runDebug(env Env, args []string) int {
	fs := newFlagSet(env, "debug", "[path] --test <name> | --issue <file|text>", "Start from a failing test or an issue description: reproduce it in the sandbox, find the\nroot cause, write a fix and verify it. With --good, bisect git history for the commit that\nintroduced the failure. Nothing runs outside the sandbox and your working tree is not changed:\nthe fix is a patch file in the run folder, and a branch in a new worktree when the files are in git.\nA model and a container runtime are both required. With no path, the current directory is used.")
	var g globalFlags
	g.registerGroups(fs, flagsAll&^(flagsScope|flagsPR|flagsFailOn))
	test := fs.String("test", "", "`name` of the failing test to debug")
	issue := fs.String("issue", "", "issue description: a `file` to read, or the text itself")
	good := fs.String("good", "", "`revision` known to be good; enables bisect up to HEAD")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 1 {
		fmt.Fprintf(env.Stderr, "spackle debug: expected one path, got %d (%q).\nDebug one project per run. Quote a path, a test name or issue text that contains spaces.\n", len(pos), pos)
		return ExitUsage
	}
	switch {
	case *test == "" && *issue == "":
		fmt.Fprint(env.Stderr, "spackle debug: nothing to debug was given.\nPass --test <name> for a failing test, or --issue <file|text> for a problem description.\n")
		return ExitUsage
	case *test != "" && *issue != "":
		fmt.Fprint(env.Stderr, "spackle debug: --test and --issue were both given.\nPass one of them: a run follows a single failure.\n")
		return ExitUsage
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle debug: %v\n", err)
		return ExitUsage
	}
	tgt := "."
	if len(pos) == 1 {
		tgt = pos[0]
	}
	issueText := ""
	if *issue != "" {
		if issueText, err = readIssue(env, *issue); err != nil {
			fmt.Fprintf(env.Stderr, "spackle debug: %v\n", err)
			return ExitUsage
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res, err := engine.Debug(ctx, engine.DebugOptions{
		Target: tgt, Test: *test, Issue: issueText, Good: *good,
		Config: cfg, Progress: env.Stderr, Confirm: confirmer(env, g.yes),
	})
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle debug: %v\n", err)
		if errors.Is(err, engine.ErrRefused) {
			return ExitUsage
		}
		return ExitError
	}
	if err := emit(env, cfg, res.Run, res.RunDir); err != nil {
		fmt.Fprintf(env.Stderr, "spackle debug: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(env.Stderr, "Run %s stored in %s\n", res.RunID, res.RunDir)

	// The exit code says whether the failure is dealt with, not how severe
	// it is: a functional bug has no severity for --fail-on to compare.
	for _, f := range res.Run.Findings {
		if f.Status == finding.StatusOpen {
			return ExitFindings
		}
	}
	if res.Run.Outcome != ledger.OutcomeCompleted {
		fmt.Fprintf(env.Stderr, "The run ended early (%s) before the failure was reproduced. Raise the budget and run again.\n", res.Run.Outcome)
		return ExitFindings
	}
	return ExitOK
}

// readIssue returns the issue text for --issue: the content of the file
// when the argument names one, otherwise the argument itself.
func readIssue(env Env, arg string) (string, error) {
	st, err := os.Stat(arg)
	if err != nil || !st.Mode().IsRegular() {
		return arg, nil
	}
	f, err := os.Open(arg) //nolint:gosec // the operator named this file on the command line
	if err != nil {
		return "", fmt.Errorf("the issue file %s cannot be read: %w. Check its permissions, or pass the issue text itself", arg, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxIssueFile+1))
	if err != nil {
		return "", fmt.Errorf("the issue file %s cannot be read: %w. Check the file, or pass the issue text itself", arg, err)
	}
	if len(b) > maxIssueFile {
		b = b[:maxIssueFile]
		fmt.Fprintf(env.Stderr, "The issue file %s is larger than %d KiB; only the first %d KiB are used.\n", arg, maxIssueFile>>10, maxIssueFile>>10)
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", fmt.Errorf("the issue file %s is empty. Put the problem description in it, or pass the text itself", arg)
	}
	return string(b), nil
}
