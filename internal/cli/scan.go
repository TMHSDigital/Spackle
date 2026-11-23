package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/report"
)

func runScan(env Env, args []string) int {
	fs := newFlagSet(env, "scan", "[path|url]", "Find, demonstrate, explain and fix flaws in a target.\nThe target is a directory, a git URL, or the URL of an application you run.\nWith no target, the current directory is scanned.")
	var g globalFlags
	g.register(fs)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 1 {
		fmt.Fprintf(env.Stderr, "spackle scan: expected one target, got %d (%q).\nScan one target per run. Quote a path that contains spaces.\n", len(pos), pos)
		return ExitUsage
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle scan: %v\n", err)
		return ExitUsage
	}
	tgt := "."
	if len(pos) == 1 {
		tgt = pos[0]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res, err := engine.Run(ctx, engine.Options{Target: tgt, Config: cfg, Progress: env.Stderr, Confirm: confirmer(env, g.yes),
		ScopeFile: g.authorize, Yes: g.yes, Interactive: isTerminal(env.Stdin), Stdin: env.Stdin,
	})
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle scan: %v\n", err)
		if errors.Is(err, engine.ErrRefused) {
			return ExitUsage
		}
		return ExitError
	}
	if err := emit(env, cfg, res.Run, res.RunDir); err != nil {
		fmt.Fprintf(env.Stderr, "spackle scan: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(env.Stderr, "Run %s stored in %s\n", res.RunID, res.RunDir)
	if res.Run.Outcome == "interrupted" {
		// The report holds what was found before the interrupt. The run
		// did not finish, so it is not a pass whatever it found.
		fmt.Fprintf(env.Stderr, "The run was interrupted. The report covers only what was investigated before that.\n")
		return ExitError
	}
	return exitFor(cfg, res.Run)
}

// confirmer returns the function that asks the operator to accept the cost
// estimate before a model is called. With --yes, or for a local model that
// costs nothing, it does not ask. Without a terminal it refuses: a pipe is
// not consent to spend money.
func confirmer(env Env, yes bool) func(engine.Estimate) bool {
	if yes {
		return nil
	}
	return func(est engine.Estimate) bool {
		if est.Local {
			return true
		}
		if !isTerminal(env.Stdin) {
			fmt.Fprintln(env.Stderr, "This run would call a paid model and there is no terminal to confirm on.")
			return false
		}
		fmt.Fprint(env.Stderr, "Proceed? [y/N] ")
		line, _ := bufio.NewReader(env.Stdin).ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "y" || answer == "yes"
	}
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// emit writes the requested report formats. The terminal format goes to
// stdout. Other formats go to --out when it is set, to stdout when exactly
// one format was requested, and otherwise stay in the run directory, where
// every format is always written.
func emit(env Env, cfg config.Config, run report.Run, runDir string) error {
	formats := cfg.Output.Formats
	for _, format := range formats {
		ext, _ := report.Ext(format)
		switch {
		case ext == "txt":
			if err := report.Terminal(run, env.Stdout, wantColor(env.Stdout)); err != nil {
				return err
			}
		case cfg.Output.Dir != "":
			if err := os.MkdirAll(cfg.Output.Dir, 0o750); err != nil {
				return fmt.Errorf("create output directory %s: %w", cfg.Output.Dir, err)
			}
			path := filepath.Join(cfg.Output.Dir, "report."+ext)
			f, err := os.Create(path) //nolint:gosec // the operator chose the output directory
			if err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			rerr := report.Render(format, run, f)
			if cerr := f.Close(); rerr == nil {
				rerr = cerr
			}
			if rerr != nil {
				return fmt.Errorf("write %s: %w", path, rerr)
			}
			fmt.Fprintf(env.Stderr, "Wrote %s\n", path)
		case len(formats) == 1:
			if err := report.Render(format, run, env.Stdout); err != nil {
				return err
			}
		default:
			fmt.Fprintf(env.Stderr, "Wrote %s\n", filepath.Join(runDir, "reports", "report."+ext))
		}
	}
	return nil
}

// exitFor returns ExitFindings when a finding that is still in the scanned
// code is at or above the configured threshold. That is an open finding, and
// also one with a patch available: the patch sits on a branch or in a patch
// file, and the code that was scanned is unchanged.
func exitFor(cfg config.Config, run report.Run) int {
	if cfg.Output.FailOn == "never" {
		return ExitOK
	}
	threshold := finding.LabelRank(cfg.Output.FailOn)
	for _, f := range run.Findings {
		unresolved := f.Status == finding.StatusOpen || f.Status == finding.StatusPatchAvailable
		if unresolved && finding.LabelRank(f.Severity.Label) >= threshold {
			return ExitFindings
		}
	}
	return ExitOK
}
