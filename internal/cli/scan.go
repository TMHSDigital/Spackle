package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/report"
	"github.com/TMHSDigital/spackle/internal/seed"
)

func runScan(env Env, args []string) int {
	fs := newFlagSet(env, "scan", "[path|url]", "Find, demonstrate, explain and fix flaws in a target.\nThe target is a directory, a git URL, or the URL of an application you run.\nWith no target, the current directory is scanned.")
	var g globalFlags
	g.register(fs)
	dryRun := fs.Bool("dry-run", false, "show what would be scanned and the cost estimate; call no model and store no run")
	ref := fs.String("ref", "", "`branch or tag` to scan, for a git URL target (default: the remote's default branch)")
	since := fs.String("since", "", "report only on files changed since this `revision`, for a directory in a git repository (for example the base commit of a pull request)")
	resume := fs.String("resume", "", "continue the stored scan with this `run id` (or \"latest\") where its budget ran out or it was interrupted, with a new budget")
	changedOnly := fs.Bool("changed", false, "report only on files that differ from the last commit, staged or not, and new files git does not ignore: a scan before you commit")
	diffScope := fs.String("diff-scope", "", "with --since or --changed: `file` reports every lead in a changed file (the default), lines only the leads on changed lines")
	force := fs.Bool("force", false, "with --resume, continue although the target's commit changed since that run")
	routesFrom := fs.String("routes-from", "", "for a running target: `directory` with the application's source; the HTTP routes found in it are added to the crawl")
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
	if unknown := seed.UnknownBuiltinRules(cfg.Scan.DisableRules); len(unknown) > 0 {
		fmt.Fprintf(env.Stderr, "Warning: [scan] disable_rules names %s, which is no built-in rule, so it disables nothing. `spackle rules` lists the built-in ids.\n", strings.Join(unknown, ", "))
	}
	tgt := "."
	if len(pos) == 1 {
		tgt = pos[0]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res, err := runEngine(ctx, engine.Options{Target: tgt, Config: cfg, Progress: env.Stderr, Confirm: confirmer(env, g.yes),
		ScopeFile: g.authorize, Yes: g.yes, Interactive: isTerminal(env.Stdin), Stdin: env.Stdin, Ref: *ref, Since: *since, Changed: *changedOnly, DiffScope: *diffScope, Resume: *resume, Force: *force, DryRun: *dryRun, RoutesFrom: *routesFrom,
	})
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle scan: %v\n", err)
		if errors.Is(err, engine.ErrRefused) {
			return ExitUsage
		}
		return ExitError
	}
	if res.Plan != nil {
		if err := printPlan(env, cfg, *res.Plan); err != nil {
			fmt.Fprintf(env.Stderr, "spackle scan: %v\n", err)
			return ExitError
		}
		return ExitOK
	}
	if err := emit(env, cfg, res.Run, res.RunDir); err != nil {
		fmt.Fprintf(env.Stderr, "spackle scan: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(env.Stderr, "Run %s stored in %s\n", res.RunID, res.RunDir)
	if engine.Resumable(res.Run) {
		fmt.Fprintf(env.Stderr, "The budget ran out before every planned investigation was done. To continue with the rest under a new budget:\n  spackle scan %s %s\n", tgt, engine.ResumeFlags(res.Run))
	}
	if res.Run.Outcome == ledger.OutcomeInterrupted {
		// The report holds what was found before the interrupt. The run
		// did not finish, so it is not a pass whatever it found.
		fmt.Fprintf(env.Stderr, "The run was interrupted. The report covers only what was investigated before that.\n")
		return ExitError
	}
	return exitFor(cfg, res.Run)
}

// runEngine is engine.Run. Tests replace it to reach the exit codes of
// runs that are hard to produce for real: an interrupt or an engine error.
var runEngine = engine.Run

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

// isTerminal reports whether r is a terminal somebody can answer a prompt
// on. The null device is a character device too and is not one. It is a
// variable only so tests can stand in for a terminal.
var isTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0 && !isNullDevice(f, st)
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
	minConfidence := finding.ConfidenceRank(cfg.Output.FailOnConfidence)
	for _, f := range run.Findings {
		unresolved := f.Status == finding.StatusOpen || f.Status == finding.StatusPatchAvailable
		confident := finding.ConfidenceRank(f.Confidence.Level) >= minConfidence
		if unresolved && confident && finding.LabelRank(f.Severity.Label) >= threshold {
			return ExitFindings
		}
	}
	return ExitOK
}

// printPlan writes a dry run's plan: as JSON when json is the one requested
// format, as text otherwise.
func printPlan(env Env, cfg config.Config, p engine.Plan) error {
	if len(cfg.Output.Formats) == 1 && cfg.Output.Formats[0] == "json" {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	}
	w := env.Stdout
	fmt.Fprintf(w, "Dry run of %s (%s target, %s mode). Nothing was sent to a model and no run was stored.\n\n", p.Target, p.TargetKind, p.Mode)
	langs := "none recognized"
	if len(p.Languages) > 0 {
		langs = strings.Join(p.Languages, ", ")
	}
	fmt.Fprintf(w, "Files to read: %d (%s)\n", p.Files, langs)
	if len(p.NotRead) > 0 {
		fmt.Fprintf(w, "Not read: %d\n", len(p.NotRead))
		for _, n := range p.NotRead {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
	fmt.Fprintln(w, "\nSeeders:")
	for _, s := range p.Seeders {
		state := fmt.Sprintf("%d leads", s.Leads)
		switch {
		case !s.Available:
			state = "not available"
		case s.Error != "":
			state += ", failed: " + s.Error
		}
		line := fmt.Sprintf("  %-16s %s", s.Name, state)
		if s.Note != "" {
			line += " (" + s.Note + ")"
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "\nLeads: %d\n", p.Leads)
	for _, group := range []struct {
		label  string
		counts map[string]int
	}{{"By class", p.LeadsByClass}, {"By severity hint", p.LeadsBySeverity}} {
		keys := make([]string, 0, len(group.counts))
		for k := range group.counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, group.counts[k]))
		}
		if len(parts) > 0 {
			fmt.Fprintf(w, "  %s: %s\n", group.label, strings.Join(parts, ", "))
		}
	}
	if p.Mode == "agentic" {
		fmt.Fprintf(w, "\nInvestigations planned: up to %d\n", p.Investigations)
	}
	fmt.Fprintf(w, "\n%s\n", p.Estimate)
	for _, n := range p.Notes {
		fmt.Fprintf(w, "Note: %s\n", n)
	}
	return nil
}
