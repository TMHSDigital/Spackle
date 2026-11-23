package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/report"
)

// runRow is one stored run as "spackle runs" shows it.
type runRow struct {
	RunID    string `json:"run_id"`
	Started  string `json:"started,omitempty"` // RFC 3339, UTC
	Target   string `json:"target,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	Findings int    `json:"findings"`
	// Extra says what else the run left in the state directory: a clone of
	// a git URL target, a fix worktree.
	Extra []string `json:"extra"`
	Error string   `json:"error,omitempty"`

	started time.Time
}

func runRuns(env Env, args []string) int {
	if len(args) > 0 && args[0] == "prune" {
		return runRunsPrune(env, args[1:])
	}
	fs := newFlagSet(env, "runs", "[prune]", "List the runs stored in the state directory, newest first.\n\"spackle runs prune\" deletes old runs with their clones and fix worktrees: see \"spackle runs prune --help\".")
	var g globalFlags
	g.registerGroups(fs, flagsConfig)
	format := fs.String("format", "text", "output `format`: text or json")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 0 {
		fmt.Fprintf(env.Stderr, "spackle runs: unexpected argument %q. Use \"spackle runs\" to list or \"spackle runs prune\" to delete.\n", pos[0])
		return ExitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(env.Stderr, "spackle runs: unknown format %q: choose text or json\n", *format)
		return ExitUsage
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle runs: %v\n", err)
		return ExitUsage
	}
	rows, err := storedRuns(cfg.StateDir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle runs: %v\n", err)
		return ExitError
	}
	if *format == "json" {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			Runs []runRow `json:"runs"`
		}{rows}); err != nil {
			fmt.Fprintf(env.Stderr, "spackle runs: %v\n", err)
			return ExitError
		}
		return ExitOK
	}
	if len(rows) == 0 {
		fmt.Fprintf(env.Stdout, "No runs are stored in %s.\n", filepath.ToSlash(engine.RunsDir(cfg.StateDir)))
		return ExitOK
	}
	for _, r := range rows {
		printRunRow(env, r)
	}
	fmt.Fprintf(env.Stdout, "\n%d run(s) in %s.\n", len(rows), filepath.ToSlash(engine.RunsDir(cfg.StateDir)))
	return ExitOK
}

func printRunRow(env Env, r runRow) {
	if r.Error != "" {
		fmt.Fprintf(env.Stdout, "%s  unreadable: %s\n", r.RunID, r.Error)
		return
	}
	line := fmt.Sprintf("%s  %-16s %3d finding(s)  %s", r.RunID, r.Outcome, r.Findings, r.Target)
	if len(r.Extra) > 0 {
		line += "  [" + strings.Join(r.Extra, ", ") + "]"
	}
	fmt.Fprintln(env.Stdout, line)
}

// storedRuns lists the run directories of a state directory, newest first.
// Names come from reading the directory, never from an argument, so nothing
// outside the runs directory can be named.
func storedRuns(stateDir string) ([]runRow, error) {
	dir := engine.RunsDir(stateDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []runRow{}, nil
		}
		return nil, fmt.Errorf("the runs directory %s cannot be read: %w", dir, err)
	}
	rows := []runRow{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		row := runRow{RunID: e.Name(), Extra: []string{}}
		if info, ierr := e.Info(); ierr == nil {
			row.started = info.ModTime()
		}
		run, lerr := report.Load(filepath.Join(dir, e.Name()))
		if lerr != nil {
			row.Error = lerr.Error()
		} else {
			row.Target, row.Outcome, row.Findings = run.Target, run.Outcome, len(run.Findings)
			if !run.StartedAt.IsZero() {
				row.started = run.StartedAt
				row.Started = run.StartedAt.UTC().Format(time.RFC3339)
			}
		}
		for _, extra := range []string{"clones", "worktrees"} {
			if st, serr := os.Stat(filepath.Join(stateDir, extra, e.Name())); serr == nil && st.IsDir() {
				row.Extra = append(row.Extra, strings.TrimSuffix(extra, "s"))
			}
		}
		rows = append(rows, row)
	}
	// Run ids start with a UTC timestamp, so reverse name order is newest
	// first.
	sort.Slice(rows, func(i, j int) bool { return rows[i].RunID > rows[j].RunID })
	return rows, nil
}

// parseAge reads a duration that may also be given in days ("30d").
func parseAge(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%q is not a number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%q is not a duration: use for example 30d or 72h", s)
	}
	return d, nil
}

func runRunsPrune(env Env, args []string) int {
	fs := newFlagSet(env, "runs prune", "", "Delete stored runs, with the clone and the fix worktree each one left in the state directory.\nGive --keep, --older-than, or both: a run is deleted when either rule selects it.\nThe runs to delete are listed first. Nothing is deleted without --yes or a typed confirmation.")
	var g globalFlags
	g.registerGroups(fs, flagsConfig|flagsYes)
	keep := fs.Int("keep", -1, "keep the newest `n` runs and delete the rest")
	olderThan := fs.String("older-than", "", "delete runs started more than this `age` ago, for example 30d or 72h")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 0 {
		fmt.Fprintf(env.Stderr, "spackle runs prune: unexpected argument %q. Runs are selected with --keep and --older-than, not by name.\n", pos[0])
		return ExitUsage
	}
	if *keep < 0 && *olderThan == "" {
		fmt.Fprintln(env.Stderr, "spackle runs prune: say what to delete with --keep <n>, --older-than <age>, or both.")
		return ExitUsage
	}
	var age time.Duration
	if *olderThan != "" {
		if age, err = parseAge(*olderThan); err != nil {
			fmt.Fprintf(env.Stderr, "spackle runs prune: --older-than: %v\n", err)
			return ExitUsage
		}
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle runs prune: %v\n", err)
		return ExitUsage
	}
	rows, err := storedRuns(cfg.StateDir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle runs prune: %v\n", err)
		return ExitError
	}
	cutoff := time.Now().Add(-age)
	var doomed []runRow
	for i, r := range rows {
		beyondKeep := *keep >= 0 && i >= *keep
		tooOld := *olderThan != "" && !r.started.IsZero() && r.started.Before(cutoff)
		if beyondKeep || tooOld {
			doomed = append(doomed, r)
		}
	}
	if len(doomed) == 0 {
		fmt.Fprintf(env.Stdout, "Nothing to delete: %d run(s) are stored and none is selected.\n", len(rows))
		return ExitOK
	}
	fmt.Fprintf(env.Stdout, "These %d of %d run(s) will be deleted, with their clones and fix worktrees:\n", len(doomed), len(rows))
	for _, r := range doomed {
		printRunRow(env, r)
	}
	if !g.yes {
		if !isTerminal(env.Stdin) {
			fmt.Fprintln(env.Stderr, "spackle runs prune: nothing was deleted. There is no terminal to confirm on: pass --yes to delete the runs listed above.")
			return ExitUsage
		}
		fmt.Fprint(env.Stderr, "Delete them? [y/N] ")
		line, _ := bufio.NewReader(env.Stdin).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			fmt.Fprintln(env.Stderr, "Nothing was deleted.")
			return ExitOK
		}
	}
	failed := 0
	for _, r := range doomed {
		// r.RunID is a directory name read from the runs directory, so each
		// path below stays inside the state directory.
		for _, dir := range []string{
			filepath.Join(engine.RunsDir(cfg.StateDir), r.RunID),
			filepath.Join(cfg.StateDir, "clones", r.RunID),
			filepath.Join(cfg.StateDir, "worktrees", r.RunID),
		} {
			if rerr := os.RemoveAll(dir); rerr != nil {
				fmt.Fprintf(env.Stderr, "spackle runs prune: %s could not be removed: %v\n", filepath.ToSlash(dir), rerr)
				failed++
			}
		}
	}
	if failed > 0 {
		return ExitError
	}
	fmt.Fprintf(env.Stdout, "Deleted %d run(s). A fix branch (spackle/<run-id>) stays in your repository; \"git worktree prune\" there clears the record of a deleted worktree.\n", len(doomed))
	return ExitOK
}
