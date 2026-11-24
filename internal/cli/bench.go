package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/bench"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/version"
)

const (
	defaultBenchCorpus  = "bench/corpus"
	defaultBenchResults = "bench/results"
)

// runBench is the maintainer command behind "make bench". It is dispatched
// from Main but deliberately absent from commands(), so it does not appear in
// the user-facing help.
func runBench(env Env, args []string) int {
	fs := newFlagSet(env, "bench", "", "Run Spackle over the labelled benchmark corpus and score the findings against ground truth.\nWith no model configured only the deterministic stages run, which costs nothing.\nResults files are produced only by this command and are never edited by hand.")
	var g globalFlags
	g.register(fs)
	// The shared --out flag means "report directory" for the other commands.
	// Here it is the results directory, with its own default and help text.
	if f := fs.Lookup("out"); f != nil {
		f.Usage = "`directory` to write the results file into"
		f.DefValue = defaultBenchResults
	}
	corpus := fs.String("corpus", defaultBenchCorpus, "`directory` that holds the benchmark fixtures")
	force := fs.Bool("force", false, "overwrite an existing results file for the same date and model, and write a file even when some fixture scans failed")
	table := fs.Bool("table", false, "print the README table for all results in --out and exit without running")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 0 {
		fmt.Fprintf(env.Stderr, "spackle bench: unexpected argument %q.\nThe corpus is chosen with --corpus, not a positional argument.\n", pos[0])
		return ExitUsage
	}
	outDir := g.out
	if outDir == "" {
		outDir = defaultBenchResults
	}

	if *table {
		return benchTable(env, outDir)
	}

	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle bench: %v\n", err)
		return ExitUsage
	}
	truths, err := bench.LoadCorpus(*corpus)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle bench: %v\n", err)
		return ExitUsage
	}
	if len(truths) == 0 {
		fmt.Fprintf(env.Stderr, "spackle bench: corpus %s has no fixtures.\nPass --corpus with the directory that holds them (bench/corpus in the Spackle repository).\n", *corpus)
		return ExitUsage
	}

	// Refuse before scanning, not after: discovering the name clash at the
	// end would throw away a run that may have cost money.
	mode, model := bench.ModeDeterministic, "none"
	if cfg.Model.Configured() {
		mode, model = bench.ModeAgentic, cfg.Model.Model
	}
	planned := bench.Results{Date: time.Now().UTC().Format("2006-01-02"), Mode: mode, Model: model}
	if target := filepath.Join(outDir, bench.FileName(planned)); !*force {
		if _, err := os.Stat(target); err == nil {
			fmt.Fprintf(env.Stderr, "spackle bench: results file %s already exists.\nA results file is never overwritten silently. Pass --force to replace it with this run.\n", target)
			return ExitUsage
		}
	}

	paid, err := benchIsPaid(cfg)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle bench: %v\n", err)
		return ExitUsage
	}
	if paid && !benchConfirm(env, cfg, len(truths), g.yes) {
		fmt.Fprintln(env.Stderr, "spackle bench: the run was not confirmed, so nothing was scanned and no model was called.\nPass --yes to skip this prompt, or lower --budget-usd.")
		return ExitUsage
	}
	if paid && !g.yes {
		// The operator read the notice about unpriced models on a terminal
		// and answered yes, which is the opt-in an unattended run needs.
		cfg.Budget.AllowUnpriced = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res, err := bench.Run(ctx, bench.Options{CorpusDir: *corpus, Config: cfg, Version: version.Version, Progress: env.Stderr})
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle bench: %v\n", err)
		return ExitError
	}
	fmt.Fprint(env.Stdout, bench.Summary(res))
	for _, n := range res.Notes {
		fmt.Fprintf(env.Stderr, "Note: %s\n", n)
	}
	failed := 0
	for _, f := range res.Fixtures {
		if f.Error != "" {
			failed++
		}
	}
	if failed > 0 {
		fmt.Fprintf(env.Stderr, "Note: %d fixture scan(s) failed. Their planted flaws count as missed; see the progress lines above.\n", failed)
	}

	// The README table has no column for "this run stopped early", so a
	// partial run is never written where it could be quoted as a result.
	if len(res.Fixtures) < res.Corpus.Fixtures {
		fmt.Fprintf(env.Stderr, "spackle bench: the run stopped after %d of %d fixtures, so no results file was written.\nThe figures above cover only part of the corpus and must not be quoted. Fix the cause in the note above and run again.\n", len(res.Fixtures), res.Corpus.Fixtures)
		return ExitError
	}
	if n := res.Totals.FailedFixtures; n > 0 && !*force {
		fmt.Fprintf(env.Stderr, "spackle bench: the scan of %d fixture(s) failed, so no results file was written.\nThe figures above leave those fixtures out and do not describe the whole corpus. Fix the cause and run again, or pass --force to write the file anyway; it records the failures.\n", n)
		return ExitError
	}
	path, err := bench.Write(outDir, res, *force)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle bench: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(env.Stdout, "Results file:      %s\n", filepath.ToSlash(path))
	return ExitOK
}

// benchTable prints the README table for the committed results.
func benchTable(env Env, outDir string) int {
	rs, err := bench.LoadResults(outDir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle bench: %v\n", err)
		return ExitError
	}
	if len(rs) == 0 {
		fmt.Fprintf(env.Stdout, "There are no committed results yet in %s. Run \"make bench\" to produce one.\n", filepath.ToSlash(outDir))
		return ExitOK
	}
	fmt.Fprint(env.Stdout, bench.Table(rs))
	return ExitOK
}

// benchIsPaid reports whether any configured stage would call a model that
// is not on this machine. It also surfaces a missing API key before the
// first fixture is scanned.
func benchIsPaid(cfg config.Config) (bool, error) {
	if !cfg.Model.Configured() {
		return false, nil
	}
	models := []config.Model{cfg.Model}
	for _, stage := range config.Stages {
		models = append(models, cfg.ForStage(stage))
	}
	for _, m := range models {
		prov, err := llm.New(m, llm.Options{Offline: cfg.Offline})
		if err != nil {
			return false, err
		}
		if !prov.Local() {
			return true, nil
		}
	}
	return false, nil
}

// benchConfirm states what a paid run will do and asks for consent. Like
// scan, it refuses without a terminal: a pipe is not consent to spend money.
func benchConfirm(env Env, cfg config.Config, fixtures int, yes bool) bool {
	fmt.Fprintf(env.Stderr, "This benchmark will run %d fixture scan(s) with %s model %s.\n", fixtures, cfg.Model.Provider, cfg.Model.Model)
	fmt.Fprintf(env.Stderr, "Spend cap for the whole benchmark: $%.2f. The run stops when the cap is reached.\n", cfg.Budget.USD)
	fmt.Fprintf(env.Stderr, "If Spackle does not know the model's price the dollar cap cannot be enforced; then only the token cap of %d applies, to each fixture separately. Add [pricing] to spackle.toml to avoid that. With --yes and a dollar cap you set, such a model is refused unless you pass --allow-unpriced.\n", cfg.Budget.Tokens)
	if yes {
		return true
	}
	if !isTerminal(env.Stdin) {
		fmt.Fprintln(env.Stderr, "This run would call a paid model and there is no terminal to confirm on.")
		return false
	}
	fmt.Fprint(env.Stderr, "Proceed? [y/N] ")
	// A read error leaves the line empty, which is a "no".
	line, _ := bufio.NewReader(env.Stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
