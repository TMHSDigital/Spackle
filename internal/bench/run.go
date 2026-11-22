package bench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/version"
)

// minFixtureUSD is the smallest spend cap handed to one fixture. The engine
// reads a zero cap as "use the default", which would lift the limit exactly
// when the benchmark has almost none left.
const minFixtureUSD = 0.01

// Options configure a benchmark run.
type Options struct {
	CorpusDir string
	Config    config.Config
	Version   string
	Now       func() time.Time
	Progress  io.Writer
	// Scan runs one fixture; nil means engine.Run. Tests inject a fake.
	Scan func(ctx context.Context, o engine.Options) (engine.Result, error)
}

// Run scans every fixture in the corpus and scores the findings.
//
// A fixture whose scan fails is recorded with its Error and its truth entries
// count as false negatives. The run stops early, returning what was done with
// a Note, when the context is cancelled, when a scan is refused for a reason
// that would repeat for every fixture, or when the cumulative model spend
// reaches Config.Budget.USD. Callers can tell a stopped run from a complete
// one by comparing len(Fixtures) with Corpus.Fixtures.
func Run(ctx context.Context, opts Options) (Results, error) {
	corpus, err := LoadCorpus(opts.CorpusDir)
	if err != nil {
		return Results{}, err
	}
	if len(corpus) == 0 {
		return Results{}, fmt.Errorf("benchmark corpus %s has no fixtures: pass --corpus with the directory that holds them (bench/corpus in the Spackle repository)", opts.CorpusDir)
	}
	scan := opts.Scan
	if scan == nil {
		scan = engine.Run
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	// Benchmark scans must not mix with the operator's own runs or reuse a
	// stale map cache, so they get a state directory of their own.
	state, err := os.MkdirTemp("", "spackle-bench-")
	if err != nil {
		return Results{}, fmt.Errorf("create a temporary state directory for the benchmark: %w", err)
	}
	defer func() { _ = os.RemoveAll(state) }()

	agentic := opts.Config.Model.Configured()
	res := Results{
		Schema: Schema, Date: now().UTC().Format("2006-01-02"), Version: opts.Version,
		Mode: ModeDeterministic, Model: "none",
		Corpus: corpusInfo(corpus), Fixtures: []FixtureScore{},
	}
	if version.Commit != "" && version.Commit != "none" {
		res.Commit = version.Commit
	}
	if agentic {
		res.Mode, res.Provider, res.Model = ModeAgentic, opts.Config.Model.Provider, opts.Config.Model.Model
	}

	limit := opts.Config.Budget.USD
	var spent float64
	var spends []spend
	stop := func(done int, reason string) {
		res.Notes = append(res.Notes, fmt.Sprintf("Stopped after %d of %d fixtures: %s. The totals cover only the fixtures that were scanned.", done, len(corpus), reason))
	}
	unknownSpendNoted := false

	for i, t := range corpus {
		if ctx.Err() != nil {
			stop(i, "the run was cancelled")
			break
		}
		// Every fixture is a separate engine run with its own budget object,
		// so the benchmark-wide cap has to be enforced here.
		if limit > 0 && spent >= limit {
			stop(i, fmt.Sprintf("model spend reached the cap of $%.2f", limit))
			break
		}
		cfg := opts.Config
		cfg.StateDir = filepath.Join(state, t.Fixture)
		cfg.Output.Dir = ""
		if limit > 0 {
			cfg.Budget.USD = limit - spent
			if cfg.Budget.USD < minFixtureUSD {
				cfg.Budget.USD = minFixtureUSD
			}
		}

		out, err := scan(ctx, engine.Options{Target: filepath.Join(opts.CorpusDir, t.Fixture), Config: cfg})
		if err != nil {
			if ctx.Err() != nil {
				stop(i, "the run was cancelled")
				break
			}
			msg := scrub(err.Error(), state)
			// With a model configured, a refusal comes from the provider
			// setup or the budget, not from the fixture, and would repeat
			// identically for every remaining fixture.
			if errors.Is(err, budget.ErrExhausted) || (agentic && errors.Is(err, engine.ErrRefused)) {
				stop(i, "the scan of "+t.Fixture+" was refused ("+msg+")")
				break
			}
			fs := Score(t, nil)
			fs.Error = msg
			res.Fixtures = append(res.Fixtures, fs)
			// A failed agentic scan may have called the model before it
			// failed, and that spend is not reported back.
			spends = append(spends, spend{costKnown: !agentic})
			if agentic && !unknownSpendNoted {
				unknownSpendNoted = true
				res.Notes = append(res.Notes, "At least one fixture scan failed after a model was configured. Its model spend is not known, so the run's cost is reported as unknown.")
			}
			progress(opts.Progress, i+1, len(corpus), fs)
			continue
		}

		reported := make([]Reported, 0, len(out.Run.Findings))
		for _, f := range out.Run.Findings {
			reported = append(reported, FromFinding(f))
		}
		fs := Score(t, reported)
		u := out.Run.Usage
		res.Fixtures = append(res.Fixtures, fs)
		spends = append(spends, spend{costUSD: u.CostUSD, costKnown: u.CostKnown, inputTokens: u.InputTokens, outputTokens: u.OutputTokens, estimated: u.Estimated})
		spent += u.CostUSD
		progress(opts.Progress, i+1, len(corpus), fs)
	}

	res.Totals = total(res.Fixtures, spends)
	res.ByLanguage = split(res.Fixtures, spends, func(s FixtureScore) string { return s.Language })
	res.ByDifficulty = split(res.Fixtures, spends, func(s FixtureScore) string { return s.Difficulty })
	return res, nil
}

// scrub removes the temporary state directory from an error message. Results
// files are committed, and the path would leak the operator's user name.
func scrub(msg, state string) string {
	msg = strings.ReplaceAll(msg, state, "<state>")
	return strings.ReplaceAll(msg, filepath.ToSlash(state), "<state>")
}

func progress(w io.Writer, n, of int, fs FixtureScore) {
	if w == nil {
		return
	}
	if fs.Error != "" {
		fmt.Fprintf(w, "[%d/%d] %s: scan failed: %s\n", n, of, fs.Fixture, fs.Error)
		return
	}
	fmt.Fprintf(w, "[%d/%d] %s: %d true positive, %d false positive, %d missed\n", n, of, fs.Fixture, fs.TruePositives, fs.FalsePositives, fs.FalseNegatives)
}
