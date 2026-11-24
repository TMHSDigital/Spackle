package engine

import (
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/TMHSDigital/spackle/internal/agent"
	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/version"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// This file holds the steps every mode (a code scan, a running-target scan,
// debug) takes in the same way: check the model, open the run, start the
// model stages. Each mode stays its own function and calls these in order.

// progressf writes one status line. A nil writer discards it. It is for the
// part of a mode that runs before a runner exists; after that, use r.say.
func progressf(w io.Writer, format string, a ...any) {
	if w != nil {
		fmt.Fprintf(w, format+"\n", a...)
	}
}

// clockOr returns clock, or the wall clock when a caller gave none.
func clockOr(clock func() time.Time) func() time.Time {
	if clock == nil {
		return time.Now
	}
	return clock
}

// preflightModel builds the provider of every stage, so a missing key or an
// offline violation is found before anything is written, and returns the
// provider of the stage the run is named after and estimated with.
func preflightModel(provs *providers, stage string) (llm.Provider, error) {
	if err := provs.checkAll(); err != nil {
		return nil, err
	}
	return provs.forStage(stage)
}

// runIDFor returns the id the caller asked for, or a new one.
func runIDFor(given, stateDir string, clock func() time.Time) (string, error) {
	if given != "" {
		return given, nil
	}
	return NewRunID(stateDir, clock())
}

// newRun creates the run directory with its ledger and returns the runner
// that owns them. It is the point where a run starts to exist: everything
// that can refuse a run comes before it. The caller defers r.done at once.
func newRun(opts Options, cfg config.Config, runID string, clock func() time.Time, provs *providers) (*runner, error) {
	runDir := filepath.Join(RunsDir(cfg.StateDir), runID)
	led, err := ledger.Create(runDir, clock)
	if err != nil {
		return nil, err
	}
	return &runner{opts: opts, cfg: cfg, led: led, runDir: runDir, runID: runID, progress: opts.Progress, clock: clock, provs: provs}, nil
}

// done is deferred by every mode as soon as its run exists, with a pointer
// to the function's error result: an error that ends the run is recorded in
// the ledger (see endOnError), and the ledger is closed.
func (r *runner) done(err *error) {
	r.endOnError(err)
	_ = r.led.Close()
}

// begin writes the run.start event. The caller fills in what its mode
// knows; the fields every mode sets the same way are set here.
func (r *runner) begin(start ledger.RunStart) (int64, error) {
	start.RunID, start.Version, start.Offline = r.runID, version.Version, r.cfg.Offline
	return r.led.Append(0, ledger.TypeRunStart, start)
}

// mapSummary is the map event of a run on source code.
func mapSummary(m mapper.Map) ledger.MapSummary {
	return ledger.MapSummary{
		Files: m.FileCount, Skipped: len(m.Skipped), Languages: m.LanguageNames(),
		Frameworks: m.Frameworks, EntryPoints: len(m.Entry), InfraFiles: len(m.InfraFiles),
		TestCommand: m.Tests.TestCommand,
	}
}

// startAgents creates what the model stages of one run share: the budget
// (its wall clock starts here), the envelope sealer and the pricer.
func (r *runner) startAgents() error {
	bud, err := budget.New(budget.Caps{
		Tokens: r.cfg.Budget.Tokens, USD: r.cfg.Budget.USD,
		Wall: r.cfg.Budget.WallTime.Duration, SandboxRuns: r.cfg.Budget.SandboxRuns,
	}, r.clock)
	if err != nil {
		return err
	}
	sealer, err := envelope.New()
	if err != nil {
		return err
	}
	r.budget, r.sealer = bud, sealer
	r.pricer = llm.NewPricer(llm.PricesFromConfig(r.cfg.Pricing))
	return nil
}

// runnerFor returns the agent runner of one stage. It needs startAgents.
func (r *runner) runnerFor(stage string) (*agent.Runner, error) {
	prov, err := r.provs.forStage(stage)
	if err != nil {
		return nil, err
	}
	return &agent.Runner{
		Provider: prov, Pricer: r.pricer, Budget: r.budget, Ledger: r.led, Stage: stage,
		MaxTurns: r.cfg.Budget.MaxTurns, MaxTokens: r.cfg.ForStage(stage).MaxOutputTokens,
	}, nil
}

// registries returns the maker of the file tool registries for a target.
// Every stage of every investigation gets a registry of its own, and they
// share one cache for the run: without it each would list the target and
// scan its files for secrets again. It needs startAgents.
func (r *runner) registries(root string, files []walk.File) func() *tools.Registry {
	cache := tools.NewCache(files)
	return func() *tools.Registry {
		return tools.NewRegistry(tools.Env{Root: root, Sealer: r.sealer, Walk: walkOptions(r.cfg), Cache: cache})
	}
}

// capState is the bookkeeping of a loop that can stop early on a cap: the
// run outcome, the cap that was reached, and what was left undone.
type capState struct {
	outcome string
	capNote string
	skipped []string
}

// exhaust records that a cap was reached and what it left undone.
func (c *capState) exhaust(capNote string, skipped ...string) {
	c.capNote = capNote
	c.skipped = append(c.skipped, skipped...)
	c.outcome = "budget-exhausted"
}
