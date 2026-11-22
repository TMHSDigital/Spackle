package engine

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/target"
	"github.com/TMHSDigital/spackle/internal/version"
)

type runner struct {
	opts     Options
	cfg      config.Config
	led      *ledger.Writer
	runDir   string
	runID    string
	progress io.Writer
	clock    func() time.Time
	provs    *providers
	budget   *budget.Budget
	sealer   *envelope.Sealer
	lab      *lab
}

func (r *runner) say(format string, a ...any) {
	if r.progress != nil {
		fmt.Fprintf(r.progress, format+"\n", a...)
	}
}

// Run executes the pipeline.
func Run(ctx context.Context, opts Options) (Result, error) {
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	say := func(format string, a ...any) {
		if opts.Progress != nil {
			fmt.Fprintf(opts.Progress, format+"\n", a...)
		}
	}
	tgt, err := target.Classify(opts.Target)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if tgt.Live() {
		return Result{}, fmt.Errorf("%w: %s is a live target. Running-target analysis is not in this build yet; scan the application's source directory instead", ErrRefused, tgt.Display)
	}

	// Everything that can refuse the run is checked before a run directory
	// exists, so a refused run leaves nothing behind.
	agentic := opts.Config.Model.Configured()
	provs := newProviders(opts.Config, opts.ProviderFactory)
	var defaultProv llm.Provider
	if agentic {
		if err := provs.checkAll(); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		if defaultProv, err = provs.forStage("investigator"); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}

	runID := opts.RunID
	if runID == "" {
		if runID, err = NewRunID(clock()); err != nil {
			return Result{}, err
		}
	}
	stateDir := opts.Config.StateDir

	root := tgt.Raw
	if tgt.Kind == target.KindGit {
		root = filepath.Join(stateDir, "clones", runID)
		say("Cloning %s", tgt.Display)
		if err := gitx.Clone(ctx, tgt.Raw, root); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}

	// Map and seed before asking for confirmation, so the estimate reflects
	// the real number of leads. Neither stage uses a model or costs money.
	say("Mapping %s", tgt.Display)
	m, err := mapper.Build(ctx, root, mapper.Options{CacheDir: filepath.Join(stateDir, "cache")})
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	seeders := opts.Seeders
	if seeders == nil {
		seeders = seed.All()
	}
	say("Running %d seeders", len(seeders))
	leads, statuses := seed.RunAll(ctx, seeders, root, m.Files)

	if agentic {
		est := estimate(opts.Config, defaultProv, llm.NewPricer(llm.PricesFromConfig(opts.Config.Pricing)), len(leads))
		say("%s", est.String())
		if opts.Confirm != nil && !opts.Confirm(est) {
			return Result{}, fmt.Errorf("%w: the run was not confirmed. Pass --yes to skip this prompt, or lower --budget-usd", ErrRefused)
		}
	}

	runDir := filepath.Join(RunsDir(stateDir), runID)
	led, err := ledger.Create(runDir, clock)
	if err != nil {
		return Result{}, err
	}
	r := &runner{opts: opts, cfg: opts.Config, led: led, runDir: runDir, runID: runID, progress: opts.Progress, clock: clock, provs: provs}
	defer func() { _ = led.Close() }()
	if agentic {
		detect := opts.DetectRuntime
		if detect == nil {
			detect = sandbox.Detect
		}
		rt, derr := detect(ctx, r.cfg.Sandbox.Runtime)
		why := ""
		if derr != nil {
			rt, why = nil, firstSentence(derr.Error())
		}
		r.lab = r.newLab(root, m.Tests, rt, why)
	}

	commit := ""
	if gitx.HasTracked(ctx, root) {
		commit, _ = gitx.HeadSHA(ctx, root)
	}
	start := ledger.RunStart{
		RunID: runID, Version: version.Version, Command: "scan",
		Target: tgt.Display, TargetKind: string(tgt.Kind), Commit: commit,
		Mode: "deterministic", Offline: r.cfg.Offline,
		Isolation: "not used: no proof of concept was run",
	}
	if agentic {
		start.Mode, start.Provider, start.Model = "agentic", defaultProv.Name(), defaultProv.Model()
		start.Isolation = r.lab.isolation()
	}
	startSeq, err := led.Append(0, ledger.TypeRunStart, start)
	if err != nil {
		return Result{}, err
	}

	mapSeq, err := led.Append(startSeq, ledger.TypeMap, ledger.MapSummary{
		Files: m.FileCount, Skipped: len(m.Skipped), Languages: m.LanguageNames(),
		Frameworks: m.Frameworks, EntryPoints: len(m.Entry), InfraFiles: len(m.InfraFiles),
		TestCommand: m.Tests.TestCommand,
	})
	if err != nil {
		return Result{}, err
	}
	for _, s := range m.Skipped {
		if _, err := led.Append(mapSeq, ledger.TypeNote, fmt.Sprintf("Not read: %s (%s)", s.Rel, s.Reason)); err != nil {
			return Result{}, err
		}
	}
	for _, l := range m.Languages {
		if !mapper.ProofLanguages[l.Lang] && l.Files > 0 && isAppLanguage(l.Lang) {
			note := fmt.Sprintf("%s (%d files): findings and analysis only. Proofs are auto-run for Go, Python and TypeScript/JavaScript in this version.", l.Lang, l.Files)
			if _, err := led.Append(mapSeq, ledger.TypeNote, note); err != nil {
				return Result{}, err
			}
		}
	}
	for _, st := range statuses {
		if _, err := led.Append(mapSeq, ledger.TypeSeeder, ledger.SeederStatus(st)); err != nil {
			return Result{}, err
		}
	}
	leadSeq := map[string]int64{}
	for _, l := range leads {
		seq, err := led.Append(mapSeq, ledger.TypeLead, l)
		if err != nil {
			return Result{}, err
		}
		leadSeq[l.ID] = seq
	}

	var findings []finding.Finding
	var parent map[string]int64
	outcome := "completed"
	if agentic {
		findings, parent, outcome, err = r.agentic(ctx, root, m, leads, leadSeq, mapSeq)
		if err != nil {
			return Result{}, r.fail(err)
		}
	} else {
		findings, parent, err = r.deterministic(leads, leadSeq)
		if err != nil {
			return Result{}, err
		}
	}

	findings = finding.Rank(finding.Dedup(findings))
	if limit := r.cfg.Budget.MaxFindings; limit > 0 && len(findings) > limit {
		var dropped []string
		for _, f := range findings[limit:] {
			dropped = append(dropped, fmt.Sprintf("%s %s (%s)", f.ID, f.Title, f.Location))
		}
		findings = findings[:limit]
		if _, err := led.Append(mapSeq, ledger.TypeBudgetSkip, ledger.BudgetSkip{Cap: fmt.Sprintf("max findings (%d)", limit), Skipped: dropped}); err != nil {
			return Result{}, err
		}
	}
	for _, f := range findings {
		if err := f.Validate(); err != nil {
			// A finding that is invalid at this point is a Spackle bug, not
			// a target problem. Record it instead of reporting it.
			if _, aerr := led.Append(parent[f.ID], ledger.TypeReject, ledger.Reject{Stage: "engine", Intent: f.ID, Reason: err.Error()}); aerr != nil {
				return Result{}, aerr
			}
			continue
		}
		if _, err := led.Append(parent[f.ID], ledger.TypeFinding, f); err != nil {
			return Result{}, err
		}
	}

	if _, err := led.Append(startSeq, ledger.TypeRunEnd, ledger.RunEnd{Outcome: outcome}); err != nil {
		return Result{}, err
	}
	if err := led.Close(); err != nil {
		return Result{}, err
	}
	return finish(runDir, runID)
}

// firstSentence shortens an error to its first clause for a one-line note.
func firstSentence(s string) string {
	for _, sep := range []string{": ", ". "} {
		if i := strings.Index(s, sep); i > 0 && i < 160 {
			s = s[:i]
			break
		}
	}
	return clipText(s, 160)
}

// deterministic reports each lead as a plausible finding. It is the whole
// analysis when no model is configured.
func (r *runner) deterministic(leads []seed.Lead, leadSeq map[string]int64) ([]finding.Finding, map[string]int64, error) {
	var findings []finding.Finding
	parent := map[string]int64{}
	for _, l := range leads {
		f := FromLead(l, "No model is configured, so this lead was not investigated or demonstrated.")
		if err := f.Validate(); err != nil {
			if _, aerr := r.led.Append(leadSeq[l.ID], ledger.TypeReject, ledger.Reject{Stage: "seed", Intent: l.ID, Reason: err.Error()}); aerr != nil {
				return nil, nil, aerr
			}
			continue
		}
		if _, seen := parent[f.ID]; !seen {
			parent[f.ID] = leadSeq[l.ID]
		}
		findings = append(findings, f)
	}
	return findings, parent, nil
}
