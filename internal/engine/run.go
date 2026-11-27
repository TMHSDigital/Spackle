package engine

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/gitx"
	proglang "github.com/TMHSDigital/spackle/internal/lang"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/target"
	"github.com/TMHSDigital/spackle/internal/textx"
	"github.com/TMHSDigital/spackle/internal/walk"
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
	pricer   llm.Pricer
	lab      *lab
	// changed is the file set of a diff scan (--since); nil for a full scan.
	changed map[string]bool
	// resume is the earlier run a resumed scan continues; nil otherwise.
	resume *resumeState
	// ended is set once the ledger has its run.end event.
	ended bool
	// recorded holds the ids of findings persist appended to the ledger
	// before recordFindings runs. An event cannot be taken back, so the
	// max-findings cap keeps them. Only persist writes it.
	recorded map[string]bool
}

func (r *runner) say(format string, a ...any) {
	if r.progress != nil {
		fmt.Fprintf(r.progress, format+"\n", a...)
	}
}

// Run executes the pipeline.
func Run(ctx context.Context, opts Options) (_ Result, err error) {
	clock := clockOr(opts.Clock)
	say := func(format string, a ...any) { progressf(opts.Progress, format, a...) }
	tgt, err := target.Classify(opts.Target)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if tgt.Live() {
		if opts.DryRun {
			return Result{}, fmt.Errorf("%w: --dry-run is for a directory or a git URL. For a running target, the scope file states what a scan may send", ErrRefused)
		}
		if diffBase(opts) != nil {
			return Result{}, fmt.Errorf("%w: --since and --changed limit a scan of a directory to its changed files, and %s is a running target", ErrRefused, tgt.Display)
		}
		if opts.Resume != "" {
			return Result{}, fmt.Errorf("%w: --resume continues a scan of a directory, and %s is a running target", ErrRefused, tgt.Display)
		}
		return runLive(ctx, opts, tgt, clock)
	}
	if opts.RoutesFrom != "" {
		return Result{}, fmt.Errorf("%w: --routes-from adds the routes found in source code to the crawl of a running application, and %s is not one. Give the URL of the running application as the target", ErrRefused, tgt.Display)
	}

	// Everything that can refuse the run is checked before a run directory
	// exists, so a refused run has no run directory and no ledger. The
	// clone of a git URL target is removed again; the map cache can stay.
	agentic := opts.Config.Model.Configured()
	provs := newProviders(opts.Config, opts.ProviderFactory)
	var defaultProv llm.Provider
	if agentic {
		if defaultProv, err = preflightModel(provs, config.StageInvestigator); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}

	runID, err := runIDFor(opts.RunID, opts.Config.StateDir, clock)
	if err != nil {
		return Result{}, err
	}
	stateDir := opts.Config.StateDir

	root := tgt.Raw
	runCreated := false
	if tgt.Kind == target.KindGit && opts.Config.Offline {
		return Result{}, fmt.Errorf("%w: %w: cloning %s would leave this machine. Clone it yourself and scan the directory, or drop --offline", ErrRefused, llm.ErrOffline, tgt.Display)
	}
	if opts.Ref != "" && tgt.Kind != target.KindGit {
		return Result{}, fmt.Errorf("%w: --ref names a branch or tag of a git URL target, and %s is not one. For a directory, check out the branch yourself", ErrRefused, tgt.Display)
	}
	if opts.Resume != "" {
		switch {
		case tgt.Kind != target.KindPath:
			return Result{}, fmt.Errorf("%w: --resume continues a scan of a directory, and %s is not one", ErrRefused, tgt.Display)
		case opts.DryRun:
			return Result{}, fmt.Errorf("%w: --resume and --dry-run cannot be combined: a dry run plans nothing to continue", ErrRefused)
		case !agentic:
			return Result{}, fmt.Errorf("%w: --resume continues the investigations of an earlier run, which needs a model. Set [model] in spackle.toml, or pass --provider and --model", ErrRefused)
		}
	}
	if opts.Since != "" && opts.Changed {
		return Result{}, fmt.Errorf("%w: --since and --changed choose different file sets; give one", ErrRefused)
	}
	if d := diffBase(opts); d != nil && tgt.Kind != target.KindPath {
		return Result{}, fmt.Errorf("%w: %s", ErrRefused, d.notLocal(tgt.Display))
	}
	if tgt.Kind == target.KindGit {
		root = filepath.Join(stateDir, "clones", runID)
		if opts.Ref != "" {
			say("Cloning %s at %s", tgt.Display, opts.Ref)
		} else {
			say("Cloning %s", tgt.Display)
		}
		if err := gitx.CloneRef(ctx, tgt.Raw, root, opts.Ref); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		// The clone belongs to the run. When no run comes of it (it is
		// refused, not confirmed, or a dry run), nothing would ever list
		// or remove the clone, so it is removed here.
		clone := root
		defer func() {
			if !runCreated {
				_ = os.RemoveAll(clone)
			}
		}()
	}
	// Every later stage needs an absolute root: the tool registry refuses a
	// relative one, because a relative path would silently mean "wherever
	// the process happens to be".
	if abs, aerr := filepath.Abs(root); aerr == nil {
		root = abs
	}

	var resume *resumeState
	if opts.Resume != "" {
		if resume, err = loadResume(ctx, stateDir, opts.Resume, root, opts.Force); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		// A resumed run covers the files the earlier run covered. Without
		// a diff flag it takes the earlier run's; a different one would
		// mix two file sets in one report.
		switch {
		case diffBase(opts) == nil:
			opts.Since, opts.Changed = resume.since, resume.changed
		case opts.Since != resume.since || opts.Changed != resume.changed:
			return Result{}, fmt.Errorf("%w: --resume: run %s was %s, and this scan asks for %s. Resume it without --since or --changed to keep its file set",
				ErrRefused, resume.runID, describeDiffBase(resume.since, resume.changed), describeDiffBase(opts.Since, opts.Changed))
		}
		// The same holds for the scope inside the changed files.
		switch {
		case opts.DiffScope == "":
			opts.DiffScope = resume.diffScope
		case (resume.since != "" || resume.changed) && linesScope(opts.DiffScope) != linesScope(resume.diffScope):
			return Result{}, fmt.Errorf("%w: --resume: run %s reported %s, and this scan asks for --diff-scope %s. Resume it without --diff-scope to keep its scope",
				ErrRefused, resume.runID, describeDiffScope(resume.diffScope), opts.DiffScope)
		}
	}
	if err := checkDiffScope(opts); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}

	// A diff scan needs its file list before anything else is done, so a
	// revision git does not know refuses the run at once.
	var changed map[string]bool
	var keep func(seed.Lead) bool
	if diffBase(opts) != nil {
		if changed, err = changedSince(ctx, root, diffBase(opts), stateDir); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		if linesScope(opts.DiffScope) {
			lines, lerr := changedLines(ctx, root, diffBase(opts), stateDir)
			if lerr != nil {
				return Result{}, fmt.Errorf("%w: %w", ErrRefused, lerr)
			}
			keep = onChangedLines(lines)
		}
	}

	// Map and seed before asking for confirmation, so the estimate reflects
	// the real number of leads. Neither stage uses a model or costs money.
	say("Mapping %s", tgt.Display)
	// The mapper hands the text of each file it reads to the seeders, so a
	// file is read once per scan.
	texts := walk.NewTexts()
	mapOpts := mapper.Options{CacheDir: filepath.Join(stateDir, "cache"), Walk: walkOptions(opts.Config), Texts: texts}
	if d := diffBase(opts); d != nil && d.changed {
		// The files of a --changed scan are exactly where the work tree
		// differs from HEAD, so the cached map of HEAD covers the rest.
		mapOpts.Changed = changed
	}
	m, err := mapper.Build(ctx, root, mapOpts)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	seeders := opts.Seeders
	if seeders == nil {
		seeders = seed.All()
	}
	seeders = configuredSeeders(seeders, opts.Config.Scan.Scanners)
	if opts.Config.Offline {
		seeders = offlineSeeders(seeders)
	}
	say("Running %d seeders", len(seeders))
	// A diff scan seeds only the changed files, so leads elsewhere neither
	// cost a read nor count against a seeder's lead cap.
	leads, statuses, leftOut, outside := seed.RunAllScoped(ctx, seeders, root, m.Files, texts, changed, keep)
	leads, scanNotes := applyScanConfig(leads, opts.Config.Scan)
	if changed != nil {
		scanNotes = append(scanNotes, diffNote(diffBase(opts).label, len(changed), leftOut))
		if keep != nil {
			scanNotes = append(scanNotes, diffLinesNote(outside))
		}
	}
	statuses = countLeads(statuses, leads)
	if resume != nil {
		scanNotes = append(scanNotes, fmt.Sprintf("Resumed from run %s: the %d investigations it planned and did not reach are continued with a new budget, and its findings are carried into this report.", resume.runID, len(resume.intents)))
	}
	if note := testConfigNote("command", opts.Config.Test.Command); agentic && note != "" {
		scanNotes = append(scanNotes, note)
	}

	if opts.DryRun {
		plan := &Plan{
			Target: tgt.Display, TargetKind: string(tgt.Kind), Mode: "deterministic",
			Files: m.FileCount, Languages: m.LanguageNames(), NotRead: []string{}, Seeders: statuses,
			Leads: len(leads), LeadsByClass: map[string]int{}, LeadsBySeverity: map[string]int{},
			Estimate: "No model is configured: the scan runs the deterministic stages only and costs nothing.",
			Notes:    append([]string{}, scanNotes...),
		}
		if plan.Languages == nil {
			plan.Languages = []string{}
		}
		for _, s := range m.Skipped {
			plan.NotRead = append(plan.NotRead, fmt.Sprintf("%s (%s)", s.Rel, s.Reason))
		}
		for _, l := range leads {
			plan.LeadsByClass[l.Class]++
			plan.LeadsBySeverity[l.Severity]++
		}
		if agentic {
			est := estimate(opts.Config, defaultProv, llm.NewPricer(llm.PricesFromConfig(opts.Config.Pricing)), len(leads))
			plan.Mode, plan.Model = "agentic", est.Model
			plan.Investigations, plan.Estimate = est.Investigations, est.String()
			// With nobody to confirm the estimate, the real run is
			// refused when its dollar cap cannot hold. A dry run is how
			// a CI setup is checked, so it says so here.
			if opts.Confirm == nil {
				if why := unpricedRefusal(opts.Config, opts.Config.ForStage(config.StageInvestigator), est); why != "" {
					plan.Notes = append(plan.Notes, "A real run with these settings would be refused: "+why)
				}
			}
		}
		if tgt.Kind == target.KindGit {
			plan.Notes = append(plan.Notes, "The repository was cloned to map it, and the clone was removed again.")
		}
		return Result{Plan: plan}, nil
	}

	if agentic {
		est := estimate(opts.Config, defaultProv, llm.NewPricer(llm.PricesFromConfig(opts.Config.Pricing)), len(leads))
		say("%s", est.String())
		if err := confirmEstimate(opts.Config, opts.Config.ForStage(config.StageInvestigator), est, opts.Confirm); err != nil {
			return Result{}, err
		}
	}

	r, err := newRun(opts, opts.Config, runID, clock, provs)
	if err != nil {
		return Result{}, err
	}
	runCreated = true
	defer r.done(&err)
	r.changed, r.resume = changed, resume
	led := r.led
	if agentic {
		rt, derr := detectRuntime(ctx, opts.DetectRuntime, r.cfg.Sandbox.Runtime)
		why := ""
		if derr != nil {
			rt, why = nil, firstSentence(derr.Error())
		}
		r.lab = r.newLab(root, m.Tests, rt, why)
	}

	commit, repoPrefix := "", ""
	if gitx.HasTracked(ctx, root) {
		commit, _ = gitx.HeadSHA(ctx, root)
		repoPrefix, _ = gitx.Prefix(ctx, root)
	}
	start := ledger.RunStart{
		Command: "scan",
		Target:  tgt.Display, TargetKind: string(tgt.Kind), Commit: commit, Ref: opts.Ref, RepoPrefix: repoPrefix,
		Mode:      "deterministic",
		Isolation: "not used: no proof of concept was run",
	}
	if tgt.Kind == target.KindPath {
		start.TargetPath = root
	}
	if resume != nil {
		start.ResumedFrom = resume.runID
	}
	start.Since, start.Changed = opts.Since, opts.Changed
	if linesScope(opts.DiffScope) {
		start.DiffScope = DiffScopeLines
	}
	if agentic {
		start.Mode, start.Provider, start.Model = "agentic", defaultProv.Name(), defaultProv.Model()
		start.Isolation = r.lab.isolation()
	}
	startSeq, err := r.begin(start)
	if err != nil {
		return Result{}, err
	}

	mapSeq, err := led.Append(startSeq, ledger.TypeMap, mapSummary(m))
	if err != nil {
		return Result{}, err
	}
	for _, s := range m.Skipped {
		if _, err := led.Append(mapSeq, ledger.TypeNote, fmt.Sprintf("Not read: %s (%s)", s.Rel, s.Reason)); err != nil {
			return Result{}, err
		}
	}
	for _, note := range scanNotes {
		if _, err := led.Append(mapSeq, ledger.TypeNote, note); err != nil {
			return Result{}, err
		}
	}
	for _, l := range m.Languages {
		if !proglang.Supported(l.Lang) && l.Files > 0 && isAppLanguage(l.Lang) {
			note := fmt.Sprintf("%s (%d files): findings and analysis only. Proofs are auto-run for %s in this version.", l.Lang, l.Files, proglang.DisplayList())
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
	outcome := ledger.OutcomeCompleted
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
	if err := r.recordFindings(mapSeq, findings, parent); err != nil {
		return Result{}, err
	}

	return r.end(startSeq, outcome)
}

// persist appends one finished finding to the ledger at once, so an
// interrupt or a later failure cannot lose it, and remembers it in
// runner.recorded so the max-findings cap keeps it. A finding that does not
// validate is not written here: recordFindings writes its reject when the
// run ends. persist and recordFindings are the only two writers of
// findings to the ledger of a code scan or a running-target scan.
func (r *runner) persist(seq int64, f finding.Finding) error {
	if f.Validate() != nil {
		return nil
	}
	if _, err := r.led.Append(seq, ledger.TypeFinding, f); err != nil {
		return err
	}
	if r.recorded == nil {
		r.recorded = map[string]bool{}
	}
	r.recorded[f.ID] = true
	return nil
}

// capFindings applies a max-findings limit to ranked findings. The ones in
// recorded are already in the ledger, and an event cannot be taken back, so
// they are always kept and come first in the count; the rest fill what
// room is left, in rank order. dropped describes the findings left out,
// and over is how many recorded findings exceed the limit on their own
// (zero while investigations are planned within the cap).
func capFindings(findings []finding.Finding, recorded map[string]bool, limit int) (kept []finding.Finding, dropped []string, over int) {
	if limit <= 0 || len(findings) <= limit {
		return findings, nil, 0
	}
	var rest []finding.Finding
	for _, f := range findings {
		if recorded[f.ID] {
			kept = append(kept, f)
		} else {
			rest = append(rest, f)
		}
	}
	over = max(len(kept)-limit, 0)
	room := min(max(limit-len(kept), 0), len(rest))
	for _, f := range rest[room:] {
		dropped = append(dropped, fmt.Sprintf("%s %s (%s)", f.ID, f.Title, f.Location))
	}
	return finding.Rank(append(kept, rest[:room]...)), dropped, over
}

// recordFindings applies the max-findings cap and appends the findings to
// the ledger when the run ends. findings must be ranked: the cap keeps the
// first ones and lists the rest in a budget skip event under mapSeq.
// Findings that persist already wrote are kept whatever their rank (see
// capFindings), because the report would load them anyway; if they alone
// exceed the cap, a note says so. A finding that does not validate is a
// Spackle bug, not a target problem, and is recorded as a reject instead
// of being reported.
func (r *runner) recordFindings(mapSeq int64, findings []finding.Finding, parent map[string]int64) error {
	if limit := r.cfg.Budget.MaxFindings; limit > 0 && len(findings) > limit {
		var dropped []string
		var over int
		findings, dropped, over = capFindings(findings, r.recorded, limit)
		if _, err := r.led.Append(mapSeq, ledger.TypeBudgetSkip, ledger.BudgetSkip{Cap: fmt.Sprintf("max findings (%d)", limit), Skipped: dropped}); err != nil {
			return err
		}
		if over > 0 {
			note := fmt.Sprintf("%d findings were already recorded when the max findings cap of %d applied, so the report holds %d more than the cap.", limit+over, limit, over)
			if _, err := r.led.Append(mapSeq, ledger.TypeNote, note); err != nil {
				return err
			}
		}
	}
	for _, f := range findings {
		if err := f.Validate(); err != nil {
			if _, aerr := r.led.Append(parent[f.ID], ledger.TypeReject, ledger.Reject{Stage: "engine", Intent: f.ID, Reason: err.Error()}); aerr != nil {
				return aerr
			}
			continue
		}
		if _, err := r.led.Append(parent[f.ID], ledger.TypeFinding, f); err != nil {
			return err
		}
	}
	return nil
}

// offlineSeeder stands in for a scanner that offline mode does not run, so
// the report still shows it and says why it was skipped.
type offlineSeeder struct{ name string }

func (o offlineSeeder) Name() string { return o.name }
func (o offlineSeeder) Available() (bool, string) {
	return false, "not run in offline mode: it downloads rules or a vulnerability database when it runs"
}
func (o offlineSeeder) Run(context.Context, string, []walk.File) ([]seed.Lead, error) {
	return nil, nil
}

// disabledSeeder stands in for an external scanner that [scan] scanners
// leaves out, so the report still shows it and says why it was not run.
type disabledSeeder struct{ name string }

func (d disabledSeeder) Name() string { return d.name }
func (d disabledSeeder) Available() (bool, string) {
	return false, DisabledScannerNote
}
func (d disabledSeeder) Run(context.Context, string, []walk.File) ([]seed.Lead, error) {
	return nil, nil
}

// DisabledScannerNote is what the report and doctor say about an external
// scanner that [scan] scanners leaves out.
const DisabledScannerNote = "not run: [scan] scanners in the configuration leaves it out"

// configuredSeeders replaces every external scanner that allow does not
// name. A nil allow (the key is absent) keeps them all; the built-in
// seeders are always kept.
func configuredSeeders(in []seed.Seeder, allow []string) []seed.Seeder {
	if allow == nil {
		return in
	}
	out := make([]seed.Seeder, 0, len(in))
	for _, s := range in {
		if seed.IsExternal(s.Name()) && !slices.Contains(allow, s.Name()) {
			out = append(out, disabledSeeder{name: s.Name()})
			continue
		}
		out = append(out, s)
	}
	return out
}

// offlineSeeders replaces every seeder that uses the network when it runs
// (it downloads rules or a vulnerability database). Offline mode promises
// that nothing leaves the machine. Whether a seeder does is its own
// property, declared where the seeder is defined.
func offlineSeeders(in []seed.Seeder) []seed.Seeder {
	out := make([]seed.Seeder, 0, len(in))
	for _, s := range in {
		if n, ok := s.(seed.NetworkUser); ok && n.UsesNetwork() {
			out = append(out, offlineSeeder{name: s.Name()})
			continue
		}
		out = append(out, s)
	}
	return out
}

// firstSentence shortens an error to its first clause for a one-line note.
func firstSentence(s string) string {
	for _, sep := range []string{": ", ". "} {
		if i := strings.Index(s, sep); i > 0 && i < 160 {
			s = s[:i]
			break
		}
	}
	return textx.Clip(s, 160)
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
