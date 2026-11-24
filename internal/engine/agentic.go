package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/agent"
	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/textx"
)

// maxIntents bounds how many investigations one run plans, whatever the
// budget. More than this and the report stops being something a person
// reads.
const maxIntents = 30

// Rough per-investigation sizes used only for the estimate shown before a
// paid run and for skipping work that would not fit in the remaining budget.
const (
	estInputPerIntent  = 60_000
	estOutputPerIntent = 6_000
)

// providers resolves and caches one provider per pipeline stage.
type providers struct {
	cfg   config.Config
	make  func(config.Model) (llm.Provider, error)
	cache map[string]llm.Provider
}

func newProviders(cfg config.Config, factory func(config.Model) (llm.Provider, error)) *providers {
	if factory == nil {
		factory = func(m config.Model) (llm.Provider, error) {
			return llm.New(m, llm.Options{Offline: cfg.Offline})
		}
	}
	return &providers{cfg: cfg, make: factory, cache: map[string]llm.Provider{}}
}

func (p *providers) forStage(stage string) (llm.Provider, error) {
	m := p.cfg.ForStage(stage)
	key := m.Provider + "|" + m.Model + "|" + m.BaseURL
	if prov, ok := p.cache[key]; ok {
		return prov, nil
	}
	prov, err := p.make(m)
	if err != nil {
		return nil, fmt.Errorf("stage %s: %w", stage, err)
	}
	p.cache[key] = prov
	return prov, nil
}

// checkAll builds the provider for every stage up front, so a missing key
// or an offline violation refuses the run before anything is written.
func (p *providers) checkAll() error {
	for _, stage := range config.Stages {
		if _, err := p.forStage(stage); err != nil {
			return err
		}
	}
	return nil
}

// Estimate describes the expected cost of the agentic stages.
type Estimate struct {
	Investigations int
	Model          string
	USD            float64
	CostKnown      bool
	Local          bool
	CapUSD         float64
	CapTokens      int
}

// String renders the estimate as the one-line notice shown to the operator.
func (e Estimate) String() string {
	switch {
	case e.Local:
		return fmt.Sprintf("About %d investigations with local model %s. No model spend. Token cap %d.", e.Investigations, e.Model, e.CapTokens)
	case !e.CostKnown:
		return fmt.Sprintf("About %d investigations with %s. Warning: its price is not known to Spackle, so spend cannot be estimated or capped in dollars; the token cap of %d still applies. Add [pricing] to spackle.toml to fix this.", e.Investigations, e.Model, e.CapTokens)
	default:
		return fmt.Sprintf("About %d investigations with %s: estimated up to $%.2f. Hard caps: $%.2f and %d tokens.", e.Investigations, e.Model, e.USD, e.CapUSD, e.CapTokens)
	}
}

// confirmEstimate is the consent step every model run passes before
// anything is written. With a confirm function the operator is asked. With
// none (--yes, the Action, the MCP server, the benchmark) nobody reads the
// estimate, so a dollar cap the operator set but that cannot hold for an
// unpriced model refuses the run unless they opted in. m is the model the
// estimate was made for.
func confirmEstimate(cfg config.Config, m config.Model, est Estimate, confirm func(Estimate) bool) error {
	if confirm != nil {
		if !confirm(est) {
			return fmt.Errorf("%w: the run was not confirmed. Pass --yes to skip this prompt, or lower --budget-usd", ErrRefused)
		}
		return nil
	}
	if why := unpricedRefusal(cfg, m, est); why != "" {
		return fmt.Errorf("%w: %s", ErrRefused, why)
	}
	return nil
}

// unpricedRefusal says why a run that nobody confirms is refused: the
// operator set a dollar cap, and it cannot hold for a model without a known
// price. It returns "" when the run may go ahead. A dry run asks the same
// question to say what the real run would do.
func unpricedRefusal(cfg config.Config, m config.Model, est Estimate) string {
	if est.Local || est.CostKnown || !cfg.Budget.USDSet || cfg.Budget.AllowUnpriced || llm.ReportsCost(m.BaseURL) {
		return ""
	}
	return fmt.Sprintf("the dollar cap of $%.2f cannot be enforced, because Spackle has no price for %s. Add its price in USD per million tokens to spackle.toml:\n\n[pricing.%q]\ninput_per_mtok = <price>\noutput_per_mtok = <price>\n\nOr pass --allow-unpriced (or set allow_unpriced = true under [budget]) to run with the token cap of %d and no dollar cap",
		est.CapUSD, est.Model, est.Model, est.CapTokens)
}

func estimate(cfg config.Config, prov llm.Provider, pricer llm.Pricer, leads int) Estimate {
	n := leads + 4
	if n > maxIntents {
		n = maxIntents
	}
	usd, known := pricer.EstimateCost(prov.Model(), prov.Local(), n*estInputPerIntent, n*estOutputPerIntent)
	if usd > cfg.Budget.USD {
		usd = cfg.Budget.USD
	}
	return Estimate{Investigations: n, Model: prov.Model(), USD: usd, CostKnown: known, Local: prov.Local(), CapUSD: cfg.Budget.USD, CapTokens: cfg.Budget.Tokens}
}

// fateKind says what a run did with a lead.
type fateKind int

const (
	fateNone       fateKind = iota // not selected for investigation in this run
	fateFound                      // an investigated finding stands for the lead
	fateDismissed                  // investigated and not confirmed
	fateIncomplete                 // the investigation gave no usable result
)

// leadFate is the fate of one lead. reason is the investigator's reason for
// a dismissal, or what went wrong for an incomplete investigation.
type leadFate struct {
	kind   fateKind
	reason string
}

// agenticState is what the investigations of one run build up.
type agenticState struct {
	capState
	findings []finding.Finding
	// parent maps a finding id to the ledger event the finding descends from.
	parent map[string]int64
	// fates maps a lead id to what happened to the lead.
	fates map[string]leadFate
	// interrupted is set when the operator cancels the run. The loop then
	// stops, and everything found so far is still reported.
	interrupted bool
}

func newAgenticState() *agenticState {
	return &agenticState{capState: capState{outcome: "completed"}, parent: map[string]int64{}, fates: map[string]leadFate{}}
}

// settle records one fate for every lead of an investigation.
func (st *agenticState) settle(leadIDs []string, kind fateKind, reason string) {
	for _, id := range leadIDs {
		st.fates[id] = leadFate{kind: kind, reason: reason}
	}
}

// agenticStages is what one investigation needs besides its intent: the
// target, the leads, the runner of each stage, and the tool registry maker.
type agenticStages struct {
	root                                  string
	leads                                 []seed.Lead
	investigator, reviewer, prover, fixer *agent.Runner
	newRegistry                           func() *tools.Registry
}

// nextStep says how the investigation loop goes on after one investigation.
type nextStep int

const (
	// goOn: take the next investigation.
	goOn nextStep = iota
	// stopBefore: this investigation did not finish. It and the ones after
	// it are listed as not investigated.
	stopBefore
	// stopAfter: this investigation is finished, and the ones after it are
	// listed as not investigated.
	stopAfter
)

// agentic runs the model-driven stages and returns the findings, the ledger
// event each finding descends from, and the run outcome.
func (r *runner) agentic(ctx context.Context, root string, m mapper.Map, leads []seed.Lead, leadSeq map[string]int64, mapSeq int64) ([]finding.Finding, map[string]int64, string, error) {
	if err := r.startAgents(); err != nil {
		return nil, nil, "", err
	}
	st := newAgenticState()
	sg := agenticStages{root: root, leads: leads, newRegistry: r.registries(root, m.Files)}

	limit := maxIntents
	if mf := r.cfg.Budget.MaxFindings; mf > 0 && mf < limit {
		limit = mf
	}

	// Plan.
	r.say("Planning investigations")
	var intents []agent.Intent
	planner, err := r.runnerFor("planner")
	if err != nil {
		return nil, nil, "", err
	}
	// In a diff scan the planner sees the entry points and trust boundaries
	// of the changed files only, and may plan for those files only. The
	// investigators still read the whole tree.
	planMap := m
	if r.changed != nil {
		planMap = changedMap(m, r.changed)
	}
	// A resumed run does not plan again: it continues with the
	// investigations the earlier run did not reach.
	var perr error
	if r.resume != nil {
		intents = agent.ResumePlan(r.resume.intents, planMap, leads, limit)
	} else {
		intents, perr = agent.Plan(ctx, planner, mapSeq, r.sealer, planMap, leads, limit)
	}
	if r.resume == nil && (perr != nil || len(intents) == 0) {
		switch {
		case ctx.Err() != nil:
			intents, st.interrupted = nil, true
		case errors.Is(perr, budget.ErrExhausted):
			intents = nil
			st.exhaust(perr.Error(), "Planning did not finish, so no lead was investigated.")
		default:
			note := "The planner returned no usable plan, so investigations were planned directly from scanner leads."
			if perr != nil {
				note = "The planner failed (" + textx.Clip(perr.Error(), 200) + "), so investigations were planned directly from scanner leads."
			}
			if _, err := r.led.Append(mapSeq, ledger.TypeNote, note); err != nil {
				return nil, nil, "", err
			}
			intents = agent.FallbackPlan(planMap, leads, limit)
		}
	}
	intentSeq := map[string]int64{}
	for _, it := range intents {
		seq, err := r.led.Append(mapSeq, ledger.TypeIntent, it)
		if err != nil {
			return nil, nil, "", err
		}
		intentSeq[it.ID] = seq
	}

	// Investigate, then review each result while its context is cheap.
	for _, s := range []struct {
		stage string
		into  **agent.Runner
	}{{"investigator", &sg.investigator}, {"reviewer", &sg.reviewer}, {"prover", &sg.prover}, {"fixer", &sg.fixer}} {
		if *s.into, err = r.runnerFor(s.stage); err != nil {
			return nil, nil, "", err
		}
	}
	invProv := sg.investigator.Provider
	estUSD, _ := r.pricer.EstimateCost(invProv.Model(), invProv.Local(), estInputPerIntent/2, estOutputPerIntent/2)

	// notInvestigated records the intents from i on as skipped.
	notInvestigated := func(i int) {
		for _, rest := range intents[i:] {
			st.skipped = append(st.skipped, fmt.Sprintf(notInvestigatedPrefix+"%s (%s)", rest.Title, strings.Join(rest.Files, ", ")))
		}
	}
	for i, it := range intents {
		var step nextStep
		if ctx.Err() != nil {
			st.interrupted, step = true, stopBefore
		} else if berr := r.budget.CanAfford(estInputPerIntent/2, estUSD); berr != nil {
			st.exhaust(berr.Error())
			step = stopBefore
		} else {
			r.say("Investigating %d/%d: %s", i+1, len(intents), it.Title)
			if step, err = r.investigateOne(ctx, st, sg, it, intentSeq[it.ID]); err != nil {
				return nil, nil, "", err
			}
		}
		if step == stopBefore {
			notInvestigated(i)
			break
		}
		if step == stopAfter {
			notInvestigated(i + 1)
			break
		}
	}
	if st.interrupted {
		st.outcome = "interrupted"
		st.capNote = "interrupted by the operator"
		r.say("Interrupted: writing the findings produced so far")
		// The run's context is cancelled. The remaining steps are local and
		// short, so they get a fresh context with its own limit.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
	}

	if err := r.leftoverFindings(st, leads, leadSeq, mapSeq); err != nil {
		return nil, nil, "", err
	}
	if err := r.publishFixes(ctx, st, mapSeq); err != nil {
		return nil, nil, "", err
	}

	// Look for chains across confirmed findings. Optional: skip when the
	// budget is gone, and never fail the run over it.
	if !st.interrupted && r.budget.Check() == nil {
		if mech, merr := r.runnerFor("mechanical"); merr == nil {
			if linked, cerr := agent.Correlate(ctx, mech, mapSeq, r.sealer, st.findings); cerr == nil {
				st.findings = linked
			} else if errors.Is(cerr, budget.ErrExhausted) {
				st.capNote = cerr.Error()
			}
		}
	}

	if len(st.skipped) > 0 || st.capNote != "" {
		if st.capNote == "" {
			st.capNote = "budget"
		}
		if len(st.skipped) == 0 {
			st.skipped = []string{"Later optional stages (review or chain analysis) were cut short."}
		}
		if _, err := r.led.Append(mapSeq, ledger.TypeBudgetSkip, ledger.BudgetSkip{Cap: st.capNote, Skipped: st.skipped}); err != nil {
			return nil, nil, "", err
		}
	}
	return st.findings, st.parent, st.outcome, nil
}

// investigateOne runs one planned investigation: the investigator, then for
// a finding the reviewer, the proof and the fix. seq is the ledger event of
// the intent. It records in st what became of the intent's leads and any
// finding, and returns how the loop goes on. A cap that is reached or an
// interrupt is not an error: it is recorded in st. The error is for a
// ledger that cannot be written.
func (r *runner) investigateOne(ctx context.Context, st *agenticState, sg agenticStages, it agent.Intent, seq int64) (nextStep, error) {
	inv, ierr := agent.Investigate(ctx, sg.investigator, seq, sg.root, r.sealer, sg.newRegistry(), it, sg.leads)
	if ierr != nil {
		if errors.Is(ierr, budget.ErrExhausted) {
			st.exhaust(ierr.Error())
			return stopBefore, nil
		}
		if ctx.Err() != nil {
			st.interrupted = true
			return stopBefore, nil
		}
		// A provider failure on one investigation should not discard
		// the rest of the run. Record it and move on.
		reason := "the investigation failed: " + textx.Clip(ierr.Error(), 300)
		if _, err := r.led.Append(seq, ledger.TypeReject, ledger.Reject{Stage: "investigator", Intent: it.ID + " " + it.Title, Reason: reason}); err != nil {
			return goOn, err
		}
		st.settle(it.LeadIDs, fateIncomplete, reason)
		return goOn, nil
	}
	if inv.Finding == nil {
		if inv.NoFinding != "" {
			st.settle(it.LeadIDs, fateDismissed, inv.NoFinding)
		} else {
			st.settle(it.LeadIDs, fateIncomplete, inv.Rejected)
		}
		return goOn, nil
	}

	f := *inv.Finding
	step := goOn
	rev, rerr := agent.ReviewFinding(ctx, sg.reviewer, seq, r.sealer, sg.newRegistry(), f)
	switch {
	case rerr == nil:
		f = agent.ApplyReview(f, rev)
		outcomeName := rev.Verdict
		if rev.Verdict == agent.ReviewRefuted {
			outcomeName = "dismissed"
		}
		if _, err := r.led.Append(seq, ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: "reviewer", Outcome: outcomeName, Reason: rev.Reason}); err != nil {
			return goOn, err
		}
	case errors.Is(rerr, budget.ErrExhausted):
		f.Confidence.Reason += " Not reviewed: the budget ran out first."
		st.capNote = rerr.Error()
	default:
		f.Confidence.Reason += " Not reviewed: the review call failed."
	}
	if f.Status == finding.StatusOpen {
		var perr error
		f, perr = r.lab.proveAndFix(ctx, f, seq, sg.prover, sg.fixer, sg.newRegistry)
		switch {
		case perr == nil:
		case errors.Is(perr, budget.ErrExhausted):
			st.capNote = perr.Error()
		case ctx.Err() != nil:
			// The finding itself is complete; only its proof or fix was
			// cut short. Keep it.
			st.interrupted = true
			step = stopAfter
		default:
			// One failed proof or fix step must not end the run. The
			// finding stays as it was traced.
			if _, err := r.led.Append(seq, ledger.TypeReject, ledger.Reject{Stage: "prover", Intent: f.ID + " " + f.Title, Reason: "the proof or fix step failed: " + textx.Clip(perr.Error(), 300)}); err != nil {
				return goOn, err
			}
		}
	}
	st.parent[f.ID] = seq
	st.findings = append(st.findings, f)
	// The finished finding goes into the ledger at once, so an interrupt or
	// a later failure cannot lose it. The ranked findings are appended again
	// at the end of the run; the ledger keeps the latest event per id. One
	// that does not validate is reported as a reject when the run ends.
	if f.Validate() == nil {
		if _, err := r.led.Append(seq, ledger.TypeFinding, f); err != nil {
			return goOn, err
		}
	}
	st.settle(it.LeadIDs, fateFound, "")
	return step, nil
}

// leftoverFindings adds what the investigations did not turn into a finding
// of their own. Leads that did not become an investigated finding are still
// reported, labelled for exactly what happened to them, and in a resumed run
// the findings of the earlier run are carried over.
func (r *runner) leftoverFindings(st *agenticState, leads []seed.Lead, leadSeq map[string]int64, mapSeq int64) error {
	investigated := map[string]int{}
	for i := range st.findings {
		if _, seen := investigated[st.findings[i].ID]; !seen {
			investigated[st.findings[i].ID] = i
		}
	}
	// In a resumed run the earlier run's findings stand unless this run
	// reached its own conclusion about the same finding. decided holds the
	// ids this run investigated or dismissed itself.
	carried := map[string]bool{}
	handled := map[string]bool{}
	decided := map[string]bool{}
	if r.resume != nil {
		handled = r.resume.handled
		for _, f := range r.resume.findings {
			carried[f.ID] = true
		}
		for i := range st.findings {
			decided[st.findings[i].ID] = true
		}
	}
	for _, l := range leads {
		fate := st.fates[l.ID]
		var f finding.Finding
		switch fate.kind {
		case fateFound:
			// The investigated finding stands for this lead, also where
			// the earlier run reported the lead by itself.
			if r.resume != nil {
				decided[FromLead(l, "").ID] = true
			}
			continue
		case fateDismissed:
			f = FromLead(l, "Investigated by reading the code and not confirmed.")
			f.Status = finding.StatusDismissed
			f.DismissReason = "Investigated and not confirmed: " + fate.reason
		case fateIncomplete:
			f = FromLead(l, "The investigation of this lead did not produce a usable result ("+textx.Clip(fate.reason, 200)+"), so it is reported as an unconfirmed lead.")
		default:
			f = FromLead(l, "This lead was not selected for investigation in this run, so it is reported as an unconfirmed lead.")
			// This run did not look at the lead. When the earlier run
			// did, or already reported it, what it found is carried over
			// below and says more than a fresh unconfirmed lead.
			if carried[f.ID] || handled[l.ID] {
				continue
			}
		}
		decided[f.ID] = true
		if verr := f.Validate(); verr != nil {
			if _, err := r.led.Append(leadSeq[l.ID], ledger.TypeReject, ledger.Reject{Stage: "seed", Intent: l.ID, Reason: verr.Error()}); err != nil {
				return err
			}
			continue
		}
		// An investigated finding of the same class at the same place
		// already covers this lead: keep the lead as one of its origins.
		if i, ok := investigated[finding.MakeID(l.Class, f.Location)]; ok {
			st.findings[i].Origin = finding.UnionOrigins(st.findings[i].Origin, f.Origin)
			continue
		}
		if _, seen := st.parent[f.ID]; !seen {
			st.parent[f.ID] = leadSeq[l.ID]
		}
		st.findings = append(st.findings, f)
	}
	if r.resume != nil {
		for _, f := range r.resume.findings {
			if decided[f.ID] {
				continue
			}
			if _, seen := st.parent[f.ID]; !seen {
				st.parent[f.ID] = mapSeq
			}
			st.findings = append(st.findings, f)
		}
	}
	st.findings = finding.Dedup(st.findings)
	return nil
}

// publishFixes puts the accepted fixes on a branch of their own and, with
// --pr, opens the pull request for it.
func (r *runner) publishFixes(ctx context.Context, st *agenticState, mapSeq int64) error {
	branch, note := r.lab.branchFixes(ctx)
	if note == "" {
		return nil
	}
	if _, err := r.led.Append(mapSeq, ledger.TypeNote, note); err != nil {
		return err
	}
	if branch == "" {
		return nil
	}
	var fixed []finding.Finding
	for i := range st.findings {
		if st.findings[i].Remediation.Patch != "" && r.lab.branched[st.findings[i].ID] {
			st.findings[i].Remediation.Branch = branch
			fixed = append(fixed, st.findings[i])
		}
	}
	if r.cfg.Fix.PR && !st.interrupted {
		if _, err := r.led.Append(mapSeq, ledger.TypeNote, r.lab.openPR(ctx, branch, fixed)); err != nil {
			return err
		}
	}
	return nil
}
