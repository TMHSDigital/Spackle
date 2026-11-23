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
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
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
		return fmt.Sprintf("About %d investigations with %s. Its price is not known to Spackle, so spend cannot be estimated or capped in dollars; the token cap of %d still applies. Add [pricing] to spackle.toml to fix this.", e.Investigations, e.Model, e.CapTokens)
	default:
		return fmt.Sprintf("About %d investigations with %s: estimated up to $%.2f. Hard caps: $%.2f and %d tokens.", e.Investigations, e.Model, e.USD, e.CapUSD, e.CapTokens)
	}
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

// agentic runs the model-driven stages and returns the findings, the ledger
// event each finding descends from, and the run outcome.
func (r *runner) agentic(ctx context.Context, root string, m mapper.Map, leads []seed.Lead, leadSeq map[string]int64, mapSeq int64) ([]finding.Finding, map[string]int64, string, error) {
	parent := map[string]int64{}
	pricer := llm.NewPricer(llm.PricesFromConfig(r.cfg.Pricing))
	bud, err := budget.New(budget.Caps{
		Tokens: r.cfg.Budget.Tokens, USD: r.cfg.Budget.USD,
		Wall: r.cfg.Budget.WallTime.Duration, SandboxRuns: r.cfg.Budget.SandboxRuns,
	}, r.clock)
	if err != nil {
		return nil, nil, "", err
	}
	r.budget = bud
	sealer, err := envelope.New()
	if err != nil {
		return nil, nil, "", err
	}
	r.sealer = sealer
	newRegistry := func() *tools.Registry {
		return tools.NewRegistry(tools.Env{Root: root, Sealer: sealer, Walk: walkOptions(r.cfg)})
	}
	runnerFor := func(stage string) (*agent.Runner, error) {
		prov, err := r.provs.forStage(stage)
		if err != nil {
			return nil, err
		}
		return &agent.Runner{
			Provider: prov, Pricer: pricer, Budget: bud, Ledger: r.led, Stage: stage,
			MaxTurns: r.cfg.Budget.MaxTurns, MaxTokens: r.cfg.ForStage(stage).MaxOutputTokens,
		}, nil
	}

	limit := maxIntents
	if mf := r.cfg.Budget.MaxFindings; mf > 0 && mf < limit {
		limit = mf
	}

	// Plan.
	r.say("Planning investigations")
	var intents []agent.Intent
	planner, err := runnerFor("planner")
	if err != nil {
		return nil, nil, "", err
	}
	// interrupted is set when the operator cancels the run. The loop then
	// stops, and everything found so far is still reported.
	interrupted := false
	planCap := ""
	intents, perr := agent.Plan(ctx, planner, mapSeq, sealer, m, leads, limit)
	if perr != nil || len(intents) == 0 {
		switch {
		case ctx.Err() != nil:
			intents, interrupted = nil, true
		case errors.Is(perr, budget.ErrExhausted):
			intents, planCap = nil, perr.Error()
		default:
			note := "The planner returned no usable plan, so investigations were planned directly from scanner leads."
			if perr != nil {
				note = "The planner failed (" + clipText(perr.Error(), 200) + "), so investigations were planned directly from scanner leads."
			}
			if _, err := r.led.Append(mapSeq, ledger.TypeNote, note); err != nil {
				return nil, nil, "", err
			}
			intents = agent.FallbackPlan(m, leads, limit)
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
	investigator, err := runnerFor("investigator")
	if err != nil {
		return nil, nil, "", err
	}
	reviewer, err := runnerFor("reviewer")
	if err != nil {
		return nil, nil, "", err
	}
	prover, err := runnerFor("prover")
	if err != nil {
		return nil, nil, "", err
	}
	fixer, err := runnerFor("fixer")
	if err != nil {
		return nil, nil, "", err
	}
	invProv := investigator.Provider
	estUSD, _ := pricer.EstimateCost(invProv.Model(), invProv.Local(), estInputPerIntent/2, estOutputPerIntent/2)

	var findings []finding.Finding
	leadState := map[string]string{} // lead id -> "found" | "dismissed:<reason>" | "incomplete:<reason>"
	outcome := "completed"
	var skipped []string
	capNote := planCap
	if planCap != "" {
		outcome = "budget-exhausted"
		skipped = append(skipped, "Planning did not finish, so no lead was investigated.")
	}
	// notInvestigated records the intents from i on as skipped.
	notInvestigated := func(i int) {
		for _, rest := range intents[i:] {
			skipped = append(skipped, fmt.Sprintf("Not investigated: %s (%s)", rest.Title, strings.Join(rest.Files, ", ")))
		}
	}
	// record appends a finished finding to the ledger at once, so an
	// interrupt or a later failure cannot lose it. The ranked findings are
	// appended again at the end of the run; the ledger keeps the latest
	// event per id.
	record := func(f finding.Finding, seq int64) error {
		if f.Validate() != nil {
			return nil // reported as a reject when the run ends
		}
		_, err := r.led.Append(seq, ledger.TypeFinding, f)
		return err
	}

	for i, it := range intents {
		if ctx.Err() != nil {
			interrupted = true
			notInvestigated(i)
			break
		}
		if berr := bud.CanAfford(estInputPerIntent/2, estUSD); berr != nil {
			capNote = berr.Error()
			notInvestigated(i)
			outcome = "budget-exhausted"
			break
		}
		r.say("Investigating %d/%d: %s", i+1, len(intents), it.Title)
		inv, ierr := agent.Investigate(ctx, investigator, intentSeq[it.ID], root, sealer, newRegistry(), it, leads)
		if ierr != nil {
			if errors.Is(ierr, budget.ErrExhausted) {
				capNote = ierr.Error()
				notInvestigated(i)
				outcome = "budget-exhausted"
				break
			}
			if ctx.Err() != nil {
				interrupted = true
				notInvestigated(i)
				break
			}
			// A provider failure on one investigation should not discard
			// the rest of the run. Record it and move on.
			reason := "the investigation failed: " + clipText(ierr.Error(), 300)
			if _, err := r.led.Append(intentSeq[it.ID], ledger.TypeReject, ledger.Reject{Stage: "investigator", Intent: it.ID + " " + it.Title, Reason: reason}); err != nil {
				return nil, nil, "", err
			}
			for _, id := range it.LeadIDs {
				leadState[id] = "incomplete:" + reason
			}
			continue
		}
		switch {
		case inv.Finding != nil:
			f := *inv.Finding
			vseq := intentSeq[it.ID]
			rev, rerr := agent.ReviewFinding(ctx, reviewer, vseq, sealer, newRegistry(), f)
			switch {
			case rerr == nil:
				f = agent.ApplyReview(f, rev)
				outcomeName := rev.Verdict
				if rev.Verdict == agent.ReviewRefuted {
					outcomeName = "dismissed"
				}
				if _, err := r.led.Append(vseq, ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: "reviewer", Outcome: outcomeName, Reason: rev.Reason}); err != nil {
					return nil, nil, "", err
				}
			case errors.Is(rerr, budget.ErrExhausted):
				f.Confidence.Reason += " Not reviewed: the budget ran out first."
				capNote = rerr.Error()
			default:
				f.Confidence.Reason += " Not reviewed: the review call failed."
			}
			if f.Status == finding.StatusOpen {
				var perr error
				f, perr = r.lab.proveAndFix(ctx, f, vseq, prover, fixer, newRegistry)
				switch {
				case perr == nil:
				case errors.Is(perr, budget.ErrExhausted):
					capNote = perr.Error()
				case ctx.Err() != nil:
					// The finding itself is complete; only its proof or
					// fix was cut short. Keep it.
					interrupted = true
					notInvestigated(i + 1)
				default:
					// One failed proof or fix step must not end the run.
					// The finding stays as it was traced.
					if _, err := r.led.Append(vseq, ledger.TypeReject, ledger.Reject{Stage: "prover", Intent: f.ID + " " + f.Title, Reason: "the proof or fix step failed: " + clipText(perr.Error(), 300)}); err != nil {
						return nil, nil, "", err
					}
				}
			}
			parent[f.ID] = vseq
			findings = append(findings, f)
			if err := record(f, vseq); err != nil {
				return nil, nil, "", err
			}
			for _, id := range it.LeadIDs {
				leadState[id] = "found"
			}
		case inv.NoFinding != "":
			for _, id := range it.LeadIDs {
				leadState[id] = "dismissed:" + inv.NoFinding
			}
		default:
			for _, id := range it.LeadIDs {
				leadState[id] = "incomplete:" + inv.Rejected
			}
		}
		if interrupted {
			break
		}
	}
	if interrupted {
		outcome = "interrupted"
		capNote = "interrupted by the operator"
		r.say("Interrupted: writing the findings produced so far")
		// The run's context is cancelled. The remaining steps are local and
		// short, so they get a fresh context with its own limit.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
	}

	// Leads that did not become an investigated finding are still reported,
	// labelled for exactly what happened to them.
	investigated := map[string]int{}
	for i := range findings {
		if _, seen := investigated[findings[i].ID]; !seen {
			investigated[findings[i].ID] = i
		}
	}
	for _, l := range leads {
		state := leadState[l.ID]
		var f finding.Finding
		switch {
		case state == "found":
			continue
		case strings.HasPrefix(state, "dismissed:"):
			f = FromLead(l, "Investigated by reading the code and not confirmed.")
			f.Status = finding.StatusDismissed
			f.DismissReason = "Investigated and not confirmed: " + strings.TrimPrefix(state, "dismissed:")
		case strings.HasPrefix(state, "incomplete:"):
			f = FromLead(l, "The investigation of this lead did not produce a usable result ("+clipText(strings.TrimPrefix(state, "incomplete:"), 200)+"), so it is reported as an unconfirmed lead.")
		default:
			f = FromLead(l, "This lead was not selected for investigation in this run, so it is reported as an unconfirmed lead.")
		}
		if verr := f.Validate(); verr != nil {
			if _, err := r.led.Append(leadSeq[l.ID], ledger.TypeReject, ledger.Reject{Stage: "seed", Intent: l.ID, Reason: verr.Error()}); err != nil {
				return nil, nil, "", err
			}
			continue
		}
		// An investigated finding of the same class at the same place
		// already covers this lead: keep the lead as one of its origins.
		if i, ok := investigated[finding.MakeID(l.Class, f.Location)]; ok {
			findings[i].Origin = finding.UnionOrigins(findings[i].Origin, f.Origin)
			continue
		}
		if _, seen := parent[f.ID]; !seen {
			parent[f.ID] = leadSeq[l.ID]
		}
		findings = append(findings, f)
	}
	findings = finding.Dedup(findings)

	// Put accepted fixes on a branch of their own.
	if branch, note := r.lab.branchFixes(ctx); note != "" {
		if _, err := r.led.Append(mapSeq, ledger.TypeNote, note); err != nil {
			return nil, nil, "", err
		}
		if branch != "" {
			var fixed []finding.Finding
			for i := range findings {
				if findings[i].Remediation.Patch != "" && r.lab.branched[findings[i].ID] {
					findings[i].Remediation.Branch = branch
					fixed = append(fixed, findings[i])
				}
			}
			if r.cfg.Fix.PR && !interrupted {
				if _, err := r.led.Append(mapSeq, ledger.TypeNote, r.lab.openPR(ctx, branch, fixed)); err != nil {
					return nil, nil, "", err
				}
			}
		}
	}

	// Look for chains across confirmed findings. Optional: skip when the
	// budget is gone, and never fail the run over it.
	if !interrupted && bud.Check() == nil {
		if mech, merr := runnerFor("mechanical"); merr == nil {
			if linked, cerr := agent.Correlate(ctx, mech, mapSeq, sealer, findings); cerr == nil {
				findings = linked
			} else if errors.Is(cerr, budget.ErrExhausted) {
				capNote = cerr.Error()
			}
		}
	}

	if len(skipped) > 0 || capNote != "" {
		if capNote == "" {
			capNote = "budget"
		}
		if len(skipped) == 0 {
			skipped = []string{"Later optional stages (review or chain analysis) were cut short."}
		}
		if _, err := r.led.Append(mapSeq, ledger.TypeBudgetSkip, ledger.BudgetSkip{Cap: capNote, Skipped: skipped}); err != nil {
			return nil, nil, "", err
		}
	}
	return findings, parent, outcome, nil
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
