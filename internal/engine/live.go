package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/agent"
	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/authz"
	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/dast"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/target"
	"github.com/TMHSDigital/spackle/internal/textx"
	"github.com/TMHSDigital/spackle/internal/version"
)

// observedClasses are the running-target classes where the recorded
// exchange is itself the demonstration: the marker came back unescaped, the
// redirect pointed off-site, the file's contents were returned. For the
// rest (an SQL error message, for example) the exchange is strong evidence
// that a flaw exists, but the flaw was not exercised, so they are reported
// as reasoned.
var observedClasses = map[string]bool{
	"xss": true, "open-redirect": true, "path-traversal": true, "exposed-file": true,
	"directory-listing": true, "missing-security-header": true, "insecure-cookie": true,
	"cors-misconfiguration": true, "information-disclosure": true,
}

// runLive scans a running application. The authorized-scope gate comes
// first: nothing is sent, and no run directory is created, until it passes.
func runLive(ctx context.Context, opts Options, tgt target.Target, clock func() time.Time) (_ Result, err error) {
	say := func(format string, a ...any) {
		if opts.Progress != nil {
			fmt.Fprintf(opts.Progress, format+"\n", a...)
		}
	}
	cfg := opts.Config
	grant, err := authz.Gate(tgt.URL, authz.Options{
		ScopeFile: opts.ScopeFile, Config: cfg.Scope, Yes: opts.Yes,
		Interactive: opts.Interactive, Stdin: opts.Stdin, Stderr: opts.Progress,
	})
	if err != nil {
		if target.KnownForge(tgt.URL.Hostname()) {
			// Most likely a repository address that was not recognized as
			// one, not a wish to probe the forge itself.
			return Result{}, fmt.Errorf("%w: %w. %s is a code hosting site: to scan a repository there, give its clone URL ending in .git", ErrRefused, err, tgt.URL.Hostname())
		}
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if cfg.Offline && !llm.IsLoopbackHost(tgt.URL.Hostname()) {
		return Result{}, fmt.Errorf("%w: %w: %s is not on this machine. Offline mode only allows a running target on localhost", ErrRefused, llm.ErrOffline, tgt.URL.Host)
	}

	agentic := cfg.Model.Configured()
	provs := newProviders(cfg, opts.ProviderFactory)
	var defaultProv llm.Provider
	if agentic {
		if err := provs.checkAll(); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		if defaultProv, err = provs.forStage("investigator"); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		est := estimate(cfg, defaultProv, llm.NewPricer(llm.PricesFromConfig(cfg.Pricing)), 12)
		say("%s", est.String())
		if err := confirmEstimate(cfg, cfg.ForStage("investigator"), est, opts.Confirm); err != nil {
			return Result{}, err
		}
	}

	runID := opts.RunID
	if runID == "" {
		if runID, err = NewRunID(opts.Config.StateDir, clock()); err != nil {
			return Result{}, err
		}
	}
	runDir := filepath.Join(RunsDir(cfg.StateDir), runID)
	led, err := ledger.Create(runDir, clock)
	if err != nil {
		return Result{}, err
	}
	r := &runner{opts: opts, cfg: cfg, led: led, runDir: runDir, runID: runID, progress: opts.Progress, clock: clock, provs: provs}
	defer func() { _ = led.Close() }()
	defer r.endOnError(&err)

	start := ledger.RunStart{
		RunID: runID, Version: version.Version, Command: "scan",
		Target: tgt.Display, TargetKind: string(tgt.Kind), Mode: "deterministic", Offline: cfg.Offline,
		Scope: grant.Summary(), ScopeSource: grant.Source(),
		Isolation: "not used: running-target findings are demonstrated by recorded requests, not by sandboxed code",
	}
	if agentic {
		start.Mode, start.Provider, start.Model = "agentic", defaultProv.Name(), defaultProv.Model()
	}
	startSeq, err := led.Append(0, ledger.TypeRunStart, start)
	if err != nil {
		return Result{}, err
	}
	if st := grant.Statement(); st != "" {
		if _, err := led.Append(startSeq, ledger.TypeNote, "Operator's authorization statement: "+textx.Clip(st, 400)); err != nil {
			return Result{}, err
		}
	}

	// Every exchange is stored as evidence the moment it happens, so a run
	// that is interrupted still shows exactly what was sent.
	exDir := filepath.Join(runDir, "evidence", "exchanges")
	if err := os.MkdirAll(exDir, 0o700); err != nil {
		return Result{}, r.fail(fmt.Errorf("write evidence: %w", err))
	}
	var recordErr error
	client, err := dast.NewClient(grant, dast.ClientOptions{
		UserAgent: "spackle/" + version.Version + " (authorized security testing)",
		OnRecord: func(ex dast.Exchange) {
			b, merr := json.MarshalIndent(ex, "", "  ")
			if merr == nil {
				merr = os.WriteFile(filepath.Join(exDir, ex.ID+".json"), append(b, '\n'), 0o600)
			}
			if merr == nil {
				_, merr = led.Append(startSeq, ledger.TypeHTTPExchange, ledger.HTTPExchange{
					ID: ex.ID, Method: ex.Method, URL: ex.URL, Status: ex.Status, Note: ex.Note, Ref: "evidence/exchanges/" + ex.ID + ".json",
				})
			}
			if merr != nil && recordErr == nil {
				recordErr = merr
			}
		},
	})
	if err != nil {
		return Result{}, r.fail(err)
	}

	say("Probing %s within the authorized scope (%s)", tgt.Display, grant.Summary())
	base, err := dast.Baseline(ctx, client, tgt.URL, dast.Options{})
	if err != nil {
		return Result{}, r.fail(fmt.Errorf("the target could not be probed: %w. Check that it is running and reachable from this machine", err))
	}
	if recordErr != nil {
		return Result{}, r.fail(fmt.Errorf("write evidence: %w", recordErr))
	}
	mapSeq, err := led.Append(startSeq, ledger.TypeMap, ledger.MapSummary{Endpoints: len(base.Endpoints)})
	if err != nil {
		return Result{}, err
	}
	for _, n := range base.Notes {
		if _, err := led.Append(mapSeq, ledger.TypeNote, n); err != nil {
			return Result{}, err
		}
	}
	if _, err := led.Append(mapSeq, ledger.TypeSeeder, ledger.SeederStatus{Name: "dast-baseline", Available: true, Leads: len(base.Leads), Note: fmt.Sprintf("%d requests, %d endpoints", client.Requests(), len(base.Endpoints))}); err != nil {
		return Result{}, err
	}

	leads := base.Leads
	for i := range leads {
		leads[i].Source = "dast-baseline"
		leads[i].Finalize()
	}
	leads = seed.Sort(seed.Unique(leads))

	var findings []finding.Finding
	parent := map[string]int64{}
	for _, l := range leads {
		seq, err := led.Append(mapSeq, ledger.TypeLead, l)
		if err != nil {
			return Result{}, err
		}
		f := liveFinding(l)
		if verr := f.Validate(); verr != nil {
			if _, aerr := led.Append(seq, ledger.TypeReject, ledger.Reject{Stage: "dast", Intent: l.ID, Reason: verr.Error()}); aerr != nil {
				return Result{}, aerr
			}
			continue
		}
		parent[f.ID] = seq
		findings = append(findings, f)
	}
	findings = finding.Rank(finding.Dedup(findings))

	outcome := "completed"
	if agentic && len(findings) > 0 {
		findings, outcome, err = r.assessLive(ctx, findings, parent, mapSeq, client, tgt)
		if err != nil {
			return Result{}, r.fail(err)
		}
		if recordErr != nil {
			return Result{}, r.fail(fmt.Errorf("write evidence: %w", recordErr))
		}
	}

	findings = finding.Rank(findings)
	if err := r.recordFindings(mapSeq, findings, parent); err != nil {
		return Result{}, err
	}
	return r.end(startSeq, outcome)
}

// liveFinding turns a probe lead into a finding whose proof is the
// recorded exchange.
func liveFinding(l seed.Lead) finding.Finding {
	f := FromLead(l, "")
	var refs []string
	for _, id := range l.Evidence {
		refs = append(refs, "evidence/exchanges/"+id+".json")
	}
	f.Flaw.Flow = nil // a probe lead has no source line; the exchange is the evidence
	ids := strings.Join(l.Evidence, ", ")
	switch {
	case len(refs) > 0 && observedClasses[l.Class]:
		f.Proof = finding.Proof{
			Status: finding.ProofDemonstrated, Kind: "http-sequence", Artifacts: refs, Result: l.Snippet,
			Summary: "The behavior was observed in the recorded exchange(s) " + ids + ".",
		}
		if f.Proof.Result == "" {
			f.Proof.Result = "See the recorded exchange(s) " + ids + "."
		}
		f.Confidence = finding.Confidence{Level: finding.ConfidenceDemonstrated, Reason: "Observed directly: the recorded request and response show it. Impact beyond what the exchange shows was not exercised."}
	case len(refs) > 0:
		f.Proof = finding.Proof{
			Status: finding.ProofReasoned, Kind: "http-sequence", Artifacts: refs, Result: l.Snippet,
			Reason: "The recorded exchange(s) " + ids + " show the symptom. The flaw itself was not exercised, to stay non-destructive.",
		}
		f.Confidence = finding.Confidence{Level: finding.ConfidenceHigh, Reason: "The response changed in the way this flaw causes. Exploitation was not attempted."}
	default:
		f.Proof = finding.Proof{Status: finding.ProofNotRun, Reason: "The probe reported this without a recorded exchange."}
	}
	return f
}

// assessLive has a model confirm and explain each running-target finding,
// with a scope-bound http_request tool for follow-up requests.
func (r *runner) assessLive(ctx context.Context, findings []finding.Finding, parent map[string]int64, mapSeq int64, client *dast.Client, tgt target.Target) ([]finding.Finding, string, error) {
	pricer := llm.NewPricer(llm.PricesFromConfig(r.cfg.Pricing))
	bud, err := budget.New(budget.Caps{
		Tokens: r.cfg.Budget.Tokens, USD: r.cfg.Budget.USD,
		Wall: r.cfg.Budget.WallTime.Duration, SandboxRuns: r.cfg.Budget.SandboxRuns,
	}, r.clock)
	if err != nil {
		return nil, "", err
	}
	sealer, err := envelope.New()
	if err != nil {
		return nil, "", err
	}
	prov, err := r.provs.forStage("investigator")
	if err != nil {
		return nil, "", err
	}
	run := &agent.Runner{Provider: prov, Pricer: pricer, Budget: bud, Ledger: r.led, Stage: "investigator", MaxTurns: 8, MaxTokens: r.cfg.ForStage("investigator").MaxOutputTokens}
	known := func(id string) bool { _, ok := client.Exchange(id); return ok }

	outcome := "completed"
	var skipped []string
	capNote := ""
	notAssessed := func(rest []finding.Finding) {
		for _, f := range rest {
			skipped = append(skipped, "Not assessed by a model: "+f.Title+" ("+f.Location.String()+")")
		}
	}
	requestCap := fmt.Sprintf("request cap reached: all %d requests the scope allows for this run have been sent. Raise max_requests in the scope to assess the rest", client.MaxRequests())
	for i := range findings {
		if cerr := ctx.Err(); cerr != nil {
			return nil, "", cerr
		}
		f := findings[i]
		if client.AtCap() {
			// No request is left to probe this finding or any after it.
			capNote = requestCap
			notAssessed(findings[i:])
			outcome = "budget-exhausted"
			break
		}
		if berr := bud.Check(); berr != nil {
			capNote = berr.Error()
			for _, rest := range findings[i:] {
				skipped = append(skipped, "Not assessed by a model: "+rest.Title+" ("+rest.Location.String()+")")
			}
			outcome = "budget-exhausted"
			break
		}
		r.say("Assessing %d/%d: %s", i+1, len(findings), f.Title)
		var text strings.Builder
		for _, ref := range f.Proof.Artifacts {
			id := strings.TrimSuffix(filepath.Base(ref), ".json")
			if ex, ok := client.Exchange(id); ok {
				b, _ := json.MarshalIndent(ex, "", " ")
				text.Write(b)
				text.WriteByte('\n')
			}
		}
		reg := tools.NewNetworkRegistry(sealer)
		reg.Add(dast.HTTPTool(client, tgt.URL))
		refusedBefore := client.CapRefusals()
		rev, aerr := agent.InvestigateEndpoint(ctx, run, parent[f.ID], sealer, reg, f, text.String(), known)
		if aerr != nil {
			if errors.Is(aerr, budget.ErrExhausted) || errors.Is(aerr, dast.ErrRequestCap) {
				capNote = aerr.Error()
				for _, rest := range findings[i:] {
					skipped = append(skipped, "Not assessed by a model: "+rest.Title+" ("+rest.Location.String()+")")
				}
				outcome = "budget-exhausted"
				break
			}
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			if _, err := r.led.Append(parent[f.ID], ledger.TypeReject, ledger.Reject{Stage: "investigator", Intent: f.ID, Reason: "the assessment failed: " + textx.Clip(aerr.Error(), 300)}); err != nil {
				return nil, "", err
			}
			continue
		}
		// The request tool tells the model that the cap is reached and
		// hands no error back here, so the client is asked instead.
		cutShort := client.CapRefusals() > refusedBefore
		switch {
		case cutShort && !rev.Confirmed:
			// The model ran out of requests while it assessed this
			// finding. What it concluded without them is not a verdict:
			// the finding keeps its standing and is listed as not assessed.
			capNote = requestCap
			notAssessed(findings[i : i+1])
			outcome = "budget-exhausted"
		case rev.Rejected != "":
			if _, err := r.led.Append(parent[f.ID], ledger.TypeReject, ledger.Reject{Stage: "investigator", Intent: f.ID, Reason: rev.Rejected}); err != nil {
				return nil, "", err
			}
		case rev.Confirmed:
			findings[i] = rev.Finding
			if _, err := r.led.Append(parent[f.ID], ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: "investigator", Outcome: "confirmed", Reason: rev.Reason}); err != nil {
				return nil, "", err
			}
		default:
			findings[i].Status = finding.StatusDismissed
			findings[i].DismissReason = "Assessed against the running target and not confirmed: " + rev.Reason
			if _, err := r.led.Append(parent[f.ID], ledger.TypeVerdict, ledger.Verdict{FindingID: f.ID, Stage: "investigator", Outcome: "dismissed", Reason: rev.Reason}); err != nil {
				return nil, "", err
			}
		}
	}
	if len(skipped) > 0 {
		if _, err := r.led.Append(mapSeq, ledger.TypeBudgetSkip, ledger.BudgetSkip{Cap: capNote, Skipped: skipped}); err != nil {
			return nil, "", err
		}
	}
	return findings, outcome, nil
}
