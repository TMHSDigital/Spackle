package report

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
)

// JSONSchema names the envelope renderJSON writes. It changes only when a key
// is removed or changes meaning; adding a key keeps the version.
const JSONSchema = "spackle.report/v1"

// The JSON report is one object with these keys, always in this order:
//
//	schema     the string "spackle.report/v1"
//	run        what was run: id, version, target, mode, scope, times, outcome
//	counts     finding totals by status, severity and proof
//	findings   active (open or fixed) findings in rank order, each the
//	           finding.Finding JSON exactly as the ledger holds it
//	dismissed  findings the reviewer refuted, same shape, with dismiss_reason
//	skipped    one entry per budget cap that was reached
//	notes      free-text notes the run recorded about what it did not do
//	coverage   the target map summary and one entry per seeder
//	usage      model calls, tokens, cost and sandbox runs
//
// Arrays are never null. Times are RFC 3339 in UTC, or the empty string when
// the ledger did not record one. usage.cost_usd is null when cost_known is
// false: an unknown cost is not zero.
type jsonReport struct {
	Schema    string              `json:"schema"`
	Run       jsonRun             `json:"run"`
	Counts    jsonCounts          `json:"counts"`
	Findings  []finding.Finding   `json:"findings"`
	Dismissed []finding.Finding   `json:"dismissed"`
	Skipped   []ledger.BudgetSkip `json:"skipped"`
	Rejected  []ledger.Reject     `json:"rejected"`
	Notes     []string            `json:"notes"`
	Coverage  jsonCoverage        `json:"coverage"`
	Usage     jsonUsage           `json:"usage"`
}

type jsonRun struct {
	ID             string `json:"id"`
	SpackleVersion string `json:"spackle_version"`
	Command        string `json:"command"`
	Target         string `json:"target"`
	TargetKind     string `json:"target_kind"`
	Commit         string `json:"commit"`
	Mode           string `json:"mode"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	Offline        bool   `json:"offline"`
	Scope          string `json:"scope"`
	ScopeSource    string `json:"scope_source"`
	Isolation      string `json:"isolation"`
	StartedAt      string `json:"started_at"`
	EndedAt        string `json:"ended_at"`
	Outcome        string `json:"outcome"`
}

type jsonCounts struct {
	Total        int `json:"total"`
	Open         int `json:"open"`
	Fixed        int `json:"fixed"`
	Dismissed    int `json:"dismissed"`
	Demonstrated int `json:"demonstrated"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	None         int `json:"none"`
}

type jsonCoverage struct {
	Map     ledger.MapSummary     `json:"map"`
	Seeders []ledger.SeederStatus `json:"seeders"`
	Leads   int                   `json:"leads"`
}

type jsonUsage struct {
	ModelCalls      int      `json:"model_calls"`
	InputTokens     int      `json:"input_tokens"`
	OutputTokens    int      `json:"output_tokens"`
	TokensEstimated bool     `json:"tokens_estimated"`
	CostUSD         *float64 `json:"cost_usd"`
	CostKnown       bool     `json:"cost_known"`
	SandboxRuns     int      `json:"sandbox_runs"`
}

func renderJSON(run Run, w io.Writer) error {
	c := run.Count()
	rep := jsonReport{
		Schema: JSONSchema,
		Run: jsonRun{
			ID: run.ID, SpackleVersion: run.Version, Command: run.Command,
			Target: run.Target, TargetKind: run.TargetKind, Commit: run.Commit,
			Mode: run.Mode, Provider: run.Provider, Model: run.Model, Offline: run.Offline,
			Scope: run.Scope, ScopeSource: run.ScopeSource, Isolation: run.Isolation,
			StartedAt: jsonTime(run.StartedAt), EndedAt: jsonTime(run.EndedAt), Outcome: run.Outcome,
		},
		Counts: jsonCounts{
			Total: len(run.Findings), Open: c.Open, Fixed: c.Fixed, Dismissed: c.Dismissed,
			Demonstrated: c.Demonstrated,
			Critical:     c.Critical, High: c.High, Medium: c.Medium, Low: c.Low, None: c.None,
		},
		Findings:  nonNil(run.Active()),
		Dismissed: nonNil(run.Dismissed()),
		Skipped:   make([]ledger.BudgetSkip, 0, len(run.Skipped)),
		Rejected:  nonNil(run.Rejected),
		Notes:     nonNil(run.Notes),
		Coverage:  jsonCoverage{Map: run.Map, Seeders: nonNil(run.Seeders), Leads: run.Usage.Leads},
		Usage: jsonUsage{
			ModelCalls: run.Usage.ModelCalls, InputTokens: run.Usage.InputTokens, OutputTokens: run.Usage.OutputTokens,
			TokensEstimated: run.Usage.Estimated, CostKnown: run.Usage.CostKnown, SandboxRuns: run.Usage.SandboxRuns,
		},
	}
	for _, s := range run.Skipped {
		rep.Skipped = append(rep.Skipped, ledger.BudgetSkip{Cap: s.Cap, Skipped: nonNil(s.Skipped)})
	}
	if run.Usage.CostKnown {
		cost := run.Usage.CostUSD
		rep.Usage.CostUSD = &cost
	}
	return writeJSON(w, rep)
}

// writeJSON encodes v with two-space indentation, HTML escaping off and a
// trailing newline.
func writeJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func jsonTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// nonNil returns s, or an empty slice when s is nil, so JSON shows [] and
// never null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
