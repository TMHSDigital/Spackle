// Package report renders a stored run. A report is a pure function of the
// run's ledger: Load reads only ledger.jsonl, and renderers use no clock, no
// environment and no map iteration order, so rendering the same run twice
// produces the same bytes.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
)

// Run is everything a renderer needs.
type Run struct {
	ID         string
	Version    string
	Command    string
	Target     string
	TargetKind string
	// TargetPath is the absolute directory a path target was scanned in.
	// It is empty for runs stored before it was recorded.
	TargetPath string
	// RepoPrefix is the scanned directory's path from the top of its git
	// work tree ("" at the top). Finding paths are relative to the scanned
	// directory; SARIF needs them relative to the repository.
	RepoPrefix  string
	Commit      string
	Mode        string // deterministic|agentic
	Provider    string
	Model       string
	Offline     bool
	Scope       string
	ScopeSource string
	Isolation   string
	StartedAt   time.Time
	EndedAt     time.Time
	Outcome     string

	Map      ledger.MapSummary
	Seeders  []ledger.SeederStatus
	Findings []finding.Finding // ranked; includes dismissed and fixed
	Skipped  []ledger.BudgetSkip
	// Rejected lists work that produced nothing: an investigation that
	// failed or whose draft was refused, and leads dropped at validation.
	Rejected []ledger.Reject
	Notes    []string
	Usage    Usage
}

// Usage totals the run's accounting.
type Usage struct {
	ModelCalls   int
	InputTokens  int
	OutputTokens int
	CostUSD      float64
	// Estimated is true when any call's token counts were estimated.
	Estimated bool
	// CostKnown is false when any call used a model with no known price.
	CostKnown   bool
	SandboxRuns int
	Leads       int
}

// Counts summarizes findings by severity label for open findings.
type Counts struct {
	Critical, High, Medium, Low, None int
	Open, Fixed, Dismissed            int
	Demonstrated                      int
}

// Count tallies the run's findings.
func (r Run) Count() Counts {
	var c Counts
	for _, f := range r.Findings {
		switch f.Status {
		case finding.StatusDismissed:
			c.Dismissed++
			continue
		case finding.StatusFixed:
			c.Fixed++
		default:
			c.Open++
		}
		if f.Proof.Status == finding.ProofDemonstrated {
			c.Demonstrated++
		}
		switch f.Severity.Label {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		default:
			c.None++
		}
	}
	return c
}

// Active returns the findings that are not dismissed, in rank order.
func (r Run) Active() []finding.Finding {
	var out []finding.Finding
	for _, f := range r.Findings {
		if f.Status != finding.StatusDismissed {
			out = append(out, f)
		}
	}
	return out
}

// Dismissed returns the findings the reviewer refuted, in rank order.
func (r Run) Dismissed() []finding.Finding {
	var out []finding.Finding
	for _, f := range r.Findings {
		if f.Status == finding.StatusDismissed {
			out = append(out, f)
		}
	}
	return out
}

// Load builds a Run from the ledger in runDir and nothing else.
func Load(runDir string) (Run, error) {
	events, err := ledger.Read(runDir)
	if err != nil {
		return Run{}, err
	}
	if len(events) == 0 {
		return Run{}, fmt.Errorf("ledger in %s is empty: the run did not start; run the scan again", runDir)
	}
	run := Run{Usage: Usage{CostKnown: true}}
	latest := map[string]finding.Finding{}
	var order []string
	sawStart := false

	for _, ev := range events {
		switch ev.Type {
		case ledger.TypeRunStart:
			var d ledger.RunStart
			if err := ev.Decode(&d); err != nil {
				return Run{}, err
			}
			if !sawStart {
				run.ID, run.Version, run.Command = d.RunID, d.Version, d.Command
				run.Target, run.TargetKind, run.Commit, run.TargetPath = d.Target, d.TargetKind, d.Commit, d.TargetPath
				run.RepoPrefix = d.RepoPrefix
				run.Mode, run.Provider, run.Model, run.Offline = d.Mode, d.Provider, d.Model, d.Offline
				run.Scope, run.ScopeSource, run.Isolation = d.Scope, d.ScopeSource, d.Isolation
				run.StartedAt = ev.TS
				sawStart = true
			}
		case ledger.TypeMap:
			if err := ev.Decode(&run.Map); err != nil {
				return Run{}, err
			}
		case ledger.TypeSeeder:
			var d ledger.SeederStatus
			if err := ev.Decode(&d); err != nil {
				return Run{}, err
			}
			run.Seeders = append(run.Seeders, d)
		case ledger.TypeLead:
			run.Usage.Leads++
		case ledger.TypeModelCall:
			var d ledger.ModelCall
			if err := ev.Decode(&d); err != nil {
				return Run{}, err
			}
			run.Usage.ModelCalls++
			run.Usage.InputTokens += d.InputTokens
			run.Usage.OutputTokens += d.OutputTokens
			run.Usage.CostUSD += d.CostUSD
			run.Usage.Estimated = run.Usage.Estimated || d.Estimated
			run.Usage.CostKnown = run.Usage.CostKnown && d.CostKnown
		case ledger.TypeSandboxRun:
			run.Usage.SandboxRuns++
		case ledger.TypeFinding:
			var f finding.Finding
			if err := ev.Decode(&f); err != nil {
				return Run{}, err
			}
			if _, seen := latest[f.ID]; !seen {
				order = append(order, f.ID)
			}
			latest[f.ID] = f
		case ledger.TypeBudgetSkip:
			var d ledger.BudgetSkip
			if err := ev.Decode(&d); err != nil {
				return Run{}, err
			}
			run.Skipped = append(run.Skipped, d)
		case ledger.TypeReject:
			var d ledger.Reject
			if err := ev.Decode(&d); err != nil {
				return Run{}, err
			}
			run.Rejected = append(run.Rejected, d)
		case ledger.TypeNote:
			var s string
			if err := ev.Decode(&s); err != nil {
				return Run{}, err
			}
			run.Notes = append(run.Notes, s)
		case ledger.TypeRunEnd:
			var d ledger.RunEnd
			if err := ev.Decode(&d); err != nil {
				return Run{}, err
			}
			run.Outcome = d.Outcome
			run.EndedAt = ev.TS
		}
	}
	if !sawStart {
		return Run{}, fmt.Errorf("ledger in %s has no run.start event: it is not a Spackle run", runDir)
	}
	if run.Outcome == "" {
		run.Outcome = "incomplete"
		run.EndedAt = events[len(events)-1].TS
	}
	fs := make([]finding.Finding, 0, len(order))
	for _, id := range order {
		fs = append(fs, latest[id])
	}
	run.Findings = finding.Rank(fs)
	sort.SliceStable(run.Seeders, func(i, j int) bool { return run.Seeders[i].Name < run.Seeders[j].Name })
	return run, nil
}

// renderer writes one format.
type renderer struct {
	ext string
	fn  func(Run, io.Writer) error
}

var renderers = map[string]renderer{
	"terminal": {"txt", renderTerminal},
	"markdown": {"md", renderMarkdown},
	"html":     {"html", renderHTML},
	"json":     {"json", renderJSON},
	"sarif":    {"sarif", renderSARIF},
}

// Formats lists the supported format names in a fixed order.
func Formats() []string {
	return []string{"terminal", "markdown", "html", "json", "sarif"}
}

// Ext returns the file extension for a format, without the dot.
func Ext(format string) (string, bool) {
	r, ok := renderers[normalize(format)]
	return r.ext, ok
}

func normalize(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "md":
		return "markdown"
	case "text", "txt", "term":
		return "terminal"
	}
	return f
}

// Render writes the run in the named format.
func Render(format string, run Run, w io.Writer) error {
	r, ok := renderers[normalize(format)]
	if !ok {
		return fmt.Errorf("unknown report format %q: choose one of %s", format, strings.Join(Formats(), ", "))
	}
	return r.fn(run, w)
}
