// Package engine runs the Spackle pipeline for one target and writes the
// run's ledger, evidence folders and reports.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/report"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/seed"
)

// ErrRefused marks a run that was refused before it started (bad target,
// missing authorization). The CLI maps it to the usage exit code.
var ErrRefused = errors.New("run refused")

// Options configure one run.
type Options struct {
	Target string
	Config config.Config
	// Progress receives one-line status messages. Nil discards them.
	Progress io.Writer
	// Seeders overrides the seeder set; nil means seed.All().
	Seeders []seed.Seeder
	// Clock and RunID make runs reproducible in tests.
	Clock func() time.Time
	RunID string
	// Confirm is asked before a run that will call a model. It receives the
	// estimate and returns whether to proceed. Nil means proceed without
	// asking (the caller has already handled --yes).
	Confirm func(Estimate) bool
	// ProviderFactory overrides how model providers are built, for tests.
	ProviderFactory func(config.Model) (llm.Provider, error)
	// DryRun stops after mapping and seeding: Result.Plan says what would
	// be scanned and what it would cost. No model is called and no run
	// directory is written.
	DryRun bool
	// Ref is the branch or tag to scan for a git URL target. Empty means
	// the remote's default branch.
	Ref string
	// RoutesFrom is a local directory holding the source of a running
	// target. Its HTTP routes, as the mapper finds them, are added to the
	// crawl next to the start URL. Only for a running target.
	RoutesFrom string
	// Since limits a scan of a directory to the files changed since this
	// revision (see gitx.ChangedSince). Empty scans everything.
	Since string
	// Changed limits a scan of a directory to the files that differ from
	// HEAD, staged or not, and the untracked files git does not ignore: a
	// pre-commit scan (see gitx.ChangedUncommitted). It excludes Since.
	Changed bool
	// DiffScope narrows a diff scan (Since or Changed): DiffScopeFile, the
	// default, reports every lead in a changed file; DiffScopeLines reports
	// only leads on the changed lines. Empty means DiffScopeFile, or, for
	// a resumed run, the scope of the run it continues.
	DiffScope string
	// Resume is the id of a stored scan to continue ("latest" for the
	// newest): its remaining investigations are run with a fresh budget
	// and its findings are carried into the new run. Force allows that
	// when the target's commit has changed since.
	Resume string
	Force  bool
	// ScopeFile is the --authorize scope file for a live target.
	ScopeFile string
	// Yes is true for --yes and CI: never prompt for authorization.
	Yes bool
	// Interactive is true when Stdin is a terminal a person can answer on.
	Interactive bool
	// Stdin is read for the interactive scope confirmation.
	Stdin io.Reader
	// OpenPR overrides how a pull request is opened for --pr, for tests.
	OpenPR func(ctx context.Context, req gitx.PRRequest) (string, error)
	// DetectRuntime overrides container runtime detection, for tests.
	DetectRuntime func(ctx context.Context, preferred string) (sandbox.Runtime, error)

	// baseline is the loaded [scan] baseline, set by Run; nil without one.
	baseline *finding.BaselineMatcher
}

// Result identifies a finished run.
type Result struct {
	RunID  string
	RunDir string
	Run    report.Run
	// Plan is set, and nothing else is, for a dry run.
	Plan *Plan
}

// Plan is what a dry run reports: what a scan of the target would read and
// do, without doing the part that costs money or writes a run.
type Plan struct {
	Target     string        `json:"target"`
	TargetKind string        `json:"target_kind"`
	Mode       string        `json:"mode"` // deterministic|agentic
	Files      int           `json:"files"`
	Languages  []string      `json:"languages"`
	NotRead    []string      `json:"not_read"`
	Seeders    []seed.Status `json:"seeders"`
	Leads      int           `json:"leads"`
	// LeadsByClass and LeadsBySeverity count the leads; the severity is
	// the seeder's hint, not a computed score.
	LeadsByClass    map[string]int `json:"leads_by_class"`
	LeadsBySeverity map[string]int `json:"leads_by_severity"`
	// Investigations is how many the planner would be asked for at most.
	// It is 0 in deterministic mode.
	Investigations int      `json:"investigations"`
	Model          string   `json:"model,omitempty"`
	Estimate       string   `json:"estimate"`
	Notes          []string `json:"notes"`
}

// RunsDir returns the directory that holds runs for a state directory.
func RunsDir(stateDir string) string { return filepath.Join(stateDir, "runs") }

// NewRunID returns an id of the form 20261122-153045-00a1b2: the UTC start
// time to the second, a sequence number in two hex digits, and two random
// bytes. The sequence number is one more than the highest among the runs in
// stateDir that started in the same second, so ids sort in the order the
// runs were started, which "latest" and every listing rely on. It stops at
// ff. Runs started at the same moment by two processes share a sequence
// number, and the random bytes keep their ids apart.
func NewRunID(stateDir string, now time.Time) (string, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate run id: %w", err)
	}
	stamp := now.UTC().Format("20060102-150405") + "-"
	seq := 0
	// A runs directory that does not exist yet has no earlier runs.
	entries, _ := os.ReadDir(RunsDir(stateDir))
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), stamp)
		if !ok || len(rest) < 2 {
			continue
		}
		if n, err := strconv.ParseUint(rest[:2], 16, 8); err == nil && int(n) >= seq {
			seq = min(int(n)+1, 0xff)
		}
	}
	return fmt.Sprintf("%s%02x%s", stamp, seq, hex.EncodeToString(b[:])), nil
}

// ResolveRun finds a run directory by id, accepting a unique prefix or the
// word "latest".
func ResolveRun(stateDir, id string) (string, error) {
	dir := RunsDir(stateDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("no runs found in %s: run \"spackle scan\" first, or pass --config if your state directory is elsewhere", dir)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no runs found in %s: run \"spackle scan\" first", dir)
	}
	if id == "" || id == "latest" {
		// Run ids start with a UTC timestamp, so the last name is the newest.
		return filepath.Join(dir, names[len(names)-1]), nil
	}
	var matches []string
	for _, n := range names {
		if n == id {
			return filepath.Join(dir, n), nil
		}
		if strings.HasPrefix(n, id) {
			matches = append(matches, n)
		}
	}
	switch len(matches) {
	case 1:
		return filepath.Join(dir, matches[0]), nil
	case 0:
		return "", fmt.Errorf("run %q not found in %s: the most recent run is %s", id, dir, names[len(names)-1])
	default:
		return "", fmt.Errorf("run id %q is ambiguous: it matches %s", id, strings.Join(matches, ", "))
	}
}

// fail records a failed run in the ledger and returns the error.
func (r *runner) fail(err error) error {
	if !r.ended {
		r.ended = true
		_, _ = r.led.Append(0, ledger.TypeRunEnd, ledger.RunEnd{Outcome: ledger.OutcomeFailed, Note: err.Error()})
	}
	return err
}

// endOnError is deferred by every mode as soon as the ledger is open, with
// a pointer to the function's error result. Whatever error ends the run
// from then on, the ledger gets a run.end event that says it failed, so the
// run never loads as "incomplete", which means the process died. It does
// nothing when the run already has its run.end.
func (r *runner) endOnError(err *error) {
	if *err != nil {
		_ = r.fail(*err)
	}
}

// end is the last step of every mode: it writes the run.end event, closes
// the ledger, and writes the reports and finding folders from it.
func (r *runner) end(startSeq int64, outcome string) (Result, error) {
	if _, err := r.led.Append(startSeq, ledger.TypeRunEnd, ledger.RunEnd{Outcome: outcome}); err != nil {
		return Result{}, err
	}
	r.ended = true
	if err := r.led.Close(); err != nil {
		return Result{}, err
	}
	return finish(r.runDir, r.runID)
}

// finish loads the run back from its ledger and writes the per-finding
// folders and the rendered reports. Everything here is derived from the
// ledger, so "spackle report" can reproduce it.
func finish(runDir, runID string) (Result, error) {
	run, err := report.Load(runDir)
	if err != nil {
		return Result{}, err
	}
	if err := WriteArtifacts(runDir, run); err != nil {
		return Result{}, err
	}
	return Result{RunID: runID, RunDir: runDir, Run: run}, nil
}

// WriteArtifacts writes findings/<id>/finding.json (plus fix.patch and
// review.md when present), reports/report.<ext> for every format, and the
// run summary that listings read.
func WriteArtifacts(runDir string, run report.Run) error {
	for _, f := range run.Findings {
		dir := filepath.Join(runDir, "findings", f.ID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("write finding folder: %w", err)
		}
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "finding.json"), append(b, '\n'), 0o600); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
		if f.Remediation.Patch != "" {
			patch := f.Remediation.Patch
			if !strings.HasSuffix(patch, "\n") {
				patch += "\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "fix.patch"), []byte(patch), 0o600); err != nil {
				return fmt.Errorf("write patch: %w", err)
			}
		}
		if f.Status == finding.StatusDismissed {
			review := "# Review of " + f.ID + "\n\nDismissed.\n\n" + f.DismissReason + "\n"
			if err := os.WriteFile(filepath.Join(dir, "review.md"), []byte(review), 0o600); err != nil {
				return fmt.Errorf("write review: %w", err)
			}
		}
	}
	repDir := filepath.Join(runDir, "reports")
	if err := os.MkdirAll(repDir, 0o700); err != nil {
		return fmt.Errorf("write reports: %w", err)
	}
	for _, format := range report.Formats() {
		ext, _ := report.Ext(format)
		if err := renderFile(filepath.Join(repDir, "report."+ext), format, run); err != nil {
			return err
		}
	}
	// Last, so the summary is only there when everything it stands for is.
	if err := report.WriteSummary(runDir, run); err != nil {
		return fmt.Errorf("write run summary: %w", err)
	}
	return nil
}

func renderFile(path, format string, run report.Run) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // path is inside the run directory
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return report.Render(format, run, f)
}

func isAppLanguage(lang string) bool {
	switch lang {
	case "shell", "powershell", "terraform", "dockerfile":
		return false
	}
	return true
}

// FromLead turns a lead into a finding at the lowest confidence level. It
// is used when no model investigates the lead.
func FromLead(l seed.Lead, notRunReason string) finding.Finding {
	loc := finding.Location{
		File: l.File, StartLine: l.Line, EndLine: l.EndLine,
		Method: l.Method, Endpoint: l.Endpoint, Parameter: l.Param,
	}
	surface := l.Surface
	if surface == "" {
		surface = finding.SurfaceCode
	}
	info := finding.Info(l.Class)
	owasp := l.OWASP
	if len(owasp) == 0 {
		owasp = info.OWASP
	}
	f := finding.Finding{
		ID: finding.MakeRuleID(l.Class, loc, l.RuleID), Title: l.Title, Surface: surface, Class: l.Class,
		CWE: l.CWE, OWASP: owasp, Location: loc,
		Severity: leadSeverity(l),
		Flaw:     finding.Flaw{Description: l.Detail},
		Exploitation: finding.Exploitation{
			Preconditions: info.Preconditions,
			Steps:         info.Steps,
			ChainsInto:    info.ChainsInto,
		},
		Proof: finding.Proof{Status: finding.ProofNotRun, Reason: notRunReason, Artifacts: l.Evidence},
		BlastRadius: finding.BlastRadius{
			Gains: info.Gains,
		},
		Remediation: finding.Remediation{Summary: l.Fix, Verification: "unverified"},
		Confidence: finding.Confidence{
			Level:  finding.ConfidencePlausible,
			Reason: fmt.Sprintf("Reported by %s rule %s. Not confirmed: reachability and impact were not investigated.", l.Source, l.RuleID),
		},
		Origin: []string{l.Source + ":" + l.RuleID},
		Status: finding.StatusOpen,
	}
	if len(info.Steps) > 0 {
		// These steps are class knowledge, not an analysis of this code.
		// Say so in the text itself, so no reader mistakes one for the other.
		steps := append([]string(nil), info.Steps...)
		steps[0] += " (these steps are typical for this class of flaw; they were not confirmed for this code)"
		f.Exploitation.Steps = steps
	}
	if l.Snippet != "" {
		f.Flaw.Flow = []finding.FlowStep{{Role: "sink", File: l.File, Line: l.Line, Quote: l.Snippet}}
	}
	if f.Remediation.Summary == "" {
		f.Remediation.Summary = info.Fix
	}
	return f
}

// leadSeverity scores a lead. The class has a default CVSS 4.0 vector; it
// is used when it roughly agrees with the seeder's own severity hint. When
// they clearly disagree the finding is marked unscored with the seeder's label, because
// inventing a vector to fit a label would make the score meaningless.
func leadSeverity(l seed.Lead) finding.Severity {
	hint := strings.ToLower(l.Severity)
	if finding.LabelRank(hint) < 1 {
		hint = "medium"
	}
	vec, ok := finding.DefaultVector(l.Class)
	if !ok {
		return finding.Severity{Label: hint, Unscored: true, Reasoning: "Estimate from the seeder. No CVSS vector: the class has no default and the lead was not investigated."}
	}
	sev, err := finding.SeverityFromVector(vec, "Default CVSS 4.0 vector for this class, assuming the flaw is reachable as it typically is. Not refined by investigation.")
	// One level of difference is within the noise of a rule author's label
	// versus a scored vector, so the vector wins. Two or more levels means
	// the class default describes a different situation from this instance.
	gap := finding.LabelRank(sev.Label) - finding.LabelRank(hint)
	if err != nil || gap > 1 || gap < -1 {
		return finding.Severity{
			Label: hint, Unscored: true,
			Reasoning: fmt.Sprintf("Estimate from the seeder (%s). The default vector for class %s does not fit this instance, and the lead was not investigated, so no CVSS score is given.", hint, l.Class),
		}
	}
	return sev
}
