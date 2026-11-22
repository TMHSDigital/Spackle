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
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/report"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/target"
	"github.com/TMHSDigital/spackle/internal/version"
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
}

// Result identifies a finished run.
type Result struct {
	RunID  string
	RunDir string
	Run    report.Run
}

// RunsDir returns the directory that holds runs for a state directory.
func RunsDir(stateDir string) string { return filepath.Join(stateDir, "runs") }

// NewRunID returns an id of the form 20261122-153045-a1b2c3.
func NewRunID(now time.Time) (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate run id: %w", err)
	}
	return now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:]), nil
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

type runner struct {
	opts     Options
	cfg      config.Config
	led      *ledger.Writer
	runDir   string
	runID    string
	progress io.Writer
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
	tgt, err := target.Classify(opts.Target)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if tgt.Live() {
		return Result{}, fmt.Errorf("%w: %s is a live target. Running-target analysis is not in this build yet; scan the application's source directory instead", ErrRefused, tgt.Display)
	}

	runID := opts.RunID
	if runID == "" {
		if runID, err = NewRunID(clock()); err != nil {
			return Result{}, err
		}
	}
	stateDir := opts.Config.StateDir
	runDir := filepath.Join(RunsDir(stateDir), runID)
	led, err := ledger.Create(runDir, clock)
	if err != nil {
		return Result{}, err
	}
	r := &runner{opts: opts, cfg: opts.Config, led: led, runDir: runDir, runID: runID, progress: opts.Progress}
	defer func() { _ = led.Close() }()

	root := tgt.Raw
	if tgt.Kind == target.KindGit {
		root = filepath.Join(stateDir, "clones", runID)
		r.say("Cloning %s", tgt.Display)
		if err := gitx.Clone(ctx, tgt.Raw, root); err != nil {
			return Result{}, r.fail(err)
		}
	}
	commit, _ := gitx.HeadSHA(ctx, root)

	start := ledger.RunStart{
		RunID: runID, Version: version.Version, Command: "scan",
		Target: tgt.Display, TargetKind: string(tgt.Kind), Commit: commit,
		Mode: "deterministic", Offline: r.cfg.Offline,
		Isolation: "not used: no proof of concept was run",
	}
	startSeq, err := led.Append(0, ledger.TypeRunStart, start)
	if err != nil {
		return Result{}, err
	}

	r.say("Mapping %s", tgt.Display)
	m, err := mapper.Build(ctx, root, mapper.Options{CacheDir: filepath.Join(stateDir, "cache")})
	if err != nil {
		return Result{}, r.fail(err)
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

	seeders := opts.Seeders
	if seeders == nil {
		seeders = seed.All()
	}
	r.say("Running %d seeders", len(seeders))
	leads, statuses := seed.RunAll(ctx, seeders, root, m.Files)
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

	// With no model, each lead is reported as a plausible finding.
	var findings []finding.Finding
	parent := map[string]int64{}
	for _, l := range leads {
		f := FromLead(l, "No model is configured, so this lead was not investigated or demonstrated.")
		if err := f.Validate(); err != nil {
			if _, aerr := led.Append(leadSeq[l.ID], ledger.TypeReject, ledger.Reject{Stage: "seed", Intent: l.ID, Reason: err.Error()}); aerr != nil {
				return Result{}, aerr
			}
			continue
		}
		if _, seen := parent[f.ID]; !seen {
			parent[f.ID] = leadSeq[l.ID]
		}
		findings = append(findings, f)
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
		if _, err := led.Append(parent[f.ID], ledger.TypeFinding, f); err != nil {
			return Result{}, err
		}
	}

	if _, err := led.Append(startSeq, ledger.TypeRunEnd, ledger.RunEnd{Outcome: "completed"}); err != nil {
		return Result{}, err
	}
	if err := led.Close(); err != nil {
		return Result{}, err
	}
	return finish(runDir, runID)
}

// fail records a failed run in the ledger and returns the error.
func (r *runner) fail(err error) error {
	_, _ = r.led.Append(0, ledger.TypeRunEnd, ledger.RunEnd{Outcome: "failed", Note: err.Error()})
	return err
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
// review.md when present) and reports/report.<ext> for every format.
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
		ID: finding.MakeID(l.Class, loc), Title: l.Title, Surface: surface, Class: l.Class,
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
		f.Exploitation.Steps = append([]string{"Typical for this class of flaw; not confirmed for this code:"}, info.Steps...)
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
