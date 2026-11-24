package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/agent"
	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/gitx"
	proglang "github.com/TMHSDigital/spackle/internal/lang"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/target"
	"github.com/TMHSDigital/spackle/internal/textx"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// DebugOptions configure one debug run.
type DebugOptions struct {
	// Target is a local directory. Git URLs and live URLs are refused.
	Target string
	// Test is the name of a failing test. Exactly one of Test and Issue is set.
	Test string
	// Issue is the text of an issue description. It is untrusted input.
	Issue string
	// Good is an optional known-good revision; it enables bisect.
	Good     string
	Config   config.Config
	Progress io.Writer
	// Clock and RunID make runs reproducible in tests.
	Clock func() time.Time
	RunID string
	// Confirm is asked before any model call. Nil means proceed.
	Confirm func(Estimate) bool
	// ProviderFactory overrides how model providers are built, for tests.
	ProviderFactory func(config.Model) (llm.Provider, error)
	// DetectRuntime overrides container runtime detection, for tests.
	DetectRuntime func(ctx context.Context, preferred string) (sandbox.Runtime, error)
}

// maxBisectProbes bounds the sandbox runs one bisect may use. Twelve probes
// cover a range of about two thousand commits.
const maxBisectProbes = 12

// maxIssueBytes bounds the issue text that is kept and sent to a model.
const maxIssueBytes = 64 << 10

var debugTestName = regexp.MustCompile(`^[A-Za-z0-9_./:\[\]-]{1,200}$`)

// reproduction is what the reproduce step learned.
type reproduction struct {
	// passes is set in test mode when the test passes: nothing to debug.
	passes     bool
	reproduced bool
	command    []string
	// output is redacted and clipped.
	output    string
	result    string // "exit code 1" or "timed out"
	isolation string
	// reason says why an issue was not reproduced.
	reason   string
	attempts int
	// poc is the model-written reproduction script in issue mode.
	poc *agent.PoC
}

// debugRun holds the state of one debug run after its ledger exists.
type debugRun struct {
	r     *runner
	l     *lab
	box   *agent.Box
	root  string
	lang  string
	image string
	m     mapper.Map
	test  string
	issue string
	good  string
	// seq is the ledger event every debug event descends from.
	seq int64
	// evidence lists the evidence file of every sandbox run, in order.
	evidence []string
}

// Debug starts from a failing test or an issue description, reproduces the
// failure in the sandbox, finds the root cause (bisecting when a good
// revision is given), writes a fix and verifies it. Nothing is executed
// outside the sandbox and the working tree is never modified.
func Debug(ctx context.Context, opts DebugOptions) (_ Result, err error) {
	clock := clockOr(opts.Clock)
	say := func(format string, a ...any) { progressf(opts.Progress, format, a...) }
	cfg := opts.Config
	test, issue := strings.TrimSpace(opts.Test), strings.TrimSpace(opts.Issue)
	switch {
	case test == "" && issue == "":
		return Result{}, fmt.Errorf("%w: debug needs something to start from. Pass --test <name> for a failing test, or --issue <file|text> for a problem description", ErrRefused)
	case test != "" && issue != "":
		return Result{}, fmt.Errorf("%w: --test and --issue were both given. Pass one: debug follows a single failure per run", ErrRefused)
	}
	// A leading dash is refused on top of the pattern so the name can never
	// be read as an option by the test runner.
	if test != "" && (!debugTestName.MatchString(test) || strings.HasPrefix(test, "-")) {
		return Result{}, fmt.Errorf("%w: the test name %q is not usable. A test name is 1 to 200 characters from letters, digits and _ . / : [ ] -, and does not start with a dash. Pass the name of one test, for example --test TestParseHeader", ErrRefused, textx.Clip(test, 80))
	}
	if strings.HasPrefix(opts.Good, "-") {
		return Result{}, fmt.Errorf("%w: --good %q is not a revision. Pass a commit hash, tag or branch that is known to be good", ErrRefused, textx.Clip(opts.Good, 80))
	}
	if len(issue) > maxIssueBytes {
		issue = issue[:maxIssueBytes]
	}
	tgt, err := target.Classify(opts.Target)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if tgt.Kind != target.KindPath {
		return Result{}, fmt.Errorf("%w: %s is not a local directory. Debug mode reproduces a failure in a copy of your working code, so it takes a directory only: clone the repository and pass its path", ErrRefused, tgt.Display)
	}
	root, err := filepath.Abs(tgt.Raw)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}

	say("Mapping %s", tgt.Display)
	m, err := mapper.Build(ctx, root, mapper.Options{CacheDir: filepath.Join(cfg.StateDir, "cache"), Walk: walkOptions(cfg)})
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	lang := m.Tests.Language
	proofLang, supported := proglang.Lookup(lang)
	if !supported {
		found := "no supported language was found"
		if names := m.LanguageNames(); len(names) > 0 {
			found = "the target is mostly " + names[0]
		}
		return Result{}, fmt.Errorf("%w: debug mode supports %s, and %s in %s. Point it at the directory that holds the project's source", ErrRefused, strings.Join(proglang.Names(), ", "), found, tgt.Display)
	}
	var reproCmd []string
	if test != "" {
		reproCmd = proofLang.SingleTest(m.Tests.TestCommand, test)
	}

	// Debug needs a model and a container runtime. Both are checked before a
	// run directory exists, so a refused run leaves nothing behind, and
	// nothing is ever run on the host instead.
	var missing []string
	provs := newProviders(cfg, opts.ProviderFactory)
	var prov llm.Provider
	switch {
	case !cfg.Model.Configured():
		missing = append(missing, "no model is configured (set [model] in spackle.toml, or pass --provider and --model)")
	default:
		var perr error
		if prov, perr = preflightModel(provs, config.StageFixer); perr != nil {
			missing = append(missing, "the configured model cannot be used ("+perr.Error()+")")
		}
	}
	rt, derr := detectRuntime(ctx, opts.DetectRuntime, cfg.Sandbox.Runtime)
	switch {
	case derr != nil:
		missing = append(missing, "no container runtime is available ("+derr.Error()+")")
	case rt == nil:
		missing = append(missing, "no container runtime is available")
	}
	if len(missing) > 0 {
		return Result{}, fmt.Errorf("%w: %s", ErrRefused, debugRefusal(missing, lang, m.Tests.TestCommand, reproCmd))
	}

	pricer := llm.NewPricer(llm.PricesFromConfig(cfg.Pricing))
	usd, known := pricer.EstimateCost(prov.Model(), prov.Local(), estInputPerIntent, estOutputPerIntent)
	if usd > cfg.Budget.USD {
		usd = cfg.Budget.USD
	}
	est := Estimate{Investigations: 1, Model: prov.Model(), USD: usd, CostKnown: known, Local: prov.Local(), CapUSD: cfg.Budget.USD, CapTokens: cfg.Budget.Tokens}
	say("%s", est.String())
	if err := confirmEstimate(cfg, cfg.ForStage(config.StageFixer), est, opts.Confirm); err != nil {
		return Result{}, err
	}

	runID, err := runIDFor(opts.RunID, cfg.StateDir, clock)
	if err != nil {
		return Result{}, err
	}
	// The runner's options are the part of a scan's options debug has.
	r, err := newRun(Options{Target: opts.Target, Config: cfg, Progress: opts.Progress}, cfg, runID, clock, provs)
	if err != nil {
		return Result{}, err
	}
	defer r.done(&err)
	led := r.led
	r.lab = r.newLab(root, m.Tests, rt, "")

	commit := ""
	if gitx.HasTracked(ctx, root) {
		commit, _ = gitx.HeadSHA(ctx, root)
	}
	startSeq, err := r.begin(ledger.RunStart{
		Command: "debug",
		Target:  tgt.Display, TargetKind: string(tgt.Kind), Commit: commit,
		// The absolute directory, so verify re-runs the reproduction here
		// wherever verify itself is run from.
		TargetPath: root,
		Mode:       "agentic", Provider: prov.Name(), Model: prov.Model(),
		Isolation: r.lab.isolation(),
	})
	if err != nil {
		return Result{}, err
	}
	mapSeq, err := led.Append(startSeq, ledger.TypeMap, mapSummary(m))
	if err != nil {
		return Result{}, err
	}

	if err := r.startAgents(); err != nil {
		return Result{}, err
	}
	newRegistry := r.registries(root, m.Files)
	prover, err := r.runnerFor(config.StageProver)
	if err != nil {
		return Result{}, err
	}
	fixer, err := r.runnerFor(config.StageFixer)
	if err != nil {
		return Result{}, err
	}

	d := &debugRun{r: r, l: r.lab, root: root, lang: lang, m: m, test: test, issue: issue, good: opts.Good, seq: mapSeq}
	// One box for the whole run, so evidence files are numbered in the
	// order the sandbox runs happened.
	d.box = r.lab.box("", mapSeq)
	record, n := d.box.Record, 0
	d.box.Record = func(purpose string, spec sandbox.Spec, res sandbox.Result) error {
		n++
		if rerr := record(purpose, spec, res); rerr != nil {
			return rerr
		}
		d.evidence = append(d.evidence, fmt.Sprintf("evidence/%02d-%s.txt", n, purpose))
		return nil
	}
	if d.image, err = r.lab.image(ctx, lang); err != nil {
		return Result{}, r.fail(fmt.Errorf("debug cannot start: %w. Set [sandbox.images] %s in spackle.toml to an image you can pull, or pull it by hand, and run again", err, lang))
	}

	outcome, f, err := d.investigate(ctx, reproCmd, prover, fixer, newRegistry)
	if err != nil {
		return Result{}, r.fail(err)
	}
	if f != nil {
		if verr := f.Validate(); verr != nil {
			// An invalid finding here is a Spackle bug, not a target problem.
			// Record it instead of reporting it.
			if _, aerr := led.Append(mapSeq, ledger.TypeReject, ledger.Reject{Stage: "engine", Intent: f.ID, Reason: verr.Error()}); aerr != nil {
				return Result{}, aerr
			}
		} else if _, aerr := led.Append(mapSeq, ledger.TypeFinding, *f); aerr != nil {
			return Result{}, aerr
		}
	}
	return r.end(startSeq, outcome)
}

// debugRefusal explains what debug mode lacks and what it could still
// determine, so the operator can run the reproduction themselves.
func debugRefusal(missing []string, lang, testCommand string, reproCmd []string) string {
	var b strings.Builder
	b.WriteString("debug mode needs both a model and a container runtime, and ")
	b.WriteString(strings.Join(missing, "; and "))
	b.WriteString(". Nothing was run, on the host or anywhere else. What Spackle could determine without them: the project's language is ")
	b.WriteString(lang)
	if testCommand != "" {
		b.WriteString("; its test command is \"" + testCommand + "\"")
	} else {
		b.WriteString("; no test command was found for it")
	}
	if reproCmd != nil {
		b.WriteString("; the reproduction command it would have run in the sandbox is \"" + strings.Join(reproCmd, " ") + "\", which you can run yourself from the project directory")
	} else {
		b.WriteString("; the reproduction would have been a script written by the model from the issue text, so there is no command to give")
	}
	b.WriteString(". Fix what is missing (\"spackle doctor\" shows the details) and run debug again")
	return b.String()
}

func (d *debugRun) note(format string, a ...any) error {
	_, err := d.r.led.Append(d.seq, ledger.TypeNote, fmt.Sprintf(format, a...))
	return err
}

// skip records what a reached cap left undone.
func (d *debugRun) skip(capErr error, skipped ...string) error {
	_, err := d.r.led.Append(d.seq, ledger.TypeBudgetSkip, ledger.BudgetSkip{Cap: capErr.Error(), Skipped: skipped})
	return err
}

// run executes one command in the sandbox against sourceDir plus files,
// through the run's box: every run counts against the sandbox cap, is
// bounded by the wall time left, and leaves an evidence file and a ledger
// event. It returns the evidence file's path relative to the run.
func (d *debugRun) run(ctx context.Context, purpose string, cmd []string, files map[string]string, sourceDir string) (sandbox.Result, string, error) {
	res, err := d.box.Exec(ctx, purpose, d.image, cmd, files, sourceDir)
	if err != nil {
		if errors.Is(err, budget.ErrExhausted) {
			return res, "", err
		}
		return res, "", fmt.Errorf("the sandbox could not run %q: %w", strings.Join(cmd, " "), err)
	}
	return res, d.evidence[len(d.evidence)-1], nil
}

func sandboxOutput(res sandbox.Result, limit int) string {
	out, _ := redact.Apply(strings.TrimSpace(res.Stdout + "\n" + res.Stderr))
	return textx.Clip(out, limit)
}

func sandboxResult(res sandbox.Result) string {
	if res.TimedOut {
		return "timed out"
	}
	return fmt.Sprintf("exit code %d", res.ExitCode)
}

// noTestMatched reports whether a test run selected no test at all, going by
// what each supported runner prints or returns in that case.
func noTestMatched(cmd []string, res sandbox.Result) bool {
	if res.TimedOut || len(cmd) == 0 {
		return false
	}
	out := res.Stdout + "\n" + res.Stderr
	switch {
	case cmd[0] == "go":
		// go test prints "[no tests to run]" for each package where the
		// pattern matched nothing, and exits 0. One package that ran a
		// test has a plain "ok" line or a failure.
		if res.ExitCode != 0 || !strings.Contains(out, "[no tests to run]") {
			return false
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "ok ") && !strings.Contains(line, "[no tests to run]") {
				return false
			}
		}
		return true
	case len(cmd) > 2 && cmd[2] == "pytest":
		return res.ExitCode == 5 // pytest: no tests were collected
	case len(cmd) > 2 && cmd[2] == "unittest":
		return strings.Contains(out, "NO TESTS RAN") || strings.Contains(out, "Ran 0 tests")
	case cmd[0] == "node":
		for _, line := range strings.Split(out, "\n") {
			if t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#")); t == "tests 0" {
				return true
			}
		}
	}
	return false
}

// stillFails reports whether a run of the reproduction shows the failure.
// For a test that is a non-zero exit or a timeout. For an issue script it is
// the marker, which the script prints only when it observed the problem:
// any sight of it counts, whatever the exit code, so this is deliberately
// looser than agent.JudgeProof. The callers that must not take a hung or
// killed script for an answer check Inconclusive first.
func (d *debugRun) stillFails(rep reproduction, res sandbox.Result) bool {
	if rep.poc != nil {
		return !res.TimedOut && strings.Contains(res.Stdout+res.Stderr, rep.poc.Marker)
	}
	return res.TimedOut || res.ExitCode != 0
}

// rerun runs the reproduction again, against another source directory or
// with patched files.
func (d *debugRun) rerun(ctx context.Context, purpose string, rep reproduction, files map[string]string, sourceDir string) (sandbox.Result, string, error) {
	all := files
	if rep.poc != nil {
		all = map[string]string{}
		for k, v := range files {
			all[k] = v
		}
		for k, v := range rep.poc.Files {
			all[k] = v
		}
	}
	return d.run(ctx, purpose, rep.command, all, sourceDir)
}

// investigate runs the debug steps in order and returns the run outcome and
// the finding, if there is one. Budget exhaustion is not an error here: it
// ends the run with what was learned.
func (d *debugRun) investigate(ctx context.Context, reproCmd []string, prover, fixer *agent.Runner, newRegistry func() *tools.Registry) (string, *finding.Finding, error) {
	rep, err := d.reproduce(ctx, reproCmd, prover, newRegistry)
	switch {
	case errors.Is(err, budget.ErrExhausted):
		return ledger.OutcomeBudgetExhausted, nil, d.skip(err, "Reproduction: not completed, so it is not known whether the failure reproduces.", "Root cause analysis and fix: not started.")
	case err != nil:
		return "", nil, err
	case rep.passes:
		return ledger.OutcomeCompleted, nil, d.note("The test %s passes on the current code, so there is nothing to debug.", d.test)
	case !rep.reproduced:
		f := d.notReproduced(rep)
		return ledger.OutcomeCompleted, &f, nil
	}

	bisect := ""
	outcome := ledger.OutcomeCompleted
	if d.good != "" {
		if bisect, err = d.bisect(ctx, rep); err != nil {
			if !errors.Is(err, budget.ErrExhausted) {
				return "", nil, err
			}
			outcome = ledger.OutcomeBudgetExhausted
			if err := d.skip(err, "Bisect: stopped early, so the first bad commit was not found."); err != nil {
				return "", nil, err
			}
		}
	}

	wantFix := d.r.cfg.Fix.On()
	if d.r.cfg.Fix.PR {
		if err := d.note("--pr is not used in debug mode: no pull request is opened. Push the fix branch yourself after reading the change."); err != nil {
			return "", nil, err
		}
	}
	var diag agent.Diagnosis
	derr := d.r.budget.Check()
	if derr == nil {
		d.r.say("Looking for the root cause")
		diag, derr = agent.Diagnose(ctx, fixer, d.seq, d.r.sealer, newRegistry(), d.root, d.failureText(rep, bisect), wantFix, d.r.cfg.Fix.MaxAttempts, d.check(rep))
	}
	switch {
	case derr == nil:
	case errors.Is(derr, budget.ErrExhausted):
		outcome = ledger.OutcomeBudgetExhausted
		left := "Root cause analysis and fix: not completed."
		if diag.RootCause != "" {
			left = "Fix: a root cause was found, but no fix was verified."
			if !wantFix {
				left = "Later steps were cut short."
			}
		}
		if err := d.skip(derr, left); err != nil {
			return "", nil, err
		}
		diag.Reason = "the budget ran out first (" + derr.Error() + ")"
	case ctx.Err() != nil:
		return "", nil, ctx.Err()
	default:
		// A provider failure should not discard a reproduced failure.
		diag.Reason = "the diagnosis step failed: " + textx.Clip(derr.Error(), 300)
	}

	f := d.finding(rep, bisect, diag, wantFix)
	if rep.poc != nil {
		// Stored like a proof, so "spackle verify" can re-run it later.
		if err := d.l.writePoC(f.ID, rep.poc); err != nil {
			return "", nil, err
		}
		for _, name := range rep.poc.SortedFiles() {
			f.Proof.Artifacts = append(f.Proof.Artifacts, "findings/"+f.ID+"/poc/"+name)
		}
	}
	if diag.Patch != "" {
		d.l.fixes = append(d.l.fixes, acceptedFix{id: f.ID, title: f.Title, files: diag.Files})
		branch, note := d.l.branchFixes(ctx)
		if note != "" {
			if err := d.note("%s", note); err != nil {
				return "", nil, err
			}
		}
		f.Remediation.Branch = branch
	}
	return outcome, &f, nil
}

// reproduce shows the failure in the sandbox: by running the named test, or
// by running a script the model writes from the issue.
func (d *debugRun) reproduce(ctx context.Context, reproCmd []string, prover *agent.Runner, newRegistry func() *tools.Registry) (reproduction, error) {
	if d.test != "" {
		d.r.say("Running %s in the sandbox", d.test)
		res, _, err := d.run(ctx, "repro", reproCmd, nil, d.root)
		if err != nil {
			return reproduction{}, err
		}
		if noTestMatched(reproCmd, res) {
			// The runner found no test by that name. Its exit status says
			// nothing about the code, so neither "fails" nor "passes" would
			// be true. Stop before a model is asked about it.
			return reproduction{}, fmt.Errorf("%w: no test named %q was found when running %q in the sandbox. Check the spelling of --test; it must name a test the project's own runner can select", ErrRefused, d.test, strings.Join(reproCmd, " "))
		}
		rep := reproduction{command: reproCmd, output: sandboxOutput(res, 4000), result: sandboxResult(res), isolation: res.Isolation, attempts: 1}
		rep.reproduced = d.stillFails(rep, res)
		rep.passes = !rep.reproduced
		return rep, nil
	}
	d.r.say("Reproducing the issue in the sandbox")
	proof, err := agent.Reproduce(ctx, prover, d.seq, d.r.sealer, newRegistry(), d.box, d.lang, d.image, d.issue)
	if err != nil {
		if errors.Is(err, budget.ErrExhausted) {
			return reproduction{}, err
		}
		if ctx.Err() != nil {
			return reproduction{}, ctx.Err()
		}
		proof.Reason = "The reproduction step failed: " + textx.Clip(err.Error(), 300)
	}
	rep := reproduction{reproduced: proof.Demonstrated, output: proof.Output, isolation: proof.Isolation, reason: proof.Reason, attempts: proof.Attempts, result: "exit code 0"}
	if proof.PoC != nil {
		rep.command = proof.PoC.Command
		if proof.Demonstrated {
			rep.poc = proof.PoC
		}
	}
	return rep, nil
}

// bisect finds the first commit that shows the failure, using the
// reproduction as the oracle. It returns a sentence for the finding, or ""
// when there is no result; the reason is then in a ledger note. Each commit
// is exported to a temporary directory: the working tree is never checked
// out or changed.
func (d *debugRun) bisect(ctx context.Context, rep reproduction) (string, error) {
	if !gitx.HasTracked(ctx, d.root) {
		return "", d.note("Bisect was skipped: the target's files are not tracked by git, so there is no history to search.")
	}
	list, err := gitx.RevList(ctx, d.root, d.good, "HEAD")
	if err != nil {
		return "", d.note("Bisect was skipped: git could not list the commits from %s to HEAD (%s). Check that --good names a commit that HEAD descends from.", d.good, textx.Clip(err.Error(), 200))
	}
	if len(list) == 0 {
		return "", d.note("Bisect was skipped: there are no commits between %s and HEAD.", d.good)
	}
	d.r.say("Bisecting %d commit(s) between %s and HEAD", len(list), d.good)

	// stopped turns a probe error into a note, unless it is a cancellation
	// or a reached cap, which the caller handles.
	stopped := func(perr error) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if errors.Is(perr, budget.ErrExhausted) {
			return "", perr
		}
		return "", d.note("Bisect stopped early (%s), so the first bad commit was not found.", textx.Clip(perr.Error(), 300))
	}
	// The failure was reproduced in the working tree, which may hold
	// uncommitted changes. The search below takes HEAD as bad without
	// running it, so check that first: if the committed code is fine, no
	// commit is to blame.
	bad, perr := d.probe(ctx, rep, "HEAD")
	if perr != nil {
		return stopped(perr)
	}
	if !bad {
		return "", d.note("The committed code at HEAD does not show the failure, so it comes from changes in the working tree that are not committed. Bisect was skipped: no commit introduced it.")
	}
	bad, perr = d.probe(ctx, rep, d.good)
	if perr != nil {
		return stopped(perr)
	}
	if bad {
		return "", d.note("The given good revision %s also shows the failure, so it is not good. Bisect was skipped: pass an older revision to --good.", d.good)
	}
	// list is oldest first and its last element is HEAD, which is known bad.
	lo, hi := 0, len(list)-1
	for probes := 1; lo < hi; probes++ {
		if probes >= maxBisectProbes {
			return "", d.note("Bisect stopped at its cap of %d sandbox probes. The first bad commit is one of the %d commits from %s to %s.", maxBisectProbes, hi-lo+1, shortRev(list[lo]), shortRev(list[hi]))
		}
		mid := (lo + hi) / 2
		if bad, perr = d.probe(ctx, rep, list[mid]); perr != nil {
			return stopped(perr)
		}
		if bad {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	first := list[lo]
	result := fmt.Sprintf("Bisect from %s to HEAD: the failure first appears in commit %s", d.good, first)
	if entry := d.logEntry(ctx, first); entry != "" {
		result += " (" + entry + ")"
	}
	result += "."
	return result, d.note("%s", result)
}

// probe exports one commit and runs the reproduction against it.
func (d *debugRun) probe(ctx context.Context, rep reproduction, rev string) (bad bool, err error) {
	tmp, err := os.MkdirTemp("", "spackle-bisect-")
	if err != nil {
		return false, fmt.Errorf("create a directory for commit %s: %w", shortRev(rev), err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	// The sandbox user cannot enter the private temp directory itself, so
	// the commit is exported into a world-readable child of it.
	src, err := gitx.ExportDir(tmp)
	if err != nil {
		return false, fmt.Errorf("create a directory for commit %s: %w", shortRev(rev), err)
	}
	if err := gitx.Archive(ctx, d.root, rev, src); err != nil {
		return false, err
	}
	res, ev, err := d.rerun(ctx, "bisect", rep, nil, src)
	if err != nil {
		return false, err
	}
	if rep.poc != nil && res.Inconclusive() {
		return false, fmt.Errorf("the reproduction script %s at commit %s, which shows neither that the failure is there nor that it is not", agent.InconclusiveWhy(res), shortRev(rev))
	}
	// A commit from before the test was written has no test to run. Its exit
	// status says nothing about the code, so it is neither good nor bad.
	if rep.poc == nil && noTestMatched(rep.command, res) {
		return false, fmt.Errorf("the test %s does not exist at commit %s, so that commit can be judged neither good nor bad (%s). The test must exist at the --good revision: pass a later one, or add the test to a branch based on it", d.test, shortRev(rev), ev)
	}
	bad = d.stillFails(rep, res)
	verdict := "does not show the failure"
	if bad {
		verdict = "shows the failure"
	}
	return bad, d.note("Bisect: commit %s %s (%s).", shortRev(rev), verdict, ev)
}

func shortRev(rev string) string {
	if len(rev) > 12 && !strings.ContainsAny(rev, "/~^") {
		return rev[:12]
	}
	return rev
}

// logEntry returns the one-line log entry of a commit, or "" when it cannot
// be found. The entry is commit metadata, which is target content: it is
// redacted and clipped before it is stored.
func (d *debugRun) logEntry(ctx context.Context, hash string) string {
	out, err := gitx.Log(ctx, d.root, "", 5000)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		short, _, _ := strings.Cut(line, " ")
		if len(short) >= 4 && strings.HasPrefix(hash, short) {
			entry, _ := redact.Apply(line)
			return textx.Clip(entry, 200)
		}
	}
	return ""
}

// failureText is what the diagnosis step is told. All of it is target
// content or operator-supplied issue text, and all of it goes to the model
// inside one envelope.
func (d *debugRun) failureText(rep reproduction, bisect string) string {
	var b strings.Builder
	if d.test != "" {
		fmt.Fprintf(&b, "Failing test: %s\n", d.test)
	} else {
		fmt.Fprintf(&b, "Issue as reported:\n%s\n\n", d.issue)
		for _, name := range rep.poc.SortedFiles() {
			fmt.Fprintf(&b, "Reproduction script %s:\n%s\n", name, textx.Clip(rep.poc.Files[name], 6000))
		}
		b.WriteString("The script prints a marker only when it observes the problem, and it printed it.\n")
	}
	fmt.Fprintf(&b, "Reproduction command: %s\nResult: %s\nOutput:\n%s\n", strings.Join(rep.command, " "), rep.result, rep.output)
	if bisect != "" {
		fmt.Fprintf(&b, "\n%s\n", bisect)
	}
	return b.String()
}

// check verifies one candidate fix in the sandbox, on a copy of the target
// with the patched files: the changed files compile, the reproduction no
// longer fails, and the project's own tests pass when it has a test command.
func (d *debugRun) check(rep reproduction) agent.Check {
	return func(ctx context.Context, files map[string]string) (problem, verification string, verified bool, err error) {
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, n)
		}
		sort.Strings(names)
		var checked []string
		proofLang, _ := proglang.Lookup(d.lang)
		if cmd := proofLang.CompileCheck(names); cmd != nil {
			res, _, rerr := d.run(ctx, "fix-compile", cmd, files, d.root)
			if rerr != nil {
				return "", "", false, rerr
			}
			if res.ExitCode != 0 || res.TimedOut {
				return "the patched code does not compile or parse:\n" + sandboxOutput(res, 1200), "", false, nil
			}
			checked = append(checked, "the changed files compile")
		}

		res, _, rerr := d.rerun(ctx, "fix-verify", rep, files, d.root)
		if rerr != nil {
			return "", "", false, rerr
		}
		if rep.poc != nil && res.Inconclusive() {
			return "the reproduction script " + agent.InconclusiveWhy(res) + " against the patched code, so it does not show that the cause is gone. The patch must leave the program running normally", "", false, nil
		}
		if d.stillFails(rep, res) {
			if rep.poc != nil {
				return "the reproduction script still shows the problem against the patched code, so the cause is still there:\n" + sandboxOutput(res, 1200), "", false, nil
			}
			return fmt.Sprintf("the test %s still fails against the patched code (%s):\n%s", d.test, sandboxResult(res), sandboxOutput(res, 1200)), "", false, nil
		}
		if rep.poc != nil {
			checked = append(checked, "the reproduction no longer shows the problem")
		} else {
			checked = append(checked, "the test "+d.test+" now passes")
		}

		// The test command is one of a fixed set the mapper chooses; it is
		// never taken from target content.
		if suite := strings.Fields(d.m.Tests.TestCommand); len(suite) > 0 {
			res, ev, rerr := d.run(ctx, "fix-tests", suite, files, d.root)
			if rerr != nil {
				return "", "", false, rerr
			}
			if res.ExitCode != 0 || res.TimedOut {
				return "", "unverified: the failure is fixed but the full test suite does not pass; check " + ev, false, nil
			}
			checked = append(checked, "the full test suite passes")
		} else {
			checked = append(checked, "no test suite was found to run")
		}
		return "", "verified: " + strings.Join(checked, "; "), true, nil
	}
}

var debugSeverity = finding.Severity{Label: "none", Unscored: true, Reasoning: "A functional bug found in debug mode; not scored as a vulnerability."}

// firstSource is the fallback location: the first mapped file in the
// project's primary language, or the first mapped file of any kind.
func (d *debugRun) firstSource() string {
	for _, f := range d.m.Files {
		if f.Lang == d.lang {
			return f.Rel
		}
	}
	if len(d.m.Files) > 0 {
		return d.m.Files[0].Rel
	}
	return ""
}

func (d *debugRun) origin() []string {
	if d.test != "" {
		return []string{"debug:test"}
	}
	return []string{"debug:issue"}
}

// notReproduced reports an issue the model could not reproduce. It is the
// weakest thing debug mode says: nothing was shown, so nothing is fixed.
func (d *debugRun) notReproduced(rep reproduction) finding.Finding {
	loc := finding.Location{File: d.firstSource()}
	issue, _ := redact.Apply(d.issue)
	reason := strings.TrimSpace(rep.reason)
	if reason == "" {
		reason = "No reproduction was produced."
	}
	return finding.Finding{
		ID: finding.MakeID("bug", loc), Title: "Reported issue was not reproduced", Surface: finding.SurfaceDebug, Class: "bug",
		Location: loc, Severity: debugSeverity,
		Flaw: finding.Flaw{Description: fmt.Sprintf("The reported issue could not be reproduced in the sandbox in %d attempt(s). %s The location is only where the project's source starts, not a diagnosis. Issue as reported: %s", rep.attempts, reason, textx.Clip(issue, 1200))},
		Proof: finding.Proof{
			Status: finding.ProofNotRun, Command: strings.Join(rep.command, " "), Result: rep.output, Artifacts: d.evidence,
			Reason: "No reproduction showed the problem. " + reason,
		},
		Remediation: finding.Remediation{
			Summary:      "No fix was attempted, because the issue was not reproduced. Add the exact input, the expected result and the actual result to the issue, or write a failing test and pass it with --test.",
			Verification: "not attempted: the issue was not reproduced",
		},
		Confidence: finding.Confidence{Level: finding.ConfidencePlausible, Reason: "The issue is reported but was not reproduced, so it is not confirmed."},
		Origin:     d.origin(), Status: finding.StatusOpen,
	}
}

// finding builds the one finding of a reproduced failure.
func (d *debugRun) finding(rep reproduction, bisect string, diag agent.Diagnosis, wantFix bool) finding.Finding {
	loc := finding.Location{File: d.firstSource()}
	changed := make([]string, 0, len(diag.Files))
	for n := range diag.Files {
		changed = append(changed, n)
	}
	sort.Strings(changed)
	switch {
	case len(changed) > 0:
		loc = finding.Location{File: changed[0]}
		if diag.File == changed[0] {
			loc.StartLine = diag.Line
		}
	case diag.File != "":
		if _, err := walk.Resolve(d.root, diag.File); err == nil {
			loc = finding.Location{File: diag.File, StartLine: diag.Line}
		}
	}

	title, desc := diag.Title, diag.RootCause
	if title == "" {
		title = "Reported issue reproduced, root cause not determined"
		if d.test != "" {
			title = "Test " + d.test + " fails, root cause not determined"
		}
	}
	if desc == "" {
		desc = "The failure was reproduced in the sandbox, but no root cause was determined: " + strings.TrimSuffix(diag.Reason, ".") + ". The location is only where the project's source starts."
	}
	if bisect != "" {
		desc += " " + bisect
	}
	var flow []finding.FlowStep
	for _, q := range diag.Quotes {
		flow = append(flow, finding.FlowStep{Role: q.Role, File: q.File, Line: q.Line, Quote: q.Quote, Note: q.Note})
	}

	proof := finding.Proof{
		Status: finding.ProofDemonstrated, Kind: "test", Command: strings.Join(rep.command, " "), Result: rep.output,
		Summary:   fmt.Sprintf("The test %s fails when it is run in the sandbox (%s).", d.test, rep.result),
		Isolation: d.l.runtime.Name() + ": " + rep.isolation,
		Artifacts: append([]string(nil), d.evidence...),
	}
	if rep.poc != nil {
		proof.Kind = "script"
		proof.Summary = "A reproduction script written from the issue ran in the sandbox and observed the reported behavior."
		if rep.poc.Explanation != "" {
			proof.Summary = rep.poc.Explanation
		}
	}
	if strings.TrimSpace(proof.Result) == "" {
		proof.Result = "(the run produced no output; " + rep.result + ")"
	}

	rem := finding.Remediation{Summary: diag.FixSummary, Why: diag.Why, Patch: diag.Patch}
	status := finding.StatusOpen
	switch {
	case diag.Patch != "":
		rem.Verification = diag.Verification
		if diag.Verified {
			status = finding.StatusPatchAvailable
		}
	case !wantFix:
		rem.Verification = "not attempted: fixes are turned off (--no-fix), so the run stopped after the root cause"
	default:
		reason := strings.TrimSpace(diag.Reason)
		if reason == "" {
			reason = "no fix was produced"
		}
		rem.Verification = "no patch: " + reason
	}
	if rem.Summary == "" {
		rem.Summary = "No fix was written in this run. Start from the root cause above and the reproduction command, and re-run debug to check your change."
	}

	return finding.Finding{
		ID: finding.MakeID("bug", loc), Title: title, Surface: finding.SurfaceDebug, Class: "bug",
		Location: loc, Severity: debugSeverity,
		Flaw:  finding.Flaw{Description: desc, Flow: flow},
		Proof: proof, Remediation: rem,
		Confidence: finding.Confidence{
			Level:  finding.ConfidenceDemonstrated,
			Reason: "The failure was reproduced in the sandbox. The root cause is the model's reading of the code: check it against the quoted lines.",
		},
		Origin: d.origin(), Status: status,
	}
}
