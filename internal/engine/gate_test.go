package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/report"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/seed"
)

const gatePoCRel = "spackle_poc/poc.py"

// gateRuntime stands in for a container runtime in the fix gate and verify
// tests. Unlike fakeRuntime it also answers the project's test command, can
// report a missing image, and lets a test replace the outcome of a proof.
type gateRuntime struct {
	mu    sync.Mutex
	runs  []sandbox.Spec
	pulls int
	// imageAbsent makes ImagePresent report false until a pull succeeds.
	imageAbsent bool
	pullErr     error
	// baseline is the result of the test suite on the unmodified code, and
	// patched its result with a patch in place.
	baseline, patched sandbox.Result
	baselineErr       error
	// proof replaces the outcome of a proof run when set. By default a proof
	// prints its own content, which holds the marker, unless app.py is
	// patched.
	proof func(spec sandbox.Spec) (sandbox.Result, error)
}

func (g *gateRuntime) Name() string { return "fake-runtime" }

func (g *gateRuntime) ImagePresent(context.Context, string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.imageAbsent
}

func (g *gateRuntime) Pull(context.Context, string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pulls++
	if g.pullErr != nil {
		return g.pullErr
	}
	g.imageAbsent = false
	return nil
}

// gateKind names what a sandbox spec is for, from its command and files.
func gateKind(spec sandbox.Spec) string {
	_, patched := spec.Files["app.py"]
	_, hasPoC := spec.Files[gatePoCRel]
	switch {
	case len(spec.Cmd) > 2 && spec.Cmd[2] == "py_compile":
		return "compile"
	case len(spec.Cmd) > 2 && spec.Cmd[2] == "pytest" && patched:
		return "tests-patched"
	case len(spec.Cmd) > 2 && spec.Cmd[2] == "pytest":
		return "tests-baseline"
	case hasPoC && patched:
		return "proof-patched"
	case hasPoC:
		return "proof"
	}
	return "other"
}

func (g *gateRuntime) Run(_ context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.runs = append(g.runs, spec)
	iso := spec.Profile.WithDefaults().Summary()
	res := sandbox.Result{Isolation: iso}
	var err error
	switch kind := gateKind(spec); kind {
	case "tests-baseline":
		res, err = g.baseline, g.baselineErr
	case "tests-patched":
		res = g.patched
	case "proof", "proof-patched":
		switch {
		case g.proof != nil:
			res, err = g.proof(spec)
		case kind == "proof-patched":
			res.ExitCode, res.Stdout = 1, "AssertionError: the injected row was not returned"
		default:
			res.Stdout = spec.Files[gatePoCRel]
		}
	}
	res.Isolation = iso
	return res, err
}

// kinds lists what the runtime was asked to run, in order.
func (g *gateRuntime) kinds() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.runs))
	for _, spec := range g.runs {
		out = append(out, gateKind(spec))
	}
	return strings.Join(out, ",")
}

func (g *gateRuntime) runCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.runs)
}

func (g *gateRuntime) detect() func(context.Context, string) (sandbox.Runtime, error) {
	return func(context.Context, string) (sandbox.Runtime, error) { return g, nil }
}

// gateOpts is labOpts with the gate runtime. The target's parent is made a
// git ceiling so an enclosing repository is never taken for the target's.
func gateOpts(t *testing.T, rt *gateRuntime) Options {
	t.Helper()
	o := labOpts(t, &fakeRuntime{})
	o.DetectRuntime = rt.detect()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(o.Target))
	return o
}

func writeTargetFile(t *testing.T, o Options, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(o.Target, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// withSuite gives the target a pytest suite, so the mapper detects the test
// command "python -m pytest -q".
func withSuite(t *testing.T, o Options) Options {
	t.Helper()
	writeTargetFile(t, o, "requirements.txt", "pytest\n")
	writeTargetFile(t, o, "test_app.py", "from app import find\n\ndef test_find():\n    assert find is not None\n")
	return o
}

const otherPy = "import sqlite3\n\ndef find_other(q):\n    return db.execute(f\"SELECT * FROM u WHERE b = '{q}'\")\n"

func otherLead() seed.Lead {
	l := sqlLead()
	l.File, l.Snippet = "other.py", `return db.execute(f"SELECT * FROM u WHERE b = '{q}'")`
	return l
}

// withSecondFinding adds a second flaw in other.py and a model that reports
// both, so one run proves and fixes two findings.
func withSecondFinding(t *testing.T, o Options) Options {
	t.Helper()
	writeTargetFile(t, o, "other.py", otherPy)
	o.Seeders = []seed.Seeder{fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), otherLead()}}}
	plan := `{"intents":[` +
		`{"title":"find query","class":"sql-injection","hypothesis":"Does q reach SQL?","files":["app.py"],"lead_ids":["` + leadID(sqlLead(), "fake") + `"],"priority":1},` +
		`{"title":"second lookup","class":"sql-injection","hypothesis":"Does q reach the zzsecond statement?","files":["other.py"],"lead_ids":["` + leadID(otherLead(), "fake") + `"],"priority":2}]}`
	second, err := json.Marshal(map[string]any{"verdict": "finding", "finding": map[string]any{
		"title": "SQL injection in find_other", "class": "sql-injection", "cwe": []string{"CWE-89"},
		"file": "other.py", "start_line": 4, "end_line": 4, "symbol": "find_other",
		"cvss_vector": sqlVector, "severity_reasoning": "Network reachable.",
		"description":  "q is formatted into the SQL text of the second statement.",
		"flow":         []map[string]any{{"role": "sink", "file": "other.py", "line": 4, "quote": `return db.execute(f"SELECT * FROM u WHERE b = '{q}'")`}},
		"attack_steps": []string{"Send a q value that closes the literal"}, "gains": []string{"Read the table"},
		"fix_summary": "Bind q as a parameter.", "confidence": "high", "confidence_reason": "Read the sink and its caller.",
	}})
	if err != nil {
		t.Fatal(err)
	}
	base := labProvider()
	fake := llm.NewFake()
	fake.Handler = func(req llm.Request, n int) (llm.Response, error) {
		resp := llm.Response{StopReason: llm.StopEnd, Usage: llm.Usage{InputTokens: 100, OutputTokens: 50, CostKnown: true}}
		labStage := strings.Contains(req.System, "demonstrate one finding") || strings.Contains(req.System, "fix one finding")
		switch {
		case stageOf(req) == "planner":
			resp.Text = plan
		case stageOf(req) == "investigator" && !labStage && strings.Contains(req.Messages[0].Text, "zzsecond"):
			resp.Text = string(second)
		default:
			return base.Handler(req, n)
		}
		return resp, nil
	}
	o.ProviderFactory = agenticOpts(t, fake).ProviderFactory
	return o
}

func gateEvents(t *testing.T, runDir string) (runs []ledger.SandboxRun, verdicts []ledger.Verdict, skips []ledger.BudgetSkip) {
	t.Helper()
	events, err := ledger.Read(runDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		switch e.Type {
		case ledger.TypeSandboxRun:
			var d ledger.SandboxRun
			if err := e.Decode(&d); err != nil {
				t.Fatal(err)
			}
			runs = append(runs, d)
		case ledger.TypeVerdict:
			var d ledger.Verdict
			if err := e.Decode(&d); err != nil {
				t.Fatal(err)
			}
			verdicts = append(verdicts, d)
		case ledger.TypeBudgetSkip:
			var d ledger.BudgetSkip
			if err := e.Decode(&d); err != nil {
				t.Fatal(err)
			}
			skips = append(skips, d)
		}
	}
	return runs, verdicts, skips
}

func purposesOf(runs []ledger.SandboxRun) string {
	out := make([]string, 0, len(runs))
	for _, r := range runs {
		out = append(out, r.Purpose)
	}
	return strings.Join(out, ",")
}

// stageVerdicts returns the outcomes one stage recorded, in order.
func stageVerdicts(verdicts []ledger.Verdict, stage string) string {
	var out []string
	for _, v := range verdicts {
		if v.Stage == stage {
			out = append(out, v.Outcome)
		}
	}
	return strings.Join(out, ",")
}

func onlyFinding(t *testing.T, res Result) finding.Finding {
	t.Helper()
	if len(res.Run.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (notes: %v)", len(res.Run.Findings), res.Run.Notes)
	}
	f := res.Run.Findings[0]
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestScanRejectsAPatchThatBreaksAPassingSuite(t *testing.T) {
	rt := &gateRuntime{patched: sandbox.Result{ExitCode: 1, Stdout: "FAILED test_app.py::test_find - assert 0 == 1"}}
	o := withSuite(t, gateOpts(t, rt))
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	if f.Status != finding.StatusOpen || f.Remediation.Patch != "" {
		t.Fatalf("a patch that breaks a passing suite was accepted: status=%s patch=%q", f.Status, f.Remediation.Patch)
	}
	if !strings.HasPrefix(f.Remediation.Verification, "no patch: ") || !strings.Contains(f.Remediation.Verification, "passed before the patch and fail after it") {
		t.Fatalf("verification = %q", f.Remediation.Verification)
	}
	// The proof is real even though every patch was rejected.
	if f.Proof.Status != finding.ProofDemonstrated {
		t.Fatalf("proof = %s", f.Proof.Status)
	}
	if _, err := os.Stat(filepath.Join(res.RunDir, "findings", f.ID, "fix.patch")); err == nil {
		t.Fatal("a rejected patch was written to the run directory")
	}
	runs, verdicts, _ := gateEvents(t, res.RunDir)
	attempt := ",fix-compile,fix-verify,fix-tests"
	if got, want := purposesOf(runs), "poc,tests-baseline"+strings.Repeat(attempt, 3); got != want {
		t.Fatalf("sandbox purposes = %s, want %s", got, want)
	}
	if got := stageVerdicts(verdicts, "fixer"); got != "fix-rejected" {
		t.Fatalf("fixer verdicts = %q, want fix-rejected", got)
	}
	// The baseline ran on the unmodified code, each later run on the patch.
	if got, want := rt.kinds(), "proof,tests-baseline"+strings.Repeat(",compile,proof-patched,tests-patched", 3); got != want {
		t.Fatalf("sandbox runs = %s, want %s", got, want)
	}
}

func TestScanKeepsAPatchWhenThePassingSuiteStillPasses(t *testing.T) {
	rt := &gateRuntime{}
	o := withSuite(t, gateOpts(t, rt))
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	want := "verified: the changed files compile; the proof of concept no longer succeeds; the test suite still passes"
	if f.Status != finding.StatusPatchAvailable || f.Remediation.Verification != want || f.Remediation.Patch == "" {
		t.Fatalf("status=%s verification=%q patch=%q", f.Status, f.Remediation.Verification, f.Remediation.Patch)
	}
	runs, verdicts, _ := gateEvents(t, res.RunDir)
	if got := purposesOf(runs); got != "poc,tests-baseline,fix-compile,fix-verify,fix-tests" {
		t.Fatalf("sandbox purposes = %s", got)
	}
	if got := stageVerdicts(verdicts, "fixer"); got != "fixed" {
		t.Fatalf("fixer verdicts = %q", got)
	}
	if res.Run.Usage.SandboxRuns != 5 {
		t.Fatalf("sandbox runs = %d, want 5: the baseline run counts against the cap", res.Run.Usage.SandboxRuns)
	}
	// The baseline is the mapper's fixed command, run on the code as it is.
	base := rt.runs[1]
	if strings.Join(base.Cmd, " ") != "python -m pytest -q" || len(base.Files) != 0 || base.SourceDir != o.Target || base.Profile.Network != "none" {
		t.Fatalf("baseline spec = %+v", base)
	}
	if tests := rt.runs[4]; strings.Join(tests.Cmd, " ") != "python -m pytest -q" || tests.Files["app.py"] != fixedAppPy || len(tests.Files) != 1 {
		t.Fatalf("patched suite spec = %+v", tests)
	}
	// The baseline belongs to the run, not to one finding.
	if runs[1].FindingID != "" || runs[1].OutputRef != "evidence/01-tests-baseline.txt" {
		t.Fatalf("baseline event = %+v", runs[1])
	}
	evidence, err := os.ReadFile(filepath.Join(res.RunDir, "evidence", "01-tests-baseline.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(evidence), "purpose: tests-baseline") || !strings.Contains(string(evidence), "command: python -m pytest -q") {
		t.Fatalf("baseline evidence:\n%s", evidence)
	}
}

func TestScanDoesNotHoldAPatchToASuiteThatAlreadyFails(t *testing.T) {
	cases := []struct {
		name     string
		baseline sandbox.Result
	}{
		{"suite fails", sandbox.Result{ExitCode: 1, Stdout: "1 failed"}},
		{"suite times out", sandbox.Result{TimedOut: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The suite would also fail on the patch: it must not be run there.
			rt := &gateRuntime{baseline: tc.baseline, patched: sandbox.Result{ExitCode: 1}}
			res, err := Run(context.Background(), withSuite(t, gateOpts(t, rt)))
			if err != nil {
				t.Fatal(err)
			}
			f := onlyFinding(t, res)
			if f.Status != finding.StatusPatchAvailable || f.Remediation.Patch == "" {
				t.Fatalf("status=%s patch=%q verification=%q", f.Status, f.Remediation.Patch, f.Remediation.Verification)
			}
			if !strings.HasPrefix(f.Remediation.Verification, "verified: ") || !strings.Contains(f.Remediation.Verification, "the test suite was not used because it does not pass on the unmodified code") {
				t.Fatalf("verification = %q", f.Remediation.Verification)
			}
			runs, _, _ := gateEvents(t, res.RunDir)
			if got := purposesOf(runs); got != "poc,tests-baseline,fix-compile,fix-verify" {
				t.Fatalf("sandbox purposes = %s", got)
			}
			if strings.Contains(rt.kinds(), "tests-patched") {
				t.Fatalf("a failing suite was run against the patch: %s", rt.kinds())
			}
		})
	}
}

func TestScanContinuesWhenTheBaselineCannotBeRun(t *testing.T) {
	rt := &gateRuntime{baselineErr: errors.New("the container engine is not responding"), patched: sandbox.Result{ExitCode: 1}}
	res, err := Run(context.Background(), withSuite(t, gateOpts(t, rt)))
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	if f.Status != finding.StatusPatchAvailable || !strings.HasPrefix(f.Remediation.Verification, "verified: ") || !strings.Contains(f.Remediation.Verification, "no longer succeeds") {
		t.Fatalf("status=%s verification=%q", f.Status, f.Remediation.Verification)
	}
	if strings.Contains(f.Remediation.Verification, "still passes") || strings.Contains(rt.kinds(), "tests-patched") {
		t.Fatalf("the suite was used without a baseline: verification=%q runs=%s", f.Remediation.Verification, rt.kinds())
	}
	// A run that never produced a result is not recorded as one.
	runs, _, _ := gateEvents(t, res.RunDir)
	if got := purposesOf(runs); got != "poc,fix-compile,fix-verify" {
		t.Fatalf("sandbox purposes = %s", got)
	}
}

func TestBaselineRunsOnceForTwoFindings(t *testing.T) {
	rt := &gateRuntime{}
	o := withSecondFinding(t, withSuite(t, gateOpts(t, rt)))
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (notes: %v)", len(res.Run.Findings), res.Run.Notes)
	}
	for _, f := range res.Run.Findings {
		if f.Status != finding.StatusPatchAvailable || !strings.Contains(f.Remediation.Verification, "the test suite still passes") {
			t.Fatalf("%s: status=%s verification=%q", f.ID, f.Status, f.Remediation.Verification)
		}
	}
	runs, _, _ := gateEvents(t, res.RunDir)
	one := "fix-compile,fix-verify,fix-tests"
	if got, want := purposesOf(runs), "poc,tests-baseline,"+one+",poc,"+one; got != want {
		t.Fatalf("sandbox purposes = %s, want %s", got, want)
	}
	if n := strings.Count(rt.kinds(), "tests-baseline"); n != 1 {
		t.Fatalf("the baseline ran %d times, want once", n)
	}
	if res.Run.Usage.SandboxRuns != 9 {
		t.Fatalf("sandbox runs = %d, want 9", res.Run.Usage.SandboxRuns)
	}
}

func TestCachedBaselineFailureAppliesToEveryFinding(t *testing.T) {
	rt := &gateRuntime{baseline: sandbox.Result{ExitCode: 1}, patched: sandbox.Result{ExitCode: 1}}
	o := withSecondFinding(t, withSuite(t, gateOpts(t, rt)))
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Run.Findings))
	}
	for _, f := range res.Run.Findings {
		if !strings.Contains(f.Remediation.Verification, "was not used because it does not pass on the unmodified code") {
			t.Fatalf("%s: verification=%q", f.ID, f.Remediation.Verification)
		}
	}
	if got := rt.kinds(); strings.Count(got, "tests-baseline") != 1 || strings.Contains(got, "tests-patched") {
		t.Fatalf("sandbox runs = %s", got)
	}
}

func TestBaselineCountsAgainstTheSandboxRunCap(t *testing.T) {
	cases := []struct {
		cap   int
		kinds string
	}{
		// The proof takes the only run: the baseline is refused.
		{1, "proof"},
		// The baseline takes the second run: the compile check is refused.
		{2, "proof,tests-baseline"},
	}
	for _, tc := range cases {
		rt := &gateRuntime{}
		o := withSuite(t, gateOpts(t, rt))
		o.Config.Budget.SandboxRuns = tc.cap
		res, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if got := rt.kinds(); got != tc.kinds {
			t.Fatalf("cap %d: sandbox runs = %s, want %s", tc.cap, got, tc.kinds)
		}
		if res.Run.Usage.SandboxRuns != tc.cap {
			t.Fatalf("cap %d: counted sandbox runs = %d", tc.cap, res.Run.Usage.SandboxRuns)
		}
		if len(res.Run.Skipped) == 0 || !strings.Contains(res.Run.Skipped[0].Cap, "sandbox run cap") {
			t.Fatalf("cap %d: skipped = %+v", tc.cap, res.Run.Skipped)
		}
		_, _, skips := gateEvents(t, res.RunDir)
		if len(skips) != 1 || !strings.Contains(skips[0].Cap, "sandbox run cap") {
			t.Fatalf("cap %d: budget skip events = %+v", tc.cap, skips)
		}
		f := onlyFinding(t, res)
		if f.Proof.Status != finding.ProofDemonstrated || f.Status != finding.StatusOpen || f.Remediation.Patch != "" {
			t.Fatalf("cap %d: proof=%s status=%s patch=%q", tc.cap, f.Proof.Status, f.Status, f.Remediation.Patch)
		}
	}
}

func TestScanReportsAProofThatDidNotReproduce(t *testing.T) {
	cases := []struct {
		name   string
		proof  func(spec sandbox.Spec) (sandbox.Result, error)
		reason string
	}{
		{
			"the proof fails without the marker",
			func(sandbox.Spec) (sandbox.Result, error) {
				return sandbox.Result{ExitCode: 1, Stderr: "AssertionError: the injected row was not returned"}, nil
			},
			"The proof ran (exit code 1) and did not show the flaw.",
		},
		{
			"the proof prints the marker and exits non-zero",
			func(spec sandbox.Spec) (sandbox.Result, error) {
				return sandbox.Result{ExitCode: 3, Stdout: spec.Files[gatePoCRel]}, nil
			},
			"The proof printed the marker but exited with code 3.",
		},
		{
			"the proof prints the marker and times out",
			func(spec sandbox.Spec) (sandbox.Result, error) {
				return sandbox.Result{TimedOut: true, Stdout: spec.Files[gatePoCRel]}, nil
			},
			"The proof timed out.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &gateRuntime{proof: tc.proof}
			res, err := Run(context.Background(), gateOpts(t, rt))
			if err != nil {
				t.Fatal(err)
			}
			f := onlyFinding(t, res)
			if f.Proof.Status != finding.ProofFailed {
				t.Fatalf("proof status = %s, want %s", f.Proof.Status, finding.ProofFailed)
			}
			if f.Confidence.Level == finding.ConfidenceDemonstrated {
				t.Fatal("a proof that did not show the flaw raised the confidence to demonstrated")
			}
			if want := tc.reason + " The finding stands on the code reading alone."; f.Proof.Reason != want {
				t.Fatalf("proof reason = %q, want %q", f.Proof.Reason, want)
			}
			if !strings.Contains(f.Proof.Isolation, "fake-runtime") || len(f.Proof.Artifacts) != 0 {
				t.Fatalf("proof = %+v", f.Proof)
			}
			runs, verdicts, _ := gateEvents(t, res.RunDir)
			if got := stageVerdicts(verdicts, "prover"); got != "not-reproduced" {
				t.Fatalf("prover verdicts = %q, want not-reproduced", got)
			}
			// The prover gets one retry; the fixer then has no proof to
			// re-run, so its patch is offered as unverified.
			if got := purposesOf(runs); got != "poc,poc,fix-compile" {
				t.Fatalf("sandbox purposes = %s", got)
			}
			if f.Status != finding.StatusOpen || f.Remediation.Patch == "" || !strings.HasPrefix(f.Remediation.Verification, "unverified: ") {
				t.Fatalf("status=%s verification=%q patch=%q", f.Status, f.Remediation.Verification, f.Remediation.Patch)
			}
			if got := stageVerdicts(verdicts, "fixer"); got != "fix-unverified" {
				t.Fatalf("fixer verdicts = %q", got)
			}
		})
	}
}

func TestScanOfflineDoesNotPullAMissingImage(t *testing.T) {
	rt := &gateRuntime{imageAbsent: true}
	o := gateOpts(t, rt)
	o.Config.Offline = true
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	if rt.pulls != 0 || rt.runCount() != 0 {
		t.Fatalf("offline mode pulled %d image(s) and ran %d command(s)", rt.pulls, rt.runCount())
	}
	if f.Proof.Status == finding.ProofDemonstrated || f.Proof.Status == finding.ProofFailed || f.Confidence.Level == finding.ConfidenceDemonstrated {
		t.Fatalf("proof = %+v", f.Proof)
	}
	if !strings.HasPrefix(f.Proof.Reason, "Traced by reading the code. The proof was not run: ") || !strings.Contains(f.Proof.Reason, "offline mode does not pull images") {
		t.Fatalf("proof reason = %q", f.Proof.Reason)
	}
	if f.Status != finding.StatusOpen || f.Remediation.Patch != "" || res.Run.Usage.SandboxRuns != 0 {
		t.Fatalf("status=%s patch=%q runs=%d", f.Status, f.Remediation.Patch, res.Run.Usage.SandboxRuns)
	}
}

func TestScanPullsAMissingImageOnceWhenOnline(t *testing.T) {
	rt := &gateRuntime{imageAbsent: true}
	res, err := Run(context.Background(), gateOpts(t, rt))
	if err != nil {
		t.Fatal(err)
	}
	if f := onlyFinding(t, res); f.Proof.Status != finding.ProofDemonstrated || f.Status != finding.StatusPatchAvailable {
		t.Fatalf("proof=%s status=%s", f.Proof.Status, f.Status)
	}
	if rt.pulls != 1 {
		t.Fatalf("pulls = %d, want 1", rt.pulls)
	}

	// A pull that fails leaves the finding traced, with the reason.
	rt = &gateRuntime{imageAbsent: true, pullErr: errors.New("registry unreachable")}
	res, err = Run(context.Background(), gateOpts(t, rt))
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	if rt.runCount() != 0 || f.Proof.Status == finding.ProofDemonstrated || !strings.Contains(f.Proof.Reason, "is not available: registry unreachable") {
		t.Fatalf("runs=%d proof=%+v", rt.runCount(), f.Proof)
	}
}

// provenRun scans the target with the fixer off, which leaves one finding
// with a stored proof for verify to re-run.
func provenRun(t *testing.T, rt *gateRuntime) (Options, Result, finding.Finding) {
	t.Helper()
	o := gateOpts(t, rt)
	off := false
	o.Config.Fix.Enabled = &off
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	if f.Proof.Status != finding.ProofDemonstrated {
		t.Fatalf("the scan did not demonstrate the finding: %+v", f.Proof)
	}
	return o, res, f
}

func gateVerify(ctx context.Context, o Options, res Result, rt *gateRuntime) ([]VerifyOutcome, error) {
	return Verify(ctx, VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: rt.detect(), Clock: fixedClock()})
}

func storedFinding(t *testing.T, runDir, id string) finding.Finding {
	t.Helper()
	run, err := report.Load(runDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range run.Findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %s is not in the run", id)
	return finding.Finding{}
}

// assertOnlyInconclusive checks that a verify whose sandbox failed added one
// inconclusive verify verdict to the ledger and no sandbox run.
func assertOnlyInconclusive(t *testing.T, runDir string, before int) {
	t.Helper()
	events, err := ledger.Read(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != before+1 || events[before].Type != ledger.TypeVerdict {
		t.Fatalf("verify added %d event(s), want one verdict", len(events)-before)
	}
	var v ledger.Verdict
	if err := events[before].Decode(&v); err != nil || v.Stage != "verify" || v.Outcome != ledger.VerdictInconclusive {
		t.Fatalf("verdict = %+v (%v), want an inconclusive verify verdict", v, err)
	}
}

func ledgerLen(t *testing.T, runDir string) int {
	t.Helper()
	events, err := ledger.Read(runDir)
	if err != nil {
		t.Fatal(err)
	}
	return len(events)
}

func TestVerifyRefusesADamagedManifest(t *testing.T) {
	cases := []struct {
		name   string
		damage func(man map[string]any) any
	}{
		{"not JSON", func(map[string]any) any { return nil }},
		{"names another finding", func(m map[string]any) any { m["finding_id"] = "SPK-0000000000"; return m }},
		{"no finding id", func(m map[string]any) any { delete(m, "finding_id"); return m }},
		{"empty command", func(m map[string]any) any { m["command"] = []string{}; return m }},
		{"empty marker", func(m map[string]any) any { m["marker"] = ""; return m }},
		{"wrong shape", func(m map[string]any) any { m["command"] = "python spackle_poc/poc.py"; return m }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &gateRuntime{}
			o, res, f := provenRun(t, rt)
			path := filepath.Join(res.RunDir, "findings", f.ID, "poc", "poc.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var man map[string]any
			if err := json.Unmarshal(raw, &man); err != nil {
				t.Fatal(err)
			}
			damaged := []byte(`{"finding_id": "` + f.ID + `", "command": [`)
			if v := tc.damage(man); v != nil {
				if damaged, err = json.Marshal(v); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, damaged, 0o600); err != nil {
				t.Fatal(err)
			}
			before, events := rt.runCount(), ledgerLen(t, res.RunDir)
			out, err := gateVerify(context.Background(), o, res, rt)
			if err == nil || !strings.Contains(err.Error(), "the stored proof for "+f.ID+" is damaged") {
				t.Fatalf("err = %v", err)
			}
			if len(out) != 0 || rt.runCount() != before {
				t.Fatalf("a damaged proof was run: outcomes=%+v runs=%d", out, rt.runCount()-before)
			}
			if ledgerLen(t, res.RunDir) != events {
				t.Fatal("verify wrote to the ledger although it ran nothing")
			}
			if got := storedFinding(t, res.RunDir, f.ID).Status; got != finding.StatusOpen {
				t.Fatalf("status = %s", got)
			}
		})
	}
}

func TestVerifyLeavesAProofThatNeverSucceeded(t *testing.T) {
	// The proof runs during the scan and does not show the flaw.
	rt := &gateRuntime{proof: func(sandbox.Spec) (sandbox.Result, error) {
		return sandbox.Result{ExitCode: 1, Stdout: "AssertionError"}, nil
	}}
	o := gateOpts(t, rt)
	off := false
	o.Config.Fix.Enabled = &off
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	if f.Proof.Status != finding.ProofFailed || f.Status != finding.StatusOpen {
		t.Fatalf("proof=%s status=%s, want a failed proof on an open finding", f.Proof.Status, f.Status)
	}
	if _, err := os.Stat(filepath.Join(res.RunDir, "findings", f.ID, "poc", "poc.json")); err != nil {
		t.Fatalf("the failed proof was not stored: %v", err)
	}

	before, events := rt.runCount(), ledgerLen(t, res.RunDir)
	var progress strings.Builder
	out, err := Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: rt.detect(), Clock: fixedClock(), Progress: &progress})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no stored proofs") {
		t.Fatalf("err = %v, want a refusal: nothing was ever demonstrated", err)
	}
	if len(out) != 0 || rt.runCount() != before || ledgerLen(t, res.RunDir) != events {
		t.Fatalf("a proof that never succeeded was re-run: outcomes=%+v runs=%d", out, rt.runCount()-before)
	}
	if !strings.Contains(progress.String(), "Skipping "+f.ID) {
		t.Fatalf("progress = %q, want a note that the finding was skipped", progress.String())
	}
	if got := storedFinding(t, res.RunDir, f.ID); got.Status != finding.StatusOpen || got.Proof.Status != finding.ProofFailed {
		t.Fatalf("status=%s proof=%s, want the finding unchanged", got.Status, got.Proof.Status)
	}
}

func TestVerifyReportsAMissingProofFile(t *testing.T) {
	rt := &gateRuntime{}
	o, res, f := provenRun(t, rt)
	if err := os.Remove(filepath.Join(res.RunDir, "findings", f.ID, "poc", "spackle_poc", "poc.py")); err != nil {
		t.Fatal(err)
	}
	before := rt.runCount()
	out, err := gateVerify(context.Background(), o, res, rt)
	if err == nil || !strings.Contains(err.Error(), "the stored proof for "+f.ID+" is missing "+gatePoCRel) {
		t.Fatalf("err = %v", err)
	}
	if len(out) != 0 || rt.runCount() != before {
		t.Fatalf("an incomplete proof was run: outcomes=%+v", out)
	}
	if got := storedFinding(t, res.RunDir, f.ID).Status; got != finding.StatusOpen {
		t.Fatalf("status = %s", got)
	}
}

func TestVerifyKeepsTheFindingWhenTheSandboxFails(t *testing.T) {
	rt := &gateRuntime{}
	o, res, f := provenRun(t, rt)
	broken := func(sandbox.Spec) (sandbox.Result, error) {
		return sandbox.Result{}, errors.New("the container engine is not responding")
	}

	// An open finding stays open: an outage is not a fix.
	rt.proof = broken
	events := ledgerLen(t, res.RunDir)
	out, err := gateVerify(context.Background(), o, res, rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].FindingID != f.ID || !out[0].Reproduces || !out[0].Inconclusive {
		t.Fatalf("outcomes = %+v", out)
	}
	if !strings.HasPrefix(out[0].Note, "The proof could not be run: ") || !strings.Contains(out[0].Note, "not responding") {
		t.Fatalf("note = %q", out[0].Note)
	}
	assertOnlyInconclusive(t, res.RunDir, events)
	if got := storedFinding(t, res.RunDir, f.ID); got.Status != finding.StatusOpen || got.Proof.Status != finding.ProofDemonstrated {
		t.Fatalf("status=%s proof=%s", got.Status, got.Proof.Status)
	}

	// The operator fixes the code and verify marks the finding fixed.
	rt.proof = func(sandbox.Spec) (sandbox.Result, error) {
		return sandbox.Result{ExitCode: 1, Stdout: "AssertionError"}, nil
	}
	if out, err = gateVerify(context.Background(), o, res, rt); err != nil || len(out) != 1 || out[0].Reproduces || out[0].Inconclusive {
		t.Fatalf("outcomes = %+v err = %v", out, err)
	}
	if got := storedFinding(t, res.RunDir, f.ID).Status; got != finding.StatusFixed {
		t.Fatalf("status = %s, want fixed", got)
	}
	// The output behind the fixed verdict is kept as evidence and linked.
	runs, _, _ := gateEvents(t, res.RunDir)
	last := runs[len(runs)-1]
	if last.Purpose != "verify" || last.OutputRef == "" {
		t.Fatalf("verify sandbox event = %+v, want it linked to its output", last)
	}
	if b, err := os.ReadFile(filepath.Join(res.RunDir, filepath.FromSlash(last.OutputRef))); err != nil || !strings.Contains(string(b), "AssertionError") {
		t.Fatalf("verify evidence %s = %q, %v", last.OutputRef, b, err)
	}

	// A fixed finding stays fixed through an outage as well.
	rt.proof = broken
	events = ledgerLen(t, res.RunDir)
	out, err = gateVerify(context.Background(), o, res, rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Reproduces || !out[0].Inconclusive || !strings.HasPrefix(out[0].Note, "The proof could not be run: ") {
		t.Fatalf("outcomes = %+v", out)
	}
	assertOnlyInconclusive(t, res.RunDir, events)
	if got := storedFinding(t, res.RunDir, f.ID).Status; got != finding.StatusFixed {
		t.Fatalf("status = %s, want fixed", got)
	}
	_, verdicts, _ := gateEvents(t, res.RunDir)
	if got := stageVerdicts(verdicts, "verify"); got != "inconclusive,no-longer-reproduces,inconclusive" {
		t.Fatalf("verify verdicts = %q", got)
	}
}

func TestVerifyOutcomeNeedsTheMarkerAndACleanExit(t *testing.T) {
	withMarker := func(res sandbox.Result) func(sandbox.Spec) (sandbox.Result, error) {
		return func(spec sandbox.Spec) (sandbox.Result, error) {
			res.Stdout = spec.Files[gatePoCRel]
			return res, nil
		}
	}
	cases := []struct {
		name         string
		proof        func(sandbox.Spec) (sandbox.Result, error)
		reproduces   bool
		inconclusive bool
		status       string
		verdict      string
		note         string
	}{
		{"marker and exit 0", withMarker(sandbox.Result{}), true, false, finding.StatusOpen, "still-reproduces", "The proof still succeeds against the current code."},
		{"marker on stderr and exit 0", func(spec sandbox.Spec) (sandbox.Result, error) {
			return sandbox.Result{Stderr: spec.Files[gatePoCRel]}, nil
		}, true, false, finding.StatusOpen, "still-reproduces", "The proof still succeeds"},
		// The marker without a clean exit is not the proof succeeding, and
		// it is not a fix either: the effect was still observed.
		{"marker but exit 1", withMarker(sandbox.Result{ExitCode: 1}), true, true, finding.StatusOpen, "inconclusive", "it printed its marker and then exited with code 1, which shows neither"},
		{"exit 0 without the marker", func(sandbox.Spec) (sandbox.Result, error) {
			return sandbox.Result{Stdout: "ok"}, nil
		}, false, false, finding.StatusFixed, "no-longer-reproduces", "The proof no longer succeeds"},
		{"marker but timed out", withMarker(sandbox.Result{TimedOut: true}), true, true, finding.StatusOpen, "inconclusive", "it timed out before it finished"},
		{"marker but killed", withMarker(sandbox.Result{ExitCode: 137}), true, true, finding.StatusOpen, "inconclusive", "it was killed (exit code 137"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &gateRuntime{}
			o, res, f := provenRun(t, rt)
			rt.proof = tc.proof
			out, err := gateVerify(context.Background(), o, res, rt)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || out[0].FindingID != f.ID || out[0].Title != f.Title || out[0].Reproduces != tc.reproduces || out[0].Inconclusive != tc.inconclusive {
				t.Fatalf("outcomes = %+v", out)
			}
			if !strings.Contains(out[0].Note, tc.note) {
				t.Fatalf("note = %q, want it to contain %q", out[0].Note, tc.note)
			}
			if got := storedFinding(t, res.RunDir, f.ID).Status; got != tc.status {
				t.Fatalf("status = %s, want %s", got, tc.status)
			}
			runs, verdicts, _ := gateEvents(t, res.RunDir)
			if got := stageVerdicts(verdicts, "verify"); got != tc.verdict {
				t.Fatalf("verify verdicts = %q, want %q", got, tc.verdict)
			}
			if got := purposesOf(runs); got != "poc,verify" {
				t.Fatalf("sandbox purposes = %s", got)
			}
		})
	}
}

func TestVerifyMarksAPatchThatWasNotApplied(t *testing.T) {
	rt := &gateRuntime{}
	o := gateOpts(t, rt)
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	if f.Status != finding.StatusPatchAvailable || f.Remediation.Patch == "" {
		t.Fatalf("status=%s patch=%q", f.Status, f.Remediation.Patch)
	}
	// The target still holds the flaw, so the stored proof succeeds.
	out, err := gateVerify(context.Background(), o, res, rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !out[0].Reproduces || out[0].Inconclusive {
		t.Fatalf("outcomes = %+v", out)
	}
	got := storedFinding(t, res.RunDir, f.ID)
	if got.Status != finding.StatusOpen || !strings.HasPrefix(got.Remediation.Verification, "not applied: the proof still succeeds against the current code") {
		t.Fatalf("status=%s verification=%q", got.Status, got.Remediation.Verification)
	}
	if got.Remediation.Patch != f.Remediation.Patch || !strings.Contains(got.Proof.Result, "SPACKLE-PROOF-") {
		t.Fatalf("the patch or the proof output was lost: %+v", got)
	}
	// The verify run saw the target as it is, without the patch.
	last := rt.runs[len(rt.runs)-1]
	if gateKind(last) != "proof" || last.SourceDir != res.Run.TargetPath {
		t.Fatalf("verify spec = %+v", last)
	}
}

func TestVerifyImageHandling(t *testing.T) {
	t.Run("offline refuses and does not pull", func(t *testing.T) {
		rt := &gateRuntime{}
		o, res, f := provenRun(t, rt)
		rt.imageAbsent = true
		o.Config.Offline = true
		before := rt.runCount()
		out, err := gateVerify(context.Background(), o, res, rt)
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "offline mode does not pull images") {
			t.Fatalf("err = %v", err)
		}
		if rt.pulls != 0 || rt.runCount() != before || len(out) != 0 {
			t.Fatalf("pulls=%d runs=%d outcomes=%+v", rt.pulls, rt.runCount()-before, out)
		}
		if got := storedFinding(t, res.RunDir, f.ID).Status; got != finding.StatusOpen {
			t.Fatalf("status = %s", got)
		}
	})
	t.Run("a failed pull stops verify", func(t *testing.T) {
		rt := &gateRuntime{}
		o, res, _ := provenRun(t, rt)
		rt.imageAbsent, rt.pullErr = true, errors.New("registry unreachable")
		before := rt.runCount()
		out, err := gateVerify(context.Background(), o, res, rt)
		if err == nil || !strings.Contains(err.Error(), "is not available: registry unreachable") {
			t.Fatalf("err = %v", err)
		}
		if rt.pulls != 1 || rt.runCount() != before || len(out) != 0 {
			t.Fatalf("pulls=%d runs=%d outcomes=%+v", rt.pulls, rt.runCount()-before, out)
		}
	})
	t.Run("a missing image is pulled when online", func(t *testing.T) {
		rt := &gateRuntime{}
		o, res, _ := provenRun(t, rt)
		rt.imageAbsent = true
		out, err := gateVerify(context.Background(), o, res, rt)
		if err != nil {
			t.Fatal(err)
		}
		if rt.pulls != 1 || len(out) != 1 || !out[0].Reproduces {
			t.Fatalf("pulls=%d outcomes=%+v", rt.pulls, out)
		}
	})
}

func TestVerifyStopsWhenInterrupted(t *testing.T) {
	scan := func(t *testing.T, rt *gateRuntime) (Options, Result) {
		t.Helper()
		o := withSecondFinding(t, gateOpts(t, rt))
		off := false
		o.Config.Fix.Enabled = &off
		res, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Run.Findings) != 2 {
			t.Fatalf("findings = %d, want 2", len(res.Run.Findings))
		}
		return o, res
	}

	t.Run("the sandbox run is cancelled", func(t *testing.T) {
		rt := &gateRuntime{}
		o, res := scan(t, rt)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		n := 0
		rt.proof = func(spec sandbox.Spec) (sandbox.Result, error) {
			n++
			if n == 2 {
				cancel() // the operator presses Ctrl-C during the second proof
				return sandbox.Result{}, context.Canceled
			}
			return sandbox.Result{Stdout: spec.Files[gatePoCRel]}, nil
		}
		out, err := gateVerify(ctx, o, res, rt)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if len(out) != 1 || out[0].FindingID != res.Run.Findings[0].ID || !out[0].Reproduces || out[0].Inconclusive {
			t.Fatalf("outcomes so far = %+v", out)
		}
		if n != 2 {
			t.Fatalf("proof runs = %d, want 2", n)
		}
	})

	t.Run("the interrupt arrives between proofs", func(t *testing.T) {
		rt := &gateRuntime{}
		o, res := scan(t, rt)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		n := 0
		rt.proof = func(sandbox.Spec) (sandbox.Result, error) {
			n++
			cancel()
			return sandbox.Result{ExitCode: 1}, nil
		}
		out, err := gateVerify(ctx, o, res, rt)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if len(out) != 1 || out[0].Reproduces || n != 1 {
			t.Fatalf("outcomes so far = %+v, proof runs = %d", out, n)
		}
		// The proof that finished is in the ledger; the other finding is untouched.
		first, second := res.Run.Findings[0].ID, res.Run.Findings[1].ID
		if got := storedFinding(t, res.RunDir, first).Status; got != finding.StatusFixed {
			t.Fatalf("%s status = %s, want fixed", first, got)
		}
		if got := storedFinding(t, res.RunDir, second).Status; got != finding.StatusOpen {
			t.Fatalf("%s status = %s, want open", second, got)
		}
	})
}
