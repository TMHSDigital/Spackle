package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
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

// fakeRuntime stands in for Docker. It "runs" a spec by applying simple
// rules to the files it was given, which is enough to exercise every
// decision the engine makes around the sandbox without a container.
type fakeRuntime struct {
	mu   sync.Mutex
	runs []sandbox.Spec
	// fixClosesProof says whether patching app.py stops the proof.
	fixClosesProof bool
	// compileFails makes the compile check fail.
	compileFails bool
	// proofGone makes every proof fail, as if the code had been fixed.
	proofGone bool
	// patchHangs makes the proof time out once app.py is patched, as a
	// patch that breaks the program would.
	patchHangs bool
	// proofHangs makes every proof time out.
	proofHangs bool
}

func (f *fakeRuntime) Name() string                              { return "fake-runtime" }
func (f *fakeRuntime) ImagePresent(context.Context, string) bool { return true }
func (f *fakeRuntime) Pull(context.Context, string) error        { return nil }
func (f *fakeRuntime) Run(_ context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, spec)
	res := sandbox.Result{Isolation: spec.Profile.WithDefaults().Summary()}
	_, patched := spec.Files["app.py"]
	poc, hasPoC := spec.Files["spackle_poc/poc.py"]
	switch {
	case len(spec.Cmd) > 2 && spec.Cmd[2] == "py_compile":
		if f.compileFails {
			res.ExitCode, res.Stderr = 1, "SyntaxError: invalid syntax"
		}
	case hasPoC:
		// The "proof" prints its own content, which holds the marker,
		// unless the patch is in place and is effective.
		switch {
		case (patched && f.patchHangs) || f.proofHangs:
			res.TimedOut, res.ExitCode = true, -1
		case (patched && f.fixClosesProof) || f.proofGone:
			res.ExitCode, res.Stdout = 1, "AssertionError: the injected row was not returned"
		default:
			res.Stdout = poc
		}
	}
	return res, nil
}

var markerRe = regexp.MustCompile(`SPACKLE-PROOF-[0-9a-f]+`)

const fixedAppPy = "import sqlite3\n\ndef find(q):\n    return db.execute(\"SELECT * FROM t WHERE a = ?\", (q,))\n"

// labProvider plays every stage, including a prover that embeds the marker
// it was given and a fixer that parameterizes the query.
func labProvider() *llm.Fake {
	f := llm.NewFake()
	f.Handler = func(req llm.Request, _ int) (llm.Response, error) {
		resp := llm.Response{StopReason: llm.StopEnd, Usage: llm.Usage{InputTokens: 100, OutputTokens: 50, CostKnown: true}}
		user := req.Messages[0].Text
		switch {
		case strings.Contains(req.System, "this step is planning"):
			resp.Text = planFor(leadID(sqlLead(), "fake"))
		case strings.Contains(req.System, "adversarial review"):
			resp.Text = `{"verdict":"confirmed","reason":"q is interpolated"}`
		case strings.Contains(req.System, "combine into a larger"):
			resp.Text = `{"chains":[]}`
		case strings.Contains(req.System, "demonstrate one finding"):
			marker := markerRe.FindString(user)
			b, _ := json.Marshal(map[string]any{
				"can_prove": true, "files": map[string]string{"spackle_poc/poc.py": "print('" + marker + "')\n"},
				"command": []string{"python", "spackle_poc/poc.py"}, "explanation": "Calls find with a crafted q.",
			})
			resp.Text = string(b)
		case strings.Contains(req.System, "fix one finding"):
			b, _ := json.Marshal(map[string]any{"files": map[string]string{"app.py": fixedAppPy}, "why": "The value is bound, not formatted."})
			resp.Text = string(b)
		default:
			resp.Text = goodDraft()
		}
		return resp, nil
	}
	return f
}

func labOpts(t *testing.T, rt *fakeRuntime) Options {
	t.Helper()
	o := agenticOpts(t, labProvider(), fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	o.DetectRuntime = func(context.Context, string) (sandbox.Runtime, error) { return rt, nil }
	return o
}

func TestProveThenFixThenVerify(t *testing.T) {
	rt := &fakeRuntime{fixClosesProof: true}
	o := labOpts(t, rt)
	before, _ := os.ReadFile(filepath.Join(o.Target, "app.py"))
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Run.Findings))
	}
	f := res.Run.Findings[0]
	if f.Proof.Status != finding.ProofDemonstrated || f.Confidence.Level != finding.ConfidenceDemonstrated {
		t.Fatalf("proof=%s confidence=%s reason=%q", f.Proof.Status, f.Confidence.Level, f.Proof.Reason)
	}
	if f.Proof.Command != "python spackle_poc/poc.py" || !strings.Contains(f.Proof.Result, "SPACKLE-PROOF-") || !strings.Contains(f.Proof.Isolation, "network none") {
		t.Fatalf("proof = %+v", f.Proof)
	}
	if f.Status != finding.StatusPatchAvailable || !strings.HasPrefix(f.Remediation.Verification, "verified: ") || !strings.Contains(f.Remediation.Verification, "no longer succeeds") {
		t.Fatalf("status=%s verification=%q", f.Status, f.Remediation.Verification)
	}
	if !strings.Contains(f.Remediation.Patch, "+    return db.execute(\"SELECT * FROM t WHERE a = ?\", (q,))") || !strings.Contains(f.Remediation.Patch, "--- a/app.py") {
		t.Fatalf("patch:\n%s", f.Remediation.Patch)
	}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}

	// The target was never modified: the patch is in the run folder only.
	after, _ := os.ReadFile(filepath.Join(o.Target, "app.py"))
	if string(before) != string(after) {
		t.Fatal("the target's working tree was modified")
	}
	dir := filepath.Join(res.RunDir, "findings", f.ID)
	for _, rel := range []string{"finding.json", "fix.patch", "poc/poc.json", "poc/spackle_poc/poc.py", "evidence/01-poc.txt"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}
	if !strings.Contains(res.Run.Isolation, "fake-runtime") || !strings.Contains(res.Run.Isolation, "network none") {
		t.Fatalf("run isolation = %q", res.Run.Isolation)
	}
	if res.Run.Usage.SandboxRuns != 3 {
		t.Fatalf("sandbox runs = %d, want 3 (proof, compile check, proof against the patch)", res.Run.Usage.SandboxRuns)
	}
	// Every run used the default isolation and a read-only view of the source.
	for _, spec := range rt.runs {
		if spec.Profile.Network != "none" || spec.SourceDir != o.Target {
			t.Fatalf("sandbox spec = %+v", spec)
		}
	}
	if !strings.Contains(strings.Join(res.Run.Notes, "|"), "patch files only") {
		t.Fatalf("notes = %v", res.Run.Notes)
	}
}

func TestPatchThatDoesNotCloseTheProofIsRejected(t *testing.T) {
	rt := &fakeRuntime{fixClosesProof: false}
	res, err := Run(context.Background(), labOpts(t, rt))
	if err != nil {
		t.Fatal(err)
	}
	f := res.Run.Findings[0]
	if f.Status != finding.StatusOpen || f.Remediation.Patch != "" {
		t.Fatalf("an ineffective patch was accepted: status=%s patch=%q", f.Status, f.Remediation.Patch)
	}
	if !strings.HasPrefix(f.Remediation.Verification, "no patch: ") || !strings.Contains(f.Remediation.Verification, "still succeeds") {
		t.Fatalf("verification = %q", f.Remediation.Verification)
	}
	// Still demonstrated: the proof is real even though no fix was found.
	if f.Proof.Status != finding.ProofDemonstrated {
		t.Fatalf("proof = %s", f.Proof.Status)
	}
}

func TestPatchThatBreaksTheBuildIsRejected(t *testing.T) {
	rt := &fakeRuntime{fixClosesProof: true, compileFails: true}
	res, err := Run(context.Background(), labOpts(t, rt))
	if err != nil {
		t.Fatal(err)
	}
	f := res.Run.Findings[0]
	if f.Status != finding.StatusOpen || !strings.Contains(f.Remediation.Verification, "does not compile") {
		t.Fatalf("status=%s verification=%q", f.Status, f.Remediation.Verification)
	}
}

func TestNoRuntimeMeansNothingIsExecuted(t *testing.T) {
	o := agenticOpts(t, labProvider(), fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := res.Run.Findings[0]
	if f.Proof.Status != finding.ProofReasoned || !strings.Contains(f.Proof.Reason, "No container runtime") {
		t.Fatalf("proof = %+v", f.Proof)
	}
	if f.Confidence.Level == finding.ConfidenceDemonstrated || f.Status != finding.StatusOpen || f.Remediation.Patch != "" {
		t.Fatalf("without a runtime nothing can be demonstrated or fixed: %+v", f)
	}
	if !strings.Contains(res.Run.Isolation, "no container runtime") || res.Run.Usage.SandboxRuns != 0 {
		t.Fatalf("isolation=%q runs=%d", res.Run.Isolation, res.Run.Usage.SandboxRuns)
	}
}

func TestNoFixFlagSkipsTheFixer(t *testing.T) {
	rt := &fakeRuntime{fixClosesProof: true}
	o := labOpts(t, rt)
	off := false
	o.Config.Fix.Enabled = &off
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := res.Run.Findings[0]
	if f.Proof.Status != finding.ProofDemonstrated || f.Remediation.Patch != "" || f.Status != finding.StatusOpen || len(rt.runs) != 1 {
		t.Fatalf("proof=%s patch=%q status=%s runs=%d", f.Proof.Status, f.Remediation.Patch, f.Status, len(rt.runs))
	}
}

func TestSandboxRunCapIsEnforced(t *testing.T) {
	rt := &fakeRuntime{fixClosesProof: true}
	o := labOpts(t, rt)
	o.Config.Budget.SandboxRuns = 1
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.runs) != 1 {
		t.Fatalf("%d sandbox runs happened with a cap of 1", len(rt.runs))
	}
	if len(res.Run.Skipped) == 0 || !strings.Contains(res.Run.Skipped[0].Cap, "sandbox run cap") {
		t.Fatalf("skipped = %+v", res.Run.Skipped)
	}
}

func TestFixesLandOnABranchAndLeaveTheWorkingTreeAlone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; fix branches need it")
	}
	rt := &fakeRuntime{fixClosesProof: true}
	o := labOpts(t, rt)
	git := func(args ...string) string {
		t.Helper()
		full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"}, args...)
		cmd := exec.Command("git", full...)
		cmd.Dir = o.Target
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	git("add", "-A")
	git("commit", "-q", "-m", "init")
	// Uncommitted work in progress must survive the run untouched.
	if err := os.WriteFile(filepath.Join(o.Target, "notes.txt"), []byte("wip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	statusBefore := git("status", "--porcelain")
	headBefore := git("rev-parse", "HEAD")

	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := res.Run.Findings[0]
	branch := "spackle/" + res.RunID
	if f.Remediation.Branch != branch {
		t.Fatalf("branch = %q, want %q (notes: %v)", f.Remediation.Branch, branch, res.Run.Notes)
	}
	if got := git("status", "--porcelain"); got != statusBefore {
		t.Fatalf("working tree changed:\nbefore %q\nafter  %q", statusBefore, got)
	}
	if git("rev-parse", "HEAD") != headBefore || git("rev-parse", "--abbrev-ref", "HEAD") != "main" {
		t.Fatal("the operator's branch or HEAD moved")
	}
	onBranch := git("show", branch+":app.py")
	if !strings.Contains(onBranch, "WHERE a = ?") {
		t.Fatalf("the fix is not on the branch:\n%s", onBranch)
	}
	if msg := git("log", "-1", "--format=%s", branch); !strings.Contains(msg, f.ID) {
		t.Fatalf("commit subject = %q", msg)
	}
	if onMain, _ := os.ReadFile(filepath.Join(o.Target, "app.py")); strings.Contains(string(onMain), "WHERE a = ?") {
		t.Fatal("the fix was written into the working tree")
	}
}

func TestLedgerRecordsEverySandboxRun(t *testing.T) {
	rt := &fakeRuntime{fixClosesProof: true}
	res, err := Run(context.Background(), labOpts(t, rt))
	if err != nil {
		t.Fatal(err)
	}
	events, _ := ledger.Read(res.RunDir)
	var purposes []string
	for _, e := range events {
		if e.Type == ledger.TypeSandboxRun {
			var d ledger.SandboxRun
			if err := e.Decode(&d); err != nil {
				t.Fatal(err)
			}
			purposes = append(purposes, d.Purpose)
			if d.Isolation == "" || d.OutputRef == "" {
				t.Errorf("sandbox event lacks isolation or evidence: %+v", d)
			}
		}
	}
	if strings.Join(purposes, ",") != "poc,fix-compile,fix-verify" {
		t.Fatalf("sandbox purposes = %v", purposes)
	}
	_ = config.Default
}

func TestVerifyRerunsStoredProofs(t *testing.T) {
	rt := &fakeRuntime{}
	o := labOpts(t, rt)
	off := false
	o.Config.Fix.Enabled = &off
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	id := res.Run.Findings[0].ID
	detect := func(context.Context, string) (sandbox.Runtime, error) { return rt, nil }

	// The code is unchanged: the proof still succeeds.
	out, err := Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: detect})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].FindingID != id || !out[0].Reproduces {
		t.Fatalf("outcomes = %+v", out)
	}

	// The operator fixes the code: the proof stops working, the finding is fixed.
	rt.proofGone = true
	out, err = Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: detect})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Reproduces {
		t.Fatalf("outcomes = %+v", out)
	}
	run, err := report.Load(res.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	f := run.Findings[0]
	if f.Status != finding.StatusFixed || !strings.Contains(f.Remediation.Verification, "spackle verify") {
		t.Fatalf("status=%s verification=%q", f.Status, f.Remediation.Verification)
	}
	// The ledger grew; it was not rewritten.
	events, _ := ledger.Read(res.RunDir)
	verdicts := 0
	for _, e := range events {
		if e.Type == ledger.TypeVerdict {
			var v ledger.Verdict
			_ = e.Decode(&v)
			if v.Stage == "verify" {
				verdicts++
			}
		}
	}
	if verdicts != 2 {
		t.Fatalf("verify verdicts in the ledger = %d, want 2", verdicts)
	}
	// The two verify runs are evidence files numbered after the scan's,
	// and their sandbox_run events point at them.
	scanFiles := 0
	for _, e := range events {
		var sr ledger.SandboxRun
		if e.Type == ledger.TypeSandboxRun && e.Decode(&sr) == nil && sr.FindingID == id && sr.Purpose != "verify" {
			scanFiles++
		}
	}
	var refs []string
	for _, e := range events {
		var sr ledger.SandboxRun
		if e.Type == ledger.TypeSandboxRun && e.Decode(&sr) == nil && sr.Purpose == "verify" {
			refs = append(refs, sr.OutputRef)
		}
	}
	want := []string{
		fmt.Sprintf("findings/%s/evidence/%02d-verify.txt", id, scanFiles+1),
		fmt.Sprintf("findings/%s/evidence/%02d-verify.txt", id, scanFiles+2),
	}
	if scanFiles == 0 || strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Fatalf("verify evidence = %v, want %v after the scan's %d files", refs, want, scanFiles)
	}
	for _, rel := range refs {
		if _, err := os.Stat(filepath.Join(res.RunDir, filepath.FromSlash(rel))); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}
}

// Verify runs proofs under the [budget] caps, as a scan does: once the wall
// time cap is spent, a proof is not started, and the finding keeps its
// status with a note that says why.
func TestVerifyIsBoundByTheBudget(t *testing.T) {
	rt := &fakeRuntime{}
	o := labOpts(t, rt)
	off := false
	o.Config.Fix.Enabled = &off
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	before := len(rt.runs)
	// Every reading of this clock is an hour after the last, so the wall
	// time cap is spent by the time the first proof would start.
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		now = now.Add(time.Hour)
		return now
	}
	detect := func(context.Context, string) (sandbox.Runtime, error) { return rt, nil }
	out, err := Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: detect, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.runs) != before {
		t.Fatalf("a proof ran past the wall time cap: %d sandbox runs, the scan made %d", len(rt.runs), before)
	}
	if len(out) != 1 || !out[0].Inconclusive || !strings.Contains(out[0].Note, "wall time") {
		t.Fatalf("outcomes = %+v", out)
	}
}

func TestVerifyRefusesWithoutARuntimeOrProofs(t *testing.T) {
	// A deterministic run has no proofs.
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{}
	detect := func(context.Context, string) (sandbox.Runtime, error) { return rt, nil }
	if _, err := Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: detect}); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no stored proofs") {
		t.Fatalf("err = %v", err)
	}
	none := func(context.Context, string) (sandbox.Runtime, error) { return nil, sandbox.ErrNoRuntime }
	if _, err := Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: none}); !errors.Is(err, ErrRefused) || !errors.Is(err, sandbox.ErrNoRuntime) {
		t.Fatalf("err = %v", err)
	}
	if len(rt.runs) != 0 {
		t.Fatal("something was executed")
	}
}

func TestPRFlagOpensADraftPullRequestOnlyWhenAsked(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; fix branches need it")
	}
	for _, wantPR := range []bool{false, true} {
		rt := &fakeRuntime{fixClosesProof: true}
		o := labOpts(t, rt)
		o.Config.Fix.PR = wantPR
		for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "-A"}, {"commit", "-q", "-m", "init"}} {
			full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)
			cmd := exec.Command("git", full...)
			cmd.Dir = o.Target
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		var got []gitx.PRRequest
		o.OpenPR = func(_ context.Context, req gitx.PRRequest) (string, error) {
			got = append(got, req)
			return "https://example.test/pr/1", nil
		}
		res, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if !wantPR {
			if len(got) != 0 {
				t.Fatal("a pull request was opened without --pr")
			}
			continue
		}
		if len(got) != 1 || got[0].Branch != "spackle/"+res.RunID || !strings.Contains(got[0].Body, res.Run.Findings[0].ID) || !strings.Contains(got[0].Body, "verified:") {
			t.Fatalf("pr requests = %+v", got)
		}
		if !strings.Contains(strings.Join(res.Run.Notes, "|"), "Draft pull request opened: https://example.test/pr/1") {
			t.Fatalf("notes = %v", res.Run.Notes)
		}
	}
}

func TestPatchThatMakesTheProofHangIsRejected(t *testing.T) {
	rt := &fakeRuntime{patchHangs: true}
	res, err := Run(context.Background(), labOpts(t, rt))
	if err != nil {
		t.Fatal(err)
	}
	f := res.Run.Findings[0]
	if f.Status != finding.StatusOpen || f.Remediation.Patch != "" {
		t.Fatalf("a patch whose proof run timed out was accepted: status=%s patch=%q", f.Status, f.Remediation.Patch)
	}
	if !strings.Contains(f.Remediation.Verification, "timed out or was killed") {
		t.Fatalf("verification = %q", f.Remediation.Verification)
	}
}

func TestVerifyKeepsTheStatusWhenAProofTimesOut(t *testing.T) {
	rt := &fakeRuntime{}
	o := labOpts(t, rt)
	off := false
	o.Config.Fix.Enabled = &off
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(res.Run.TargetPath) {
		t.Fatalf("the run did not record an absolute target path: %q", res.Run.TargetPath)
	}
	rt.proofHangs = true
	detect := func(context.Context, string) (sandbox.Runtime, error) { return rt, nil }
	out, err := Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: detect})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !out[0].Inconclusive || !out[0].Reproduces || !strings.Contains(out[0].Note, "timed out") {
		t.Fatalf("outcomes = %+v", out)
	}
	run, err := report.Load(res.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := run.Findings[0].Status; got != finding.StatusOpen {
		t.Fatalf("a timed-out proof changed the status to %s", got)
	}
	// The proofs run against the scanned directory, not the current one.
	last := rt.runs[len(rt.runs)-1]
	if last.SourceDir != res.Run.TargetPath {
		t.Fatalf("verify ran against %q, want %q", last.SourceDir, res.Run.TargetPath)
	}
}

func TestFixBranchLeavesOutUncommittedEdits(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; fix branches need it")
	}
	rt := &fakeRuntime{fixClosesProof: true}
	o := labOpts(t, rt)
	git := func(args ...string) string {
		t.Helper()
		full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"}, args...)
		cmd := exec.Command("git", full...)
		cmd.Dir = o.Target
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	git("add", "-A")
	git("commit", "-q", "-m", "init")
	// The operator has unfinished, uncommitted work in the file that gets fixed.
	app := filepath.Join(o.Target, "app.py")
	src, err := os.ReadFile(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app, append(src, []byte("\nWIP_NOT_FOR_REVIEW = True\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := res.Run.Findings[0]
	if f.Remediation.Patch == "" {
		t.Fatal("the fix was not kept as a patch file")
	}
	if f.Remediation.Branch != "" {
		t.Fatalf("the finding names branch %q although the fix was not committed", f.Remediation.Branch)
	}
	if out := git("branch", "--list", "spackle/*"); out != "" {
		t.Fatalf("a fix branch was created from a file with uncommitted changes: %s", out)
	}
	if notes := strings.Join(res.Run.Notes, " | "); !strings.Contains(notes, "uncommitted changes in your working tree") {
		t.Fatalf("no note explains why there is no branch: %s", notes)
	}
}

// VerifyOptions.Findings limits verify to the named findings' proofs.
func TestVerifyOnlyTheNamedFindings(t *testing.T) {
	rt := &fakeRuntime{}
	o := labOpts(t, rt)
	off := false
	o.Config.Fix.Enabled = &off
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	id := res.Run.Findings[0].ID
	detect := func(context.Context, string) (sandbox.Runtime, error) { return rt, nil }
	out, err := Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: detect, Findings: []string{"SPK-00000000"}})
	if err == nil && len(out) != 0 {
		t.Fatalf("a filter naming another finding re-ran %+v", out)
	}
	out, err = Verify(context.Background(), VerifyOptions{Config: o.Config, RunDir: res.RunDir, DetectRuntime: detect, Findings: []string{id}})
	if err != nil || len(out) != 1 || out[0].FindingID != id {
		t.Fatalf("outcomes = %+v, err = %v", out, err)
	}
}
