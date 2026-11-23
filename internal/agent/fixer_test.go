package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/sandbox"
)

const (
	fixMarker = "SPACKLE-PROOF-0123456789abcdef"
	fixImage  = "python:test"
	fixPoCRel = "spackle_poc/poc.py"
)

var fixTestCmd = []string{"python", "-m", "pytest", "-q"}

// fixKind names the check a sandbox spec belongs to, from its command.
func fixKind(spec sandbox.Spec) string {
	switch {
	case len(spec.Cmd) > 2 && spec.Cmd[2] == "py_compile":
		return "compile"
	case len(spec.Cmd) > 2 && spec.Cmd[2] == "pytest":
		return "tests"
	case len(spec.Cmd) > 1 && spec.Cmd[1] == fixPoCRel:
		return "proof"
	}
	return "other"
}

// fixRuntime answers each kind of check with the result a test chose. A
// kind with no entry exits 0 with no output.
func fixRuntime(results map[string]sandbox.Result) *dbgRuntime {
	return &dbgRuntime{fn: func(spec sandbox.Spec) sandbox.Result { return results[fixKind(spec)] }}
}

func fixPoC() *PoC {
	return &PoC{
		Files:   map[string]string{fixPoCRel: "print('" + fixMarker + "')\n"},
		Command: []string{"python", fixPoCRel}, Marker: fixMarker, Language: "python", Image: fixImage,
	}
}

func fixReply(t *testing.T, files map[string]string) string {
	t.Helper()
	return jsonText(t, map[string]any{"files": files, "why": "The value is bound, not formatted."})
}

func goodFixReply(t *testing.T) string {
	t.Helper()
	return fixReply(t, map[string]string{"app.py": fixedSearch})
}

// failingRuntime is a sandbox whose every run fails to start.
type failingRuntime struct{ err error }

func (failingRuntime) Name() string                              { return "fake-runtime" }
func (failingRuntime) ImagePresent(context.Context, string) bool { return true }
func (failingRuntime) Pull(context.Context, string) error        { return nil }
func (r failingRuntime) Run(context.Context, sandbox.Spec) (sandbox.Result, error) {
	return sandbox.Result{}, r.err
}

func TestVerifyFixAcceptsAPatchThatClosesTheProof(t *testing.T) {
	f := setup(t, budget.Caps{})
	rt := fixRuntime(map[string]sandbox.Result{"proof": {ExitCode: 1, Stderr: "AssertionError: the injected row was not returned"}})
	var purposes []string
	in := FixInput{Language: "python", Image: fixImage, PoC: fixPoC(), TestCmd: fixTestCmd, BaselineTestsPass: true}
	problem, files, patch, verification, verified, err := verifyFix(context.Background(), dbgBox(f, rt, &purposes), in, goodFixReply(t))
	if err != nil {
		t.Fatal(err)
	}
	if problem != "" || !verified {
		t.Fatalf("problem=%q verified=%v", problem, verified)
	}
	want := "verified: the changed files compile; the proof of concept no longer succeeds; the test suite still passes"
	if verification != want {
		t.Fatalf("verification = %q, want %q", verification, want)
	}
	if files["app.py"] != fixedSearch || len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	if !strings.Contains(patch, "--- a/app.py") || !strings.Contains(patch, "+    return conn.execute(\"SELECT id, title FROM notes WHERE title LIKE ?\"") {
		t.Fatalf("patch:\n%s", patch)
	}
	if got := strings.Join(purposes, ","); got != "fix-compile,fix-verify,fix-tests" {
		t.Fatalf("sandbox purposes = %s", got)
	}
	if len(rt.runs) != 3 {
		t.Fatalf("sandbox runs = %d, want 3", len(rt.runs))
	}
	compile, proof, tests := rt.runs[0], rt.runs[1], rt.runs[2]
	if strings.Join(compile.Cmd, " ") != "python -m py_compile app.py" || compile.Files["app.py"] != fixedSearch {
		t.Fatalf("compile check = %+v", compile)
	}
	// The proof runs against the patched file, with the proof's own files added.
	if strings.Join(proof.Cmd, " ") != "python "+fixPoCRel || proof.Files["app.py"] != fixedSearch || !strings.Contains(proof.Files[fixPoCRel], fixMarker) {
		t.Fatalf("proof run = %+v", proof)
	}
	// The suite runs against the patch alone: the proof is not part of the project.
	if strings.Join(tests.Cmd, " ") != "python -m pytest -q" || tests.Files["app.py"] != fixedSearch || len(tests.Files) != 1 {
		t.Fatalf("test run = %+v", tests)
	}
	for _, spec := range rt.runs {
		if spec.Image != fixImage || spec.SourceDir != f.root {
			t.Fatalf("sandbox spec = %+v", spec)
		}
	}
	// The target itself is never written to.
	if raw, _ := os.ReadFile(filepath.Join(f.root, "app.py")); string(raw) != appPy {
		t.Fatal("verifyFix changed the target")
	}
}

func TestVerifyFixRejections(t *testing.T) {
	big := strings.Repeat("x = 1\n", 450)
	cases := []struct {
		name    string
		reply   func(t *testing.T) string
		results map[string]sandbox.Result
		in      func(in *FixInput)
		want    string
		runs    string
	}{
		{
			name:  "patch over 400 changed lines",
			reply: func(t *testing.T) string { return fixReply(t, map[string]string{"app.py": big}) },
			want:  "a fix for one finding should be far smaller", runs: "",
		},
		{
			name:    "compile failure",
			results: map[string]sandbox.Result{"compile": {ExitCode: 1, Stderr: "SyntaxError: invalid syntax"}},
			want:    "the patched code does not compile or parse:\nSyntaxError: invalid syntax", runs: "fix-compile",
		},
		{
			name:    "compile check times out",
			results: map[string]sandbox.Result{"compile": {TimedOut: true}},
			want:    "the patched code does not compile or parse", runs: "fix-compile",
		},
		{
			name:    "proof still succeeds",
			results: map[string]sandbox.Result{"proof": {Stdout: fixMarker + "\n"}},
			want:    "the proof of concept still succeeds against the patched code", runs: "fix-compile,fix-verify",
		},
		{
			// The marker alone decides: a proof that prints it has shown the
			// flaw even when it then exits non-zero.
			name:    "proof prints the marker on stderr and exits non-zero",
			results: map[string]sandbox.Result{"proof": {ExitCode: 1, Stderr: "boom " + fixMarker}},
			want:    "the proof of concept still succeeds against the patched code", runs: "fix-compile,fix-verify",
		},
		{
			name:    "proof times out against the patch",
			results: map[string]sandbox.Result{"proof": {TimedOut: true, ExitCode: -1}},
			want:    "timed out or was killed", runs: "fix-compile,fix-verify",
		},
		{
			name:    "proof is killed against the patch",
			results: map[string]sandbox.Result{"proof": {ExitCode: 137}},
			want:    "timed out or was killed", runs: "fix-compile,fix-verify",
		},
		{
			name:    "passing suite fails after the patch",
			results: map[string]sandbox.Result{"proof": {ExitCode: 1}, "tests": {ExitCode: 1, Stdout: "FAILED test_app.py::test_search"}},
			want:    "the project's tests passed before the patch and fail after it:\nFAILED test_app.py::test_search", runs: "fix-compile,fix-verify,fix-tests",
		},
		{
			name:    "passing suite times out after the patch",
			results: map[string]sandbox.Result{"proof": {ExitCode: 1}, "tests": {TimedOut: true}},
			want:    "the project's tests passed before the patch and fail after it", runs: "fix-compile,fix-verify,fix-tests",
		},
		{
			name:    "passing suite fails after the patch and there is no proof",
			results: map[string]sandbox.Result{"tests": {ExitCode: 2, Stderr: "ERROR collecting test_app.py"}},
			in:      func(in *FixInput) { in.PoC = nil },
			want:    "the project's tests passed before the patch and fail after it:\nERROR collecting test_app.py", runs: "fix-compile,fix-tests",
		},
		{
			name:  "reply is not JSON",
			reply: func(*testing.T) string { return "I cannot do that." },
			want:  "the reply contains no JSON object", runs: "",
		},
		{
			name:  "reply changes no files",
			reply: func(t *testing.T) string { return fixReply(t, map[string]string{}) },
			want:  "the reply changes no files", runs: "",
		},
		{
			name: "reply changes more than three files",
			reply: func(t *testing.T) string {
				return fixReply(t, map[string]string{"a.py": "1", "b.py": "2", "c.py": "3", "d.py": "4"})
			},
			want: "at most 3 are allowed", runs: "",
		},
		{
			name:  "file that does not exist",
			reply: func(t *testing.T) string { return fixReply(t, map[string]string{"missing.py": "x = 1\n"}) },
			want:  "A fix may only change files that exist in the target", runs: "",
		},
		{
			name:  "file outside the target",
			reply: func(t *testing.T) string { return fixReply(t, map[string]string{"../outside-secret.txt": "x\n"}) },
			want:  "A fix may only change files that exist in the target", runs: "",
		},
		{
			name: "test file",
			reply: func(t *testing.T) string {
				return fixReply(t, map[string]string{"test_app.py": "def test_search():\n    pass\n"})
			},
			want: "is a test or proof file; fix the code, not the check", runs: "",
		},
		{
			name:  "unchanged file",
			reply: func(t *testing.T) string { return fixReply(t, map[string]string{"app.py": appPy}) },
			want:  "is unchanged", runs: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, budget.Caps{})
			// A test file the fixer must not be allowed to weaken.
			if err := os.WriteFile(filepath.Join(f.root, "test_app.py"), []byte("def test_search():\n    assert True\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			rt := fixRuntime(tc.results)
			var purposes []string
			in := FixInput{Language: "python", Image: fixImage, PoC: fixPoC(), TestCmd: fixTestCmd, BaselineTestsPass: true}
			if tc.in != nil {
				tc.in(&in)
			}
			reply := goodFixReply(t)
			if tc.reply != nil {
				reply = tc.reply(t)
			}
			problem, files, patch, verification, verified, err := verifyFix(context.Background(), dbgBox(f, rt, &purposes), in, reply)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(problem, tc.want) {
				t.Fatalf("problem = %q, want it to contain %q", problem, tc.want)
			}
			if files != nil || patch != "" || verification != "" || verified {
				t.Fatalf("a rejected patch was returned: files=%v patch=%q verification=%q verified=%v", files, patch, verification, verified)
			}
			if got := strings.Join(purposes, ","); got != tc.runs {
				t.Fatalf("sandbox purposes = %q, want %q", got, tc.runs)
			}
		})
	}
}

func TestVerifyFixWithoutAProofIsUnverified(t *testing.T) {
	f := setup(t, budget.Caps{})
	rt := fixRuntime(nil)
	var purposes []string
	in := FixInput{Language: "python", Image: fixImage}
	problem, files, patch, verification, verified, err := verifyFix(context.Background(), dbgBox(f, rt, &purposes), in, goodFixReply(t))
	if err != nil {
		t.Fatal(err)
	}
	if problem != "" || verified {
		t.Fatalf("problem=%q verified=%v: without a proof a patch cannot be verified", problem, verified)
	}
	want := "unverified: there was no proof of concept to re-run, so the patch is offered but not proven (the changed files compile; no test suite was found to run)"
	if verification != want {
		t.Fatalf("verification = %q, want %q", verification, want)
	}
	if patch == "" || files["app.py"] != fixedSearch {
		t.Fatalf("the unverified patch was not offered: files=%v patch=%q", files, patch)
	}
	if got := strings.Join(purposes, ","); got != "fix-compile" {
		t.Fatalf("sandbox purposes = %q", got)
	}
}

func TestVerifyFixUsesTheSuiteOnlyWhenItPassedBefore(t *testing.T) {
	cases := []struct {
		name     string
		testCmd  []string
		baseline bool
		want     string
		runs     string
	}{
		{"suite passed before", fixTestCmd, true, "the test suite still passes", "fix-compile,fix-verify,fix-tests"},
		{"suite failed before", fixTestCmd, false, "the test suite was not used because it does not pass on the unmodified code", "fix-compile,fix-verify"},
		{"no suite", nil, false, "no test suite was found to run", "fix-compile,fix-verify"},
		// A baseline flag without a command must not invent a test run.
		{"no suite but a baseline flag", nil, true, "no test suite was found to run", "fix-compile,fix-verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, budget.Caps{})
			// The suite would fail if it were run: only the first case runs
			// it, and there it must pass, so make it fail everywhere else.
			results := map[string]sandbox.Result{"proof": {ExitCode: 1}}
			if tc.runs != "fix-compile,fix-verify,fix-tests" {
				results["tests"] = sandbox.Result{ExitCode: 1, Stdout: "FAILED"}
			}
			rt := fixRuntime(results)
			var purposes []string
			in := FixInput{Language: "python", Image: fixImage, PoC: fixPoC(), TestCmd: tc.testCmd, BaselineTestsPass: tc.baseline}
			problem, _, patch, verification, verified, err := verifyFix(context.Background(), dbgBox(f, rt, &purposes), in, goodFixReply(t))
			if err != nil {
				t.Fatal(err)
			}
			if problem != "" || !verified || patch == "" {
				t.Fatalf("problem=%q verified=%v patch=%q", problem, verified, patch)
			}
			if !strings.HasPrefix(verification, "verified: ") || !strings.HasSuffix(verification, tc.want) {
				t.Fatalf("verification = %q, want it to end with %q", verification, tc.want)
			}
			if got := strings.Join(purposes, ","); got != tc.runs {
				t.Fatalf("sandbox purposes = %q, want %q", got, tc.runs)
			}
		})
	}
}

func TestVerifyFixSkipsTheCompileCheckForUnknownLanguages(t *testing.T) {
	f := setup(t, budget.Caps{})
	rt := fixRuntime(map[string]sandbox.Result{"proof": {ExitCode: 1}})
	var purposes []string
	in := FixInput{Language: "ruby", Image: fixImage, PoC: fixPoC()}
	problem, _, _, verification, verified, err := verifyFix(context.Background(), dbgBox(f, rt, &purposes), in, goodFixReply(t))
	if err != nil {
		t.Fatal(err)
	}
	if problem != "" || !verified || verification != "verified: the proof of concept no longer succeeds; no test suite was found to run" {
		t.Fatalf("problem=%q verified=%v verification=%q", problem, verified, verification)
	}
	if got := strings.Join(purposes, ","); got != "fix-verify" {
		t.Fatalf("sandbox purposes = %q", got)
	}
}

func TestCompileCheckCommands(t *testing.T) {
	cases := []struct {
		lang    string
		changed []string
		want    string
	}{
		{"python", []string{"a.py", "pkg/b.py"}, "python -m py_compile a.py pkg/b.py"},
		{"go", []string{"main.go"}, "go build ./..."},
		{"javascript", []string{"index.js"}, "node --check index.js"},
		{"javascript", []string{"a.js", "b.js"}, ""},
		{"typescript", []string{"a.ts"}, ""},
		{"", []string{"a.rb"}, ""},
	}
	for _, tc := range cases {
		if got := strings.Join(compileCheck(tc.lang, tc.changed), " "); got != tc.want {
			t.Errorf("compileCheck(%q, %v) = %q, want %q", tc.lang, tc.changed, got, tc.want)
		}
	}
}

func TestVerifyFixKeepsTheFilesLineEndings(t *testing.T) {
	f := setup(t, budget.Caps{})
	crlf := strings.ReplaceAll(appPy, "\n", "\r\n")
	if err := os.WriteFile(filepath.Join(f.root, "app.py"), []byte(crlf), 0o644); err != nil {
		t.Fatal(err)
	}
	var purposes []string
	// The model answers with LF and without the final newline.
	reply := fixReply(t, map[string]string{"app.py": strings.TrimSuffix(fixedSearch, "\n")})
	problem, files, patch, _, _, err := verifyFix(context.Background(), dbgBox(f, fixRuntime(nil), &purposes), FixInput{Language: "python", Image: fixImage}, reply)
	if err != nil || problem != "" {
		t.Fatalf("problem=%q err=%v", problem, err)
	}
	if want := strings.ReplaceAll(fixedSearch, "\n", "\r\n"); files["app.py"] != want {
		t.Fatalf("patched content = %q, want %q", files["app.py"], want)
	}
	// Only the changed function is in the patch, not every line of the file.
	if strings.Contains(patch, "-def get(conn, note_id)") || strings.Contains(patch, "-import sqlite3") {
		t.Fatalf("the patch rewrites unchanged lines:\n%s", patch)
	}
}

func TestVerifyFixReturnsSandboxAndBudgetErrors(t *testing.T) {
	// One sandbox run is allowed: the compile check takes it, and the proof
	// run is refused by the budget.
	f := setup(t, budget.Caps{Tokens: 1_000_000, USD: 5, Wall: time.Hour, SandboxRuns: 1})
	rt := fixRuntime(nil)
	var purposes []string
	in := FixInput{Language: "python", Image: fixImage, PoC: fixPoC(), TestCmd: fixTestCmd, BaselineTestsPass: true}
	problem, files, patch, _, verified, err := verifyFix(context.Background(), dbgBox(f, rt, &purposes), in, goodFixReply(t))
	if !errors.Is(err, budget.ErrExhausted) {
		t.Fatalf("err = %v, want the sandbox run cap", err)
	}
	if problem != "" || files != nil || patch != "" || verified {
		t.Fatalf("a patch was returned although its checks did not finish: problem=%q patch=%q", problem, patch)
	}
	if len(rt.runs) != 1 {
		t.Fatalf("sandbox runs = %d with a cap of 1", len(rt.runs))
	}

	// A sandbox that cannot run anything is an error, not a rejected patch.
	f = setup(t, budget.Caps{})
	boom := errors.New("the container engine is not responding")
	box := &Box{Runtime: failingRuntime{err: boom}, Budget: f.runner.Budget, Root: f.root}
	problem, files, patch, _, verified, err = verifyFix(context.Background(), box, in, goodFixReply(t))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the runtime error", err)
	}
	if problem != "" || files != nil || patch != "" || verified {
		t.Fatalf("a patch was returned although the sandbox failed: problem=%q patch=%q", problem, patch)
	}
}

func TestFixSendsTheRejectionBackAndReturnsTheVerifiedPatch(t *testing.T) {
	fnd := baseFinding(t)
	f := setup(t, budget.Caps{Tokens: 1_000_000, USD: 5, Wall: time.Hour, SandboxRuns: 20}, llm.Say(goodFixReply(t)), llm.Say(goodFixReply(t)))
	suiteRuns := 0
	rt := &dbgRuntime{fn: func(spec sandbox.Spec) sandbox.Result {
		switch fixKind(spec) {
		case "proof":
			return sandbox.Result{ExitCode: 1}
		case "tests":
			suiteRuns++
			if suiteRuns == 1 {
				return sandbox.Result{ExitCode: 1, Stdout: "FAILED test_app.py::test_search - assert 0 == 1"}
			}
		}
		return sandbox.Result{}
	}}
	var purposes []string
	in := FixInput{Language: "python", Image: fixImage, PoC: fixPoC(), TestCmd: fixTestCmd, BaselineTestsPass: true, MaxAttempts: 3}
	res, err := Fix(context.Background(), f.runner, 0, f.sealer, f.reg, dbgBox(f, rt, &purposes), in, fnd)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified || res.Attempts != 2 || res.Reason != "" || res.Patch == "" || res.Files["app.py"] != fixedSearch {
		t.Fatalf("fix = %+v", res)
	}
	if res.Why != "The value is bound, not formatted." || !strings.Contains(res.Verification, "the test suite still passes") {
		t.Fatalf("fix = %+v", res)
	}
	if len(f.fake.Requests) != 2 {
		t.Fatalf("model requests = %d, want 2", len(f.fake.Requests))
	}
	first, second := f.fake.Requests[0].Messages[0].Text, f.fake.Requests[1].Messages[0].Text
	if strings.Contains(first, "was rejected") || !strings.HasPrefix(first, "Fix this finding.") {
		t.Fatalf("first request:\n%s", first)
	}
	if !strings.Contains(second, "Your previous patch was rejected: the project's tests passed before the patch and fail after it") || !strings.Contains(second, "assert 0 == 1") {
		t.Fatalf("the rejection was not sent back:\n%s", second)
	}
}

func TestFixGivesUpAfterMaxAttemptsAndReturnsNoPatch(t *testing.T) {
	fnd := baseFinding(t)
	f := setup(t, budget.Caps{Tokens: 1_000_000, USD: 5, Wall: time.Hour, SandboxRuns: 20}, llm.Say(goodFixReply(t)), llm.Say(goodFixReply(t)), llm.Say(goodFixReply(t)))
	rt := fixRuntime(map[string]sandbox.Result{"proof": {ExitCode: 1}, "tests": {ExitCode: 1, Stdout: "FAILED test_app.py::test_search"}})
	var purposes []string
	in := FixInput{Language: "python", Image: fixImage, PoC: fixPoC(), TestCmd: fixTestCmd, BaselineTestsPass: true, MaxAttempts: 2}
	res, err := Fix(context.Background(), f.runner, 0, f.sealer, f.reg, dbgBox(f, rt, &purposes), in, fnd)
	if err != nil {
		t.Fatal(err)
	}
	if res.Patch != "" || res.Files != nil || res.Verified || res.Verification != "" {
		t.Fatalf("a patch that breaks the suite was returned: %+v", res)
	}
	if res.Attempts != 2 || !strings.HasPrefix(res.Reason, "No patch passed verification in 2 attempt(s). Last problem: the project's tests passed before the patch and fail after it") {
		t.Fatalf("attempts=%d reason=%q", res.Attempts, res.Reason)
	}
	if len(f.fake.Requests) != 2 || f.fake.Remaining() != 1 {
		t.Fatalf("model requests = %d, want 2 (the attempt limit)", len(f.fake.Requests))
	}
}

func TestFixStopsOnARefusal(t *testing.T) {
	fnd := baseFinding(t)
	f := setup(t, budget.Caps{}, llm.Response{StopReason: llm.StopRefusal, RefusalNote: "declined"})
	rt := fixRuntime(nil)
	var purposes []string
	res, err := Fix(context.Background(), f.runner, 0, f.sealer, f.reg, dbgBox(f, rt, &purposes), FixInput{Language: "python", Image: fixImage, PoC: fixPoC()}, fnd)
	if err != nil {
		t.Fatal(err)
	}
	if res.Patch != "" || res.Verified || res.Attempts != 1 || !strings.Contains(res.Reason, "did not produce a patch") {
		t.Fatalf("fix = %+v", res)
	}
	if len(rt.runs) != 0 {
		t.Fatalf("%d sandbox runs happened although no patch was written", len(rt.runs))
	}
}
