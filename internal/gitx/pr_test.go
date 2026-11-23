package gitx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The fake GitHub CLI is this test binary under the name "gh". When the
// binary is started under that name, TestMain runs fakeGHMain and never
// reaches the tests. No compiler is needed to build it.
const (
	fakeGHLogEnv    = "SPACKLE_TEST_FAKE_GH_LOG"
	fakeGHExitEnv   = "SPACKLE_TEST_FAKE_GH_EXIT"
	fakeGHStdoutEnv = "SPACKLE_TEST_FAKE_GH_STDOUT"
	fakeGHStderrEnv = "SPACKLE_TEST_FAKE_GH_STDERR"
)

// fakeGHCall is what the fake records about one invocation.
type fakeGHCall struct {
	Args           []string `json:"args"`
	Dir            string   `json:"dir"`
	BodyFile       string   `json:"body_file"`
	Body           string   `json:"body"`
	BodyErr        string   `json:"body_err"`
	PromptDisabled string   `json:"prompt_disabled"`
	TerminalPrompt string   `json:"terminal_prompt"`
}

var (
	fakeGHOnce sync.Once
	fakeGHDir  string
	fakeGHErr  error
)

func TestMain(m *testing.M) {
	name := strings.ToLower(filepath.Base(os.Args[0]))
	if strings.TrimSuffix(name, ".exe") == "gh" {
		os.Exit(fakeGHMain())
	}
	code := m.Run()
	if fakeGHDir != "" {
		_ = os.RemoveAll(fakeGHDir)
	}
	os.Exit(code)
}

// fakeGHMain records the call in the file named by the environment, prints
// the configured output and returns the configured exit code.
func fakeGHMain() int {
	call := fakeGHCall{
		Args:           os.Args[1:],
		PromptDisabled: os.Getenv("GH_PROMPT_DISABLED"),
		TerminalPrompt: os.Getenv("GIT_TERMINAL_PROMPT"),
	}
	call.Dir, _ = os.Getwd()
	for i, a := range call.Args {
		if a == "--body-file" && i+1 < len(call.Args) {
			call.BodyFile = call.Args[i+1]
			b, err := os.ReadFile(call.BodyFile)
			call.Body = string(b)
			if err != nil {
				call.BodyErr = err.Error()
			}
		}
	}
	if log := os.Getenv(fakeGHLogEnv); log != "" {
		data, err := json.Marshal(call)
		if err == nil {
			err = os.WriteFile(log, data, 0o600)
		}
		if err != nil {
			_, _ = io.WriteString(os.Stderr, "fake gh: "+err.Error()+"\n")
			return 97
		}
	}
	_, _ = io.WriteString(os.Stdout, os.Getenv(fakeGHStdoutEnv))
	_, _ = io.WriteString(os.Stderr, os.Getenv(fakeGHStderrEnv))
	code, _ := strconv.Atoi(os.Getenv(fakeGHExitEnv))
	return code
}

// installFakeGH copies the test binary to a directory as "gh", once per test
// binary, and returns that directory.
func installFakeGH(t *testing.T) string {
	t.Helper()
	fakeGHOnce.Do(func() {
		var self string
		self, fakeGHErr = os.Executable()
		if fakeGHErr != nil {
			return
		}
		fakeGHDir, fakeGHErr = os.MkdirTemp("", "spackle-fakegh-")
		if fakeGHErr != nil {
			return
		}
		name := "gh"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		fakeGHErr = copyExecutable(self, filepath.Join(fakeGHDir, name))
	})
	if fakeGHErr != nil {
		t.Skipf("cannot install the fake GitHub CLI: %v", fakeGHErr)
	}
	return fakeGHDir
}

func copyExecutable(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	_, err = io.Copy(out, in)
	return err
}

// fakeGH puts the fake GitHub CLI first on PATH for the test, configures
// its answer, and returns the path of the file it records its call in.
func fakeGH(t *testing.T, exit int, stdout, stderr string) string {
	t.Helper()
	dir := installFakeGH(t)
	log := filepath.Join(t.TempDir(), "gh-call.json")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(fakeGHLogEnv, log)
	t.Setenv(fakeGHExitEnv, strconv.Itoa(exit))
	t.Setenv(fakeGHStdoutEnv, stdout)
	t.Setenv(fakeGHStderrEnv, stderr)
	return log
}

// readGHCall returns the recorded call, or false when the fake never ran.
func readGHCall(t *testing.T, log string) (fakeGHCall, bool) {
	t.Helper()
	data, err := os.ReadFile(log)
	if errors.Is(err, os.ErrNotExist) {
		return fakeGHCall{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var call fakeGHCall
	if err := json.Unmarshal(data, &call); err != nil {
		t.Fatalf("the fake gh log is not JSON: %v: %q", err, data)
	}
	return call, true
}

const prBranch = "spackle/fix-run-1"

// newPRRepo creates a repository whose "origin" remote is a local bare
// repository holding main, with a fix branch checked out that has one commit
// origin does not have. It returns the work tree, the bare repository and
// the commit of the fix branch.
func newPRRepo(t *testing.T) (dir, origin, head string) {
	t.Helper()
	dir = newRepo(t)
	origin = newBare(t)
	git(t, dir, "remote", "add", "origin", origin)
	git(t, dir, "push", "-q", "origin", "main")
	git(t, dir, "checkout", "-q", "-b", prBranch)
	writeFile(t, dir, "a.txt", "fixed\n")
	head = commit(t, dir, "fix: something")
	return dir, origin, head
}

// remoteBranch returns the commit a branch points at in a bare repository,
// or "" when the branch does not exist there.
func remoteBranch(t *testing.T, bare, branch string) string {
	t.Helper()
	out := git(t, bare, "for-each-ref", "--format=%(objectname)", "refs/heads/"+branch)
	return strings.TrimSpace(out)
}

func TestOpenPRRefusesAnInvalidBranchBeforeAnythingRuns(t *testing.T) {
	dir, origin, _ := newPRRepo(t)
	log := fakeGH(t, 0, "https://example.test/pr/1\n", "")
	for _, branch := range []string{"", "-x", "--force", "-"} {
		url, err := OpenPR(context.Background(), PRRequest{Dir: dir, Branch: branch, Title: "t", Body: "b"})
		if err == nil || url != "" {
			t.Errorf("branch %q: url = %q, err = %v; want it refused", branch, url, err)
			continue
		}
		if want := "branch " + strconv.Quote(branch) + " is not valid"; err.Error() != want {
			t.Errorf("branch %q: err = %q, want %q", branch, err, want)
		}
	}
	if _, ran := readGHCall(t, log); ran {
		t.Error("gh ran for a branch that was refused")
	}
	if got := git(t, origin, "for-each-ref", "--format=%(refname)"); got != "refs/heads/main" {
		t.Errorf("origin holds %q after refused requests, want only refs/heads/main", got)
	}
}

func TestOpenPRPushesTheBranchAndOpensADraft(t *testing.T) {
	dir, origin, head := newPRRepo(t)
	const url = "https://example.test/owner/repo/pull/7"
	log := fakeGH(t, 0, "\n"+url+"\n", "")
	// Shell metacharacters must arrive as one literal argument, and the body
	// must arrive byte for byte.
	title := `fix: quote "user" input; $(touch pwned) && echo 'x' | cat`
	body := "## Summary\r\n\nLine two with `code` and \"quotes\".\n\n- item\n\ttabbed\nno trailing newline"

	got, err := OpenPR(context.Background(), PRRequest{Dir: dir, Branch: prBranch, Title: title, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if got != url {
		t.Errorf("url = %q, want gh's output trimmed: %q", got, url)
	}

	if sha := remoteBranch(t, origin, prBranch); sha != head {
		t.Errorf("origin has %s at %q, want the pushed commit %s", prBranch, sha, head)
	}
	if up := git(t, dir, "rev-parse", "--abbrev-ref", prBranch+"@{upstream}"); up != "origin/"+prBranch {
		t.Errorf("upstream of the branch = %q, want origin/%s", up, prBranch)
	}

	call, ran := readGHCall(t, log)
	if !ran {
		t.Fatal("gh was not run")
	}
	want := []string{"pr", "create", "--draft", "--head", prBranch, "--title", title, "--body-file", call.BodyFile}
	if len(call.Args) != len(want) {
		t.Fatalf("gh arguments = %q, want %q", call.Args, want)
	}
	for i := range want {
		if call.Args[i] != want[i] {
			t.Fatalf("gh argument %d = %q, want %q (all: %q)", i, call.Args[i], want[i], call.Args)
		}
	}
	if call.BodyFile == "" || !filepath.IsAbs(call.BodyFile) {
		t.Errorf("body file = %q, want an absolute path", call.BodyFile)
	}
	if call.BodyErr != "" {
		t.Errorf("gh could not read the body file: %s", call.BodyErr)
	}
	if call.Body != body {
		t.Errorf("body file held %q, want %q", call.Body, body)
	}
	if _, err := os.Lstat(call.BodyFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the body file %s was not removed (stat error: %v)", call.BodyFile, err)
	}
	if !sameDir(t, call.Dir, dir) {
		t.Errorf("gh ran in %q, want the work tree %q", call.Dir, dir)
	}
	if call.PromptDisabled != "1" || call.TerminalPrompt != "0" {
		t.Errorf("gh saw GH_PROMPT_DISABLED=%q GIT_TERMINAL_PROMPT=%q, want 1 and 0", call.PromptDisabled, call.TerminalPrompt)
	}
	if _, err := os.Lstat(filepath.Join(dir, "pwned")); err == nil {
		t.Error("the title was interpreted by a shell")
	}
}

func TestOpenPRWhenGHFailsSaysTheBranchWasPushed(t *testing.T) {
	dir, origin, head := newPRRepo(t)
	log := fakeGH(t, 1, "", "\npull request create failed: GraphQL: No commits between main and the branch\nsecond line\n")

	url, err := OpenPR(context.Background(), PRRequest{Dir: dir, Branch: prBranch, Title: "fix: something", Body: "body"})
	if err == nil || url != "" {
		t.Fatalf("url = %q, err = %v; want an error", url, err)
	}
	want := "gh pr create failed: pull request create failed: GraphQL: No commits between main and the branch. " +
		"The branch " + prBranch + " was pushed; open the pull request by hand"
	if err.Error() != want {
		t.Errorf("err = %q\nwant  %q", err, want)
	}
	if sha := remoteBranch(t, origin, prBranch); sha != head {
		t.Errorf("origin has %s at %q, want the pushed commit %s", prBranch, sha, head)
	}
	call, ran := readGHCall(t, log)
	if !ran {
		t.Fatal("gh was not run")
	}
	if _, err := os.Lstat(call.BodyFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the body file %s was not removed after a failure (stat error: %v)", call.BodyFile, err)
	}
}

func TestOpenPRWithoutGHGivesTheInstallHintAndDoesNotPush(t *testing.T) {
	dir, origin, _ := newPRRepo(t)
	t.Run("gh is not on PATH", func(t *testing.T) {
		// An empty directory as the whole PATH: neither a real gh nor the
		// fake can be found. git is not needed, the check comes first.
		t.Setenv("PATH", t.TempDir())
		url, err := OpenPR(context.Background(), PRRequest{Dir: dir, Branch: prBranch, Title: "t", Body: "b"})
		if err == nil || url != "" {
			t.Fatalf("url = %q, err = %v; want an error", url, err)
		}
		for _, want := range []string{"the GitHub CLI (gh) is not installed", `"gh auth login"`, "push the branch and open the pull request yourself"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, want it to contain %q", err, want)
			}
		}
	})
	// PATH is restored here, so git can be asked what origin holds.
	if sha := remoteBranch(t, origin, prBranch); sha != "" {
		t.Errorf("the branch was pushed (%s) although gh is missing", sha)
	}
}

func TestOpenPRWhenThePushFailsDoesNotRunGH(t *testing.T) {
	dir := newRepo(t)
	git(t, dir, "checkout", "-q", "-b", prBranch)
	log := fakeGH(t, 0, "https://example.test/pr/1\n", "")

	// The repository has no remote named origin.
	url, err := OpenPR(context.Background(), PRRequest{Dir: dir, Branch: prBranch, Title: "t", Body: "b"})
	if err == nil || url != "" {
		t.Fatalf("url = %q, err = %v; want an error", url, err)
	}
	for _, want := range []string{"push " + prBranch + " to origin: ", "Check that the remote exists and that you may push to it"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
	if strings.ContainsAny(err.Error(), "\r\n") {
		t.Errorf("err = %q, want one line", err)
	}
	if _, ran := readGHCall(t, log); ran {
		t.Error("gh ran although the push failed")
	}
}
