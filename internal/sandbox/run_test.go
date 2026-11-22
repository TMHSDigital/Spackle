package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCLISource is a stand-in for docker: it records how it was called, echoes its arguments
// and the staged files as JSON, and exits or sleeps as told through FAKE_* variables.
const fakeCLISource = `package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func envInt(key string) int {
	n, _ := strconv.Atoi(os.Getenv(key))
	return n
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		os.Exit(2)
	}
	if p := os.Getenv("FAKE_LOG"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprintln(f, strings.Join(args, " "))
			f.Close()
		}
	}
	switch args[0] {
	case "version":
		if n := envInt("FAKE_VERSION_EXIT"); n != 0 {
			fmt.Fprintln(os.Stderr, "Cannot connect to the engine")
			os.Exit(n)
		}
		fmt.Println("99.0.0")
	case "image":
		os.Exit(envInt("FAKE_IMAGE_EXIT"))
	case "container":
		// Inspect after kill and rm: the container is gone.
		os.Exit(1)
	case "kill":
		// Tell a sleeping "run" to stop, as killing a container ends the real CLI.
		os.WriteFile(os.Getenv("FAKE_LOG")+".killed", nil, 0o600)
	case "pull":
		if n := envInt("FAKE_PULL_EXIT"); n != 0 {
			fmt.Fprintln(os.Stderr, "pull access denied")
			os.Exit(n)
		}
	case "run":
		staged := map[string]string{}
		for _, a := range args {
			root, ok := strings.CutPrefix(a, "type=bind,source=")
			if !ok {
				continue
			}
			root, ok = strings.CutSuffix(root, ",target=/spackle-in,readonly")
			if !ok {
				continue
			}
			filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(root, p)
				b, _ := os.ReadFile(p)
				staged[filepath.ToSlash(rel)] = string(b)
				return nil
			})
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"args": args, "staged": staged})
		fmt.Fprint(os.Stderr, os.Getenv("FAKE_STDERR"))
		if n := envInt("FAKE_BIG"); n > 0 {
			os.Stdout.WriteString(strings.Repeat("x", n))
		}
		if d, err := time.ParseDuration(os.Getenv("FAKE_SLEEP")); err == nil {
			for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
				if _, err := os.Stat(os.Getenv("FAKE_LOG") + ".killed"); err == nil && os.Getenv("FAKE_IGNORE_KILL") == "" {
					os.Exit(137)
				}
			}
		}
		os.Exit(envInt("FAKE_EXIT"))
	}
}
`

var (
	fakeOnce sync.Once
	fakeDir  string
	fakePath string
	fakeErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeDir != "" {
		_ = os.RemoveAll(fakeDir)
	}
	os.Exit(code)
}

// fakeCLI builds the fake once per test binary, named docker so Detect can find it on PATH.
// It returns the directory and the executable path.
func fakeCLI(t *testing.T) (dir, path string) {
	t.Helper()
	fakeOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			fakeErr = err
			return
		}
		fakeDir, fakeErr = os.MkdirTemp("", "spackle-fakecli-")
		if fakeErr != nil {
			return
		}
		src := filepath.Join(fakeDir, "src")
		bin := filepath.Join(fakeDir, "bin")
		for _, d := range []string{src, bin} {
			if fakeErr = os.Mkdir(d, 0o700); fakeErr != nil {
				return
			}
		}
		if fakeErr = os.WriteFile(filepath.Join(src, "main.go"), []byte(fakeCLISource), 0o600); fakeErr != nil {
			return
		}
		fakePath = filepath.Join(bin, "docker")
		if runtime.GOOS == "windows" {
			fakePath += ".exe"
		}
		cmd := exec.Command(goTool, "build", "-o", fakePath, "main.go")
		cmd.Dir = src
		// The fake is a single file outside any module or workspace.
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
		if out, err := cmd.CombinedOutput(); err != nil {
			fakeErr = errors.New("go build failed: " + err.Error() + ": " + string(out))
		}
	})
	if fakeErr != nil {
		t.Skipf("cannot build the fake container CLI (the go tool is needed for this test): %v", fakeErr)
	}
	return filepath.Dir(fakePath), fakePath
}

func fakeRuntime(t *testing.T) (*cliRuntime, string) {
	t.Helper()
	_, path := fakeCLI(t)
	log := filepath.Join(t.TempDir(), "calls.log")
	t.Setenv("FAKE_LOG", log)
	for _, k := range []string{"FAKE_EXIT", "FAKE_STDERR", "FAKE_BIG", "FAKE_SLEEP", "FAKE_IMAGE_EXIT", "FAKE_PULL_EXIT", "FAKE_VERSION_EXIT", "FAKE_IGNORE_KILL"} {
		t.Setenv(k, "")
	}
	return newCLIRuntime("docker", path), log
}

func readLog(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

type fakeOutput struct {
	Args   []string          `json:"args"`
	Staged map[string]string `json:"staged"`
}

func decodeFake(t *testing.T, stdout string) fakeOutput {
	t.Helper()
	line, _, _ := strings.Cut(stdout, "\n")
	var out fakeOutput
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("fake CLI output is not JSON: %v: %q", err, line)
	}
	return out
}

// stageRoot returns the private temp directory behind the /spackle-in mount in argv.
func stageRoot(t *testing.T, argv []string) string {
	t.Helper()
	for _, a := range argv {
		if root, ok := strings.CutPrefix(a, "type=bind,source="); ok {
			if root, ok = strings.CutSuffix(root, ",target=/spackle-in,readonly"); ok {
				return filepath.Dir(root)
			}
		}
	}
	t.Fatalf("no stage mount in %q", argv)
	return ""
}

func containerNameFrom(t *testing.T, argv []string) string {
	t.Helper()
	i := slices.Index(argv, "--name")
	if i < 0 || i+1 >= len(argv) {
		t.Fatalf("no --name in %q", argv)
	}
	return argv[i+1]
}

func TestRunFakeResult(t *testing.T) {
	rt, log := fakeRuntime(t)
	t.Setenv("FAKE_EXIT", "7")
	t.Setenv("FAKE_STDERR", "boom")
	spec := Spec{
		Image: testImage,
		Cmd:   []string{"sh", "poc/run.sh"},
		Files: map[string]string{"poc/run.sh": "echo hi", "top.txt": "top"},
	}
	res, err := rt.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("a non-zero exit of the contained program must not be an error: %v", err)
	}
	if res.ExitCode != 7 || res.TimedOut {
		t.Errorf("ExitCode = %d, TimedOut = %v; want 7, false", res.ExitCode, res.TimedOut)
	}
	if res.Stderr != "boom" {
		t.Errorf("Stderr = %q, want boom", res.Stderr)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", res.Duration)
	}
	wantIso := "docker, network none, capabilities dropped, read-only root, non-root user, 1024 MB memory, 2 CPUs, 256 processes, 2m0s timeout"
	if res.Isolation != wantIso {
		t.Errorf("Isolation = %q, want %q", res.Isolation, wantIso)
	}
	out := decodeFake(t, res.Stdout)
	if res.Argv[0] != rt.cli || !slices.Equal(res.Argv[1:], out.Args) {
		t.Errorf("Argv = %q does not match what the CLI received: %q", res.Argv, out.Args)
	}
	if out.Staged["poc/run.sh"] != "echo hi" || out.Staged["top.txt"] != "top" || len(out.Staged) != 2 {
		t.Errorf("staged files seen by the CLI = %v", out.Staged)
	}
	if name := containerNameFrom(t, res.Argv); !regexp.MustCompile(`^spackle-[0-9a-f]{12}$`).MatchString(name) {
		t.Errorf("container name %q is not spackle- plus 12 hex characters", name)
	}
	if root := stageRoot(t, res.Argv); !strings.HasPrefix(filepath.Base(root), "spackle-stage-") {
		t.Errorf("unexpected stage root %q", root)
	} else if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stage directory %q was not removed after the run (stat error: %v)", root, err)
	}
	calls := readLog(t, log)
	if len(calls) != 2 || !strings.HasPrefix(calls[0], "image inspect") || !strings.HasPrefix(calls[1], "run --rm") {
		t.Errorf("unexpected CLI calls: %q", calls)
	}
}

func TestRunFakeDistinctNames(t *testing.T) {
	rt, _ := fakeRuntime(t)
	a, err := rt.Run(context.Background(), baseSpec())
	if err != nil {
		t.Fatal(err)
	}
	b, err := rt.Run(context.Background(), baseSpec())
	if err != nil {
		t.Fatal(err)
	}
	if containerNameFrom(t, a.Argv) == containerNameFrom(t, b.Argv) {
		t.Error("two runs used the same container name")
	}
	if a.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", a.ExitCode)
	}
}

func TestRunFakeTimeout(t *testing.T) {
	rt, log := fakeRuntime(t)
	t.Setenv("FAKE_SLEEP", "60s")
	spec := baseSpec()
	spec.Files = map[string]string{"a.txt": "a"}
	spec.Profile.Timeout = time.Second
	start := time.Now()
	res, err := rt.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("a timeout is a Result, not an error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("Run took %v after a 1s timeout", elapsed)
	}
	if !res.TimedOut || res.ExitCode != -1 {
		t.Errorf("TimedOut = %v, ExitCode = %d; want true, -1", res.TimedOut, res.ExitCode)
	}
	name := containerNameFrom(t, res.Argv)
	calls := readLog(t, log)
	if !slices.Contains(calls, "kill "+name) || !slices.Contains(calls, "rm -f "+name) {
		t.Errorf("the container was not killed and removed after the timeout: %q", calls)
	}
	if _, err := os.Stat(stageRoot(t, res.Argv)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stage directory was not removed after a timeout (stat error: %v)", err)
	}
}

func TestRunFakeTimeoutKillsStuckCLI(t *testing.T) {
	// The engine ignores the kill: the CLI itself must still be stopped by the backstop.
	rt, _ := fakeRuntime(t)
	t.Setenv("FAKE_SLEEP", "90s")
	t.Setenv("FAKE_IGNORE_KILL", "1")
	spec := baseSpec()
	spec.Profile.Timeout = 500 * time.Millisecond
	start := time.Now()
	res, err := rt.Run(context.Background(), spec)
	if err != nil || !res.TimedOut || res.ExitCode != -1 {
		t.Errorf("TimedOut = %v, ExitCode = %d, err = %v; want true, -1, nil", res.TimedOut, res.ExitCode, err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("Run took %v; the stuck CLI was not killed by the backstop", elapsed)
	}
}

func TestRunFakeCancel(t *testing.T) {
	rt, log := fakeRuntime(t)
	t.Setenv("FAKE_SLEEP", "60s")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	res, err := rt.Run(ctx, baseSpec())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res.TimedOut || res.ExitCode != -1 {
		t.Errorf("TimedOut = %v, ExitCode = %d; want false, -1", res.TimedOut, res.ExitCode)
	}
	if calls := readLog(t, log); !slices.Contains(calls, "kill "+containerNameFrom(t, res.Argv)) {
		t.Errorf("the container was not killed after cancel: %q", calls)
	}
}

func TestRunFakeEngineFailure(t *testing.T) {
	for _, code := range []string{"125", "126", "127"} {
		rt, _ := fakeRuntime(t)
		t.Setenv("FAKE_EXIT", code)
		t.Setenv("FAKE_STDERR", "docker: Error response from daemon: something broke.\n")
		_, err := rt.Run(context.Background(), baseSpec())
		if err == nil {
			t.Fatalf("exit %s with an engine message must be an error", code)
		}
		if !strings.Contains(err.Error(), "something broke") || !strings.Contains(err.Error(), "docker pull "+testImage) {
			t.Errorf("error lacks the engine message or the next step: %v", err)
		}
	}
}

func TestRunFakeProgramExit127IsResult(t *testing.T) {
	rt, _ := fakeRuntime(t)
	t.Setenv("FAKE_EXIT", "127")
	t.Setenv("FAKE_STDERR", "sh: nosuchtool: not found\n")
	res, err := rt.Run(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("a contained program exiting 127 without an engine message is a Result: %v", err)
	}
	if res.ExitCode != 127 {
		t.Errorf("ExitCode = %d, want 127", res.ExitCode)
	}
}

func TestRunFakeBootstrapFailure(t *testing.T) {
	rt, _ := fakeRuntime(t)
	t.Setenv("FAKE_EXIT", "122")
	t.Setenv("FAKE_STDERR", "cp: can't open '/src/x': Permission denied\nspackle-bootstrap: could not copy the source into /work\n")
	if _, err := rt.Run(context.Background(), baseSpec()); err == nil {
		t.Fatal("a failed work directory setup must be an error, not a program result")
	}
	t.Setenv("FAKE_STDERR", "unrelated")
	res, err := rt.Run(context.Background(), baseSpec())
	if err != nil || res.ExitCode != 122 {
		t.Errorf("exit 122 without the bootstrap marker is a program result: %d, %v", res.ExitCode, err)
	}
}

func TestRunFakeImageMissing(t *testing.T) {
	rt, log := fakeRuntime(t)
	t.Setenv("FAKE_IMAGE_EXIT", "1")
	_, err := rt.Run(context.Background(), baseSpec())
	if err == nil || !strings.Contains(err.Error(), "docker pull "+testImage) {
		t.Fatalf("a missing image must be an error naming the pull command, got %v", err)
	}
	for _, call := range readLog(t, log) {
		if strings.HasPrefix(call, "run") {
			t.Errorf("run was invoked although the image is missing: %q", call)
		}
	}
}

func TestRunFakeOutputCap(t *testing.T) {
	rt, _ := fakeRuntime(t)
	t.Setenv("FAKE_BIG", "2097152")
	res, err := rt.Run(context.Background(), baseSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != outputCap+len(truncatedNote) || !strings.HasSuffix(res.Stdout, truncatedNote) {
		t.Errorf("Stdout length = %d, want the 1 MiB cap plus the truncation note", len(res.Stdout))
	}
}

func TestRunFakeInvalidSpecRunsNothing(t *testing.T) {
	rt, log := fakeRuntime(t)
	spec := baseSpec()
	spec.Files = map[string]string{"../escape": "x"}
	if _, err := rt.Run(context.Background(), spec); err == nil {
		t.Fatal("expected a validation error")
	}
	if calls := readLog(t, log); len(calls) != 0 {
		t.Errorf("the CLI was invoked for an invalid spec: %q", calls)
	}
}

func TestRunMissingCLI(t *testing.T) {
	rt := newCLIRuntime("docker", filepath.Join(t.TempDir(), "no-such-docker"))
	if _, err := rt.Run(context.Background(), baseSpec()); err == nil {
		t.Fatal("expected an error when the CLI does not exist")
	}
}

func TestFakeImagePresentAndPull(t *testing.T) {
	rt, log := fakeRuntime(t)
	ctx := context.Background()
	if rt.Name() != "docker" {
		t.Errorf("Name() = %q", rt.Name())
	}
	if !rt.ImagePresent(ctx, testImage) {
		t.Error("ImagePresent = false, want true")
	}
	if err := rt.Pull(ctx, testImage); err != nil {
		t.Errorf("Pull: %v", err)
	}
	if rt.ImagePresent(ctx, "--help") {
		t.Error("ImagePresent accepted an option-like image")
	}
	if err := rt.Pull(ctx, "--all-tags"); err == nil {
		t.Error("Pull accepted an option-like image")
	}
	if calls := readLog(t, log); len(calls) != 2 {
		t.Errorf("an invalid image reached the CLI: %q", calls)
	}
	t.Setenv("FAKE_IMAGE_EXIT", "1")
	t.Setenv("FAKE_PULL_EXIT", "1")
	if rt.ImagePresent(ctx, testImage) {
		t.Error("ImagePresent = true, want false")
	}
	if err := rt.Pull(ctx, testImage); err == nil || !strings.Contains(err.Error(), "pull access denied") {
		t.Errorf("Pull error should carry the engine message, got %v", err)
	}
}

func TestDetectFake(t *testing.T) {
	dir, _ := fakeCLI(t)
	fakeRuntime(t)
	t.Setenv("PATH", dir)
	ctx := context.Background()
	for _, preferred := range []string{"auto", "docker"} {
		rt, err := Detect(ctx, preferred)
		if err != nil {
			t.Fatalf("Detect(%q): %v", preferred, err)
		}
		if rt.Name() != "docker" {
			t.Errorf("Detect(%q).Name() = %q, want docker", preferred, rt.Name())
		}
	}
	if _, err := Detect(ctx, "podman"); !errors.Is(err, ErrNoRuntime) {
		t.Errorf(`Detect("podman") with only docker on PATH = %v, want ErrNoRuntime`, err)
	}
	t.Setenv("FAKE_VERSION_EXIT", "1")
	_, err := Detect(ctx, "auto")
	if !errors.Is(err, ErrNoRuntime) {
		t.Fatalf("Detect with a dead engine = %v, want ErrNoRuntime", err)
	}
	if !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("error should say the engine did not answer: %v", err)
	}
}

func TestWriteStage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "in")
	if err := writeStage(root, map[string]string{"a/b/c.txt": "c", "d.txt": "d"}); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{"a/b/c.txt": "c", "d.txt": "d"} {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", rel, got, err, want)
		}
	}
	if runtime.GOOS != "windows" {
		for rel, want := range map[string]os.FileMode{".": 0o755, "a": 0o755, "a/b/c.txt": 0o644} {
			info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil || info.Mode().Perm() != want {
				t.Errorf("mode of %s = %v, %v; want %v", rel, info.Mode().Perm(), err, want)
			}
		}
	}
	if err := writeStage(filepath.Join(t.TempDir(), "in"), map[string]string{"../x": "x"}); err == nil {
		t.Error("writeStage must refuse a path that leaves the stage directory")
	}
}
