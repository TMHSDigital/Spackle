package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// integrationRuntime returns a real runtime with the test image present. Without one the test
// is skipped, unless SPACKLE_REQUIRE_RUNTIME=1 (set in CI on Linux) so the job cannot pass by
// skipping everything.
func integrationRuntime(t *testing.T) (Runtime, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	t.Cleanup(cancel)
	unavailable := func(msg string, err error) {
		t.Helper()
		if os.Getenv("SPACKLE_REQUIRE_RUNTIME") == "1" {
			t.Fatalf("SPACKLE_REQUIRE_RUNTIME=1 but %s: %v", msg, err)
		}
		t.Skip(msg)
	}
	rt, err := Detect(ctx, "auto")
	if err != nil {
		unavailable("no container runtime found; install Docker or Podman to run sandbox tests", err)
	}
	if !rt.ImagePresent(ctx, testImage) {
		if err := rt.Pull(ctx, testImage); err != nil {
			unavailable("could not pull "+testImage+"; pull it by hand to run sandbox tests", err)
		}
	}
	return rt, ctx
}

func mustRun(t *testing.T, rt Runtime, ctx context.Context, spec Spec) Result { //nolint:revive // context-as-argument: t first reads better in a test helper
	t.Helper()
	res, err := rt.Run(ctx, spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// snapshot returns the sorted listing of dir with a content hash per file.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		line := filepath.ToSlash(rel)
		if !d.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			line += " " + hex.EncodeToString(sum[:])
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func writeSource(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for rel, content := range map[string]string{"a.txt": "alpha\n", "sub/b.txt": "beta\n"} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationDefaultProfileHasNoNetwork(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	res := mustRun(t, rt, ctx, Spec{Image: testImage, Cmd: []string{"wget", "-q", "-T", "3", "-O-", "http://1.1.1.1"}})
	if res.ExitCode == 0 {
		t.Fatalf("wget reached the network from the default profile: stdout %q", res.Stdout)
	}
	if !strings.Contains(res.Isolation, "network none") {
		t.Errorf("Isolation = %q", res.Isolation)
	}
}

func TestIntegrationSourceMountIsReadOnly(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	src := t.TempDir()
	writeSource(t, src)
	before := snapshot(t, src)
	res := mustRun(t, rt, ctx, Spec{
		Image:     testImage,
		Cmd:       []string{"sh", "-c", "echo x > /src/new || exit 3; echo changed > /src/a.txt"},
		SourceDir: src,
	})
	if res.ExitCode == 0 {
		t.Errorf("writing to /src succeeded: stdout %q stderr %q", res.Stdout, res.Stderr)
	}
	if after := snapshot(t, src); after != before {
		t.Errorf("the host source directory changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestIntegrationWorkDirIsWritableWithSourceAndFiles(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	src := t.TempDir()
	writeSource(t, src)
	res := mustRun(t, rt, ctx, Spec{
		Image:     testImage,
		Cmd:       []string{"sh", "-c", "pwd && cat ../a.txt b.txt ../poc/poc.txt && echo written > ../new.txt && cat /work/new.txt && echo $MARK"},
		SourceDir: src,
		// a.txt is also staged to check that Files win over the source copy.
		Files:  map[string]string{"poc/poc.txt": "proof\n", "a.txt": "patched\n"},
		Subdir: "sub",
		Env:    map[string]string{"MARK": "env ok"},
	})
	want := "/work/sub\npatched\nbeta\nproof\nwritten\nenv ok\n"
	if res.ExitCode != 0 || res.Stdout != want {
		t.Errorf("exit %d, stdout %q, stderr %q; want stdout %q", res.ExitCode, res.Stdout, res.Stderr, want)
	}
	if got, err := os.ReadFile(filepath.Join(src, "a.txt")); err != nil || string(got) != "alpha\n" {
		t.Errorf("host a.txt = %q, %v; the staged file must not reach the host source", got, err)
	}
}

func TestIntegrationProcessIsNotRoot(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	res := mustRun(t, rt, ctx, Spec{Image: testImage, Cmd: []string{"id", "-u"}})
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "65534" {
		t.Errorf("id -u: exit %d, stdout %q, stderr %q; want 65534", res.ExitCode, res.Stdout, res.Stderr)
	}
}

// The timeout tests are not parallel: they assert wall time, which a busy engine would skew.

func assertContainerGone(t *testing.T, ctx context.Context, rt Runtime, res Result) { //nolint:revive // context-as-argument: t first reads better in a test helper
	t.Helper()
	name := containerNameFrom(t, res.Argv)
	// Checked twice: a container whose creation was still in flight when the timeout fired
	// would only show up a moment later.
	for _, wait := range []time.Duration{0, 3 * time.Second} {
		time.Sleep(wait)
		out, err := exec.CommandContext(ctx, res.Argv[0], "ps", "-a", "--filter", "name="+name, "-q").Output()
		if err != nil {
			t.Fatalf("%s ps: %v", rt.Name(), err)
		}
		if strings.TrimSpace(string(out)) != "" {
			t.Errorf("container %s still exists %v after Run returned: %q", name, wait, out)
		}
	}
}

func TestIntegrationTimeoutKillsContainer(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	start := time.Now()
	res := mustRun(t, rt, ctx, Spec{
		Image:   testImage,
		Cmd:     []string{"sleep", "60"},
		Profile: Profile{Timeout: 3 * time.Second},
	})
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("Run returned after %v, want under 15s", elapsed)
	}
	if !res.TimedOut || res.ExitCode != -1 {
		t.Errorf("TimedOut = %v, ExitCode = %d; want true, -1", res.TimedOut, res.ExitCode)
	}
	assertContainerGone(t, ctx, rt, res)
}

func TestIntegrationTimeoutDuringStartupLeavesNoContainer(t *testing.T) {
	// The timeout fires while the engine is still creating the container. Killing the CLI at
	// that moment would leave a created, never removed container behind.
	rt, ctx := integrationRuntime(t)
	res := mustRun(t, rt, ctx, Spec{
		Image:   testImage,
		Cmd:     []string{"sleep", "60"},
		Profile: Profile{Timeout: 50 * time.Millisecond},
	})
	if !res.TimedOut || res.ExitCode != -1 {
		t.Errorf("TimedOut = %v, ExitCode = %d; want true, -1", res.TimedOut, res.ExitCode)
	}
	assertContainerGone(t, ctx, rt, res)
}

func TestIntegrationRootFilesystemIsReadOnly(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	res := mustRun(t, rt, ctx, Spec{Image: testImage, Cmd: []string{"touch", "/etc/x"}})
	if res.ExitCode == 0 {
		t.Error("touch /etc/x succeeded; the root filesystem is writable")
	}
}

func TestIntegrationNonZeroExitIsResult(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	res, err := rt.Run(ctx, Spec{Image: testImage, Cmd: []string{"sh", "-c", "echo out; echo err >&2; exit 7"}})
	if err != nil {
		t.Fatalf("exit 7 must be a Result, not an error: %v", err)
	}
	if res.ExitCode != 7 || res.Stdout != "out\n" || res.Stderr != "err\n" || res.TimedOut {
		t.Errorf("got exit %d, stdout %q, stderr %q, timed out %v", res.ExitCode, res.Stdout, res.Stderr, res.TimedOut)
	}
}

func TestIntegrationSourceDirWithSpace(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	src := filepath.Join(t.TempDir(), "dir with space")
	writeSource(t, src)
	res := mustRun(t, rt, ctx, Spec{Image: testImage, Cmd: []string{"cat", "a.txt", "sub/b.txt"}, SourceDir: src})
	if res.ExitCode != 0 || res.Stdout != "alpha\nbeta\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestIntegrationHostileCmdIsNotInterpreted(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	hostile := "; echo injected > /work/pwned #"
	res := mustRun(t, rt, ctx, Spec{Image: testImage, Cmd: []string{"sh", "-c", `printf '%s\n' "$1"; ls /work`, "sh", hostile}})
	if res.ExitCode != 0 || res.Stdout != hostile+"\n" {
		t.Errorf("exit %d, stdout %q, stderr %q; the argument must arrive verbatim and create nothing", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestIntegrationMissingSubdirIsAnError(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	_, err := rt.Run(ctx, Spec{Image: testImage, Cmd: []string{"true"}, Subdir: "nope"})
	if err == nil || !strings.Contains(err.Error(), "subdirectory") {
		t.Errorf("a missing Subdir must be reported as a setup error, got %v", err)
	}
}

func TestIntegrationMissingImageIsAnError(t *testing.T) {
	rt, ctx := integrationRuntime(t)
	// Container startup dominates these tests; run them side by side.
	t.Parallel()
	const missing = "spackle-test/no-such-image:0"
	_, err := rt.Run(ctx, Spec{Image: missing, Cmd: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "pull "+missing) {
		t.Errorf("a missing image must be an error naming the pull command, got %v", err)
	}
}
