package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	outputCap     = 1 << 20
	truncatedNote = "\n[spackle: output truncated at 1 MiB]"

	probeTimeout = 15 * time.Second
	// reapTimeout bounds how long Run waits, after a timeout or cancel, for the CLI to exit
	// once its container has been killed. After that the CLI itself is killed.
	reapTimeout = 10 * time.Second
	// reapCallTimeout bounds each single kill, remove or inspect call during cleanup.
	reapCallTimeout = 5 * time.Second
	// waitDelay bounds how long a management command waits for output pipes once killed.
	waitDelay = 5 * time.Second
)

// cliRuntime drives one container CLI (docker or podman) with argument vectors.
type cliRuntime struct {
	name string // "docker" or "podman"
	cli  string // path of the executable
}

// newCLIRuntime builds a runtime around an explicit CLI path. Detect uses it after probing;
// tests use it to point at a fake CLI.
func newCLIRuntime(name, cli string) *cliRuntime {
	return &cliRuntime{name: name, cli: cli}
}

// Detect finds a working runtime. preferred is "auto", "docker", "podman" or "none".
// It returns ErrNoRuntime (wrapped with a what/why/what-to-do message) when preferred is "none",
// when no CLI is on PATH, or when the CLI is present but the engine does not answer
// (`<cli> version --format {{.Server.Version}}` with a 15s timeout).
func Detect(ctx context.Context, preferred string) (Runtime, error) {
	var names []string
	switch preferred {
	case "auto":
		names = []string{"docker", "podman"}
	case "docker", "podman":
		names = []string{preferred}
	case "none":
		return nil, fmt.Errorf("%w: the sandbox runtime is set to \"none\", so proofs and fix verification are not run. Set [sandbox] runtime to auto, docker or podman to enable them", ErrNoRuntime)
	default:
		return nil, fmt.Errorf("sandbox: runtime %q is not one of auto, docker, podman, none. Fix the [sandbox] runtime setting", preferred)
	}
	var reasons []string
	for _, name := range names {
		cli, err := exec.LookPath(name)
		if err != nil {
			reasons = append(reasons, name+" is not on PATH")
			continue
		}
		if err := probe(ctx, name, cli); err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		return newCLIRuntime(name, cli), nil
	}
	return nil, fmt.Errorf("%w: %s, so proofs and fix verification are not run. Install Docker or Podman, or start the engine, and run again", ErrNoRuntime, strings.Join(reasons, "; "))
}

// probe checks that the engine behind the CLI answers, not just that the CLI is installed.
func probe(ctx context.Context, name, cli string) error {
	out, err := runCLI(ctx, probeTimeout, cli, "version", "--format", "{{.Server.Version}}")
	if err == nil && strings.TrimSpace(out) != "" {
		return nil
	}
	if name == "podman" {
		// A local (daemonless) podman has no server section, so the version template fails
		// even though the engine works. `info` exercises the engine in both modes.
		if out, infoErr := runCLI(ctx, probeTimeout, cli, "info", "--format", "{{.Host.Os}}"); infoErr == nil && strings.TrimSpace(out) != "" {
			return nil
		}
	}
	if err == nil {
		err = errors.New("it reported no server version")
	}
	return fmt.Errorf("%s is installed but its engine did not answer (%w)", name, err)
}

// runCLI runs a short management command and returns its stdout. On failure the error carries
// the tail of stderr, which is where the engine says what is wrong.
func runCLI(ctx context.Context, timeout time.Duration, cli string, args ...string) (string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var stdout, stderr capWriter
	stdout.limit, stderr.limit = outputCap, outputCap
	cmd := exec.CommandContext(ctx, cli, args...) //nolint:gosec // G204: cli is the docker or podman path from LookPath and args are fixed management verbs, never a shell
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = waitDelay
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return stdout.String(), fmt.Errorf("no answer in time: %w", ctx.Err())
		}
		if msg := tail(stderr.String()); msg != "" {
			return stdout.String(), fmt.Errorf("%w: %s", err, msg)
		}
		return stdout.String(), err
	}
	return stdout.String(), nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	const keep = 600
	if len(s) > keep {
		s = "..." + s[len(s)-keep:]
	}
	return s
}

func (r *cliRuntime) Name() string { return r.name }

// ImagePresent reports whether the image is already in the local store. It never pulls.
func (r *cliRuntime) ImagePresent(ctx context.Context, image string) bool {
	if validateImage(image) != nil {
		return false
	}
	_, err := runCLI(ctx, probeTimeout, r.cli, "image", "inspect", "--format", "{{.Id}}", image)
	return err == nil
}

// Pull downloads the image. It is bounded only by ctx because image size varies widely.
func (r *cliRuntime) Pull(ctx context.Context, image string) error {
	if err := validateImage(image); err != nil {
		return err
	}
	if _, err := runCLI(ctx, 0, r.cli, "pull", image); err != nil {
		return fmt.Errorf("sandbox: %s could not pull image %q: %w. Check the image name and network access, or load the image by hand", r.name, image, err)
	}
	return nil
}

// Run executes the spec in a fresh container and removes the container afterwards.
// A non-zero exit of the contained program is a Result, not an error. An error means the
// program did not run to an outcome: bad spec, engine failure, missing image, failed setup
// or a cancelled context.
func (r *cliRuntime) Run(ctx context.Context, spec Spec) (Result, error) {
	v, err := validateSpec(spec)
	if err != nil {
		return Result{}, err
	}
	name, err := containerName()
	if err != nil {
		return Result{}, err
	}

	stageDir := ""
	if len(spec.Files) > 0 {
		tmp, err := os.MkdirTemp("", "spackle-stage-")
		if err != nil {
			return Result{}, fmt.Errorf("sandbox: cannot create a staging directory for the run files: %w. Check that the temp directory is writable", err)
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		// The mount is a child of the private 0700 temp directory: other host users cannot
		// reach it, while inside the container only the child (0755) is visible, so the
		// unprivileged container user can read it.
		stageDir = filepath.Join(tmp, "in")
		if err := writeStage(stageDir, spec.Files); err != nil {
			return Result{}, err
		}
	}
	args, err := BuildArgs(spec, stageDir, name)
	if err != nil {
		return Result{}, err
	}

	// Checked up front so a missing image is reported as such instead of the engine starting
	// an implicit pull that eats the run timeout.
	if !r.ImagePresent(ctx, spec.Image) {
		if ctx.Err() != nil {
			return Result{}, fmt.Errorf("sandbox: run cancelled before the container started: %w", ctx.Err())
		}
		return Result{}, fmt.Errorf("sandbox: image %q is not available to %s (not pulled yet, or the engine stopped answering), so nothing was run. Pull it with `%s pull %s` and run again", spec.Image, r.name, r.name, spec.Image)
	}

	res := Result{
		Isolation: r.name + ", " + v.profile.Summary(),
		Argv:      append([]string{r.cli}, args...),
	}
	runCtx, cancel := context.WithTimeout(ctx, v.profile.Timeout)
	defer cancel()
	stdout := &capWriter{limit: outputCap}
	stderr := &capWriter{limit: outputCap}
	cmd := exec.CommandContext(runCtx, r.cli, args...) //nolint:gosec // G204: cli is the docker or podman path; args come from BuildArgs, which validates every caller field and never builds shell text
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// On timeout or cancel the CLI is deliberately not killed at once. Killing it does not
	// stop the container, and it does not stop a create request that is still in flight: the
	// engine would finish creating a container nobody removes. Instead reap kills the
	// container by name and the CLI exits on its own, which proves nothing is in flight.
	// WaitDelay is the backstop: exec kills the CLI that long after the context is done.
	cmd.Cancel = func() error { return nil }
	cmd.WaitDelay = reapTimeout
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("sandbox: could not start %s: %w. Check that %s is installed and runnable", r.cli, err, r.name)
	}
	done := make(chan struct{})
	go func() {
		// The error is not needed: the exit code is read from ProcessState.
		_ = cmd.Wait()
		close(done)
	}()
	interrupted := false
	select {
	case <-done:
	case <-runCtx.Done():
		interrupted = true
		r.reap(ctx, name, done)
	}
	res.Duration = time.Since(start)
	res.Stdout, res.Stderr = stdout.String(), stderr.String()
	// The bootstrap says when the work directory is ready. Take that line out of the
	// output: it is not something the program wrote.
	ready := false
	if before, after, ok := strings.Cut(res.Stderr, bootstrapReady+"\n"); ok {
		ready, res.Stderr = true, before+after
	}
	if interrupted {
		res.ExitCode = -1
		if ctx.Err() != nil {
			return res, fmt.Errorf("sandbox: run cancelled by the caller; container %s was killed: %w", name, ctx.Err())
		}
		if !ready {
			return res, fmt.Errorf("sandbox: preparing the work directory took longer than the %s timeout, so the command never started. Copying the source into the container is part of the run: exclude large directories that the code does not need, or raise the [sandbox] timeout", v.profile.Timeout)
		}
		res.TimedOut = true
		return res, nil
	}
	res.ExitCode = cmd.ProcessState.ExitCode()

	switch {
	case res.ExitCode == bootstrapFailExit && strings.Contains(res.Stderr, bootstrapMarker):
		return res, fmt.Errorf("sandbox: the work directory could not be prepared inside the container, so the command did not run: %s. Check that the source files are readable by other users and fit in the 1 GiB work directory", tail(res.Stderr))
	case isEngineExit(res.ExitCode) && hasEngineMessage(r.name, res.Stderr):
		return res, fmt.Errorf("sandbox: %s could not run the container (exit %d): %s. Check that the engine is running with `%s info`, that image %q has a POSIX `sh`, and that it is present (`%s pull %s`)", r.name, res.ExitCode, tail(res.Stderr), r.name, spec.Image, r.name, spec.Image)
	}
	return res, nil
}

// isEngineExit reports the exit codes docker and podman reserve for their own failures.
func isEngineExit(code int) bool {
	return code == 125 || code == 126 || code == 127
}

// hasEngineMessage tells an engine failure from a contained program that happened to exit
// with 125 to 127 (a shell exits 127 for "command not found", which is a real result).
func hasEngineMessage(name, stderr string) bool {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, name+": ") ||
			strings.HasPrefix(line, "docker: ") ||
			strings.HasPrefix(line, "Error: ") ||
			strings.Contains(line, "Error response from daemon") ||
			strings.Contains(line, "OCI runtime") {
			return true
		}
	}
	return false
}

// reap makes sure neither the container nor the CLI outlives the call. done is closed when
// the CLI has exited. It is best effort: every command may fail because the container is
// already gone or was never created.
func (r *cliRuntime) reap(ctx context.Context, name string, done <-chan struct{}) {
	// The caller's context is already done here, so detach from its cancellation.
	bg := context.WithoutCancel(ctx)
	exited := false
	for !exited {
		// kill ends a running container; rm also covers one that was created but not started,
		// which --rm never removes.
		_, _ = runCLI(bg, reapCallTimeout, r.cli, "kill", name)
		_, _ = runCLI(bg, reapCallTimeout, r.cli, "rm", "-f", name)
		select {
		case <-done:
			exited = true
		case <-time.After(250 * time.Millisecond):
		}
	}
	// The engine removes asynchronously and `rm` returns early when a removal is already in
	// progress, so confirm the container is gone before reporting back.
	deadline := time.Now().Add(reapTimeout)
	for {
		_, _ = runCLI(bg, reapCallTimeout, r.cli, "rm", "-f", name)
		if _, err := runCLI(bg, reapCallTimeout, r.cli, "container", "inspect", "--format", "{{.Id}}", name); err != nil {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func containerName() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sandbox: cannot generate a container name: %w. Check the system random source", err)
	}
	return "spackle-" + hex.EncodeToString(b), nil
}

// writeStage writes files under root, which must not exist yet.
func writeStage(root string, files map[string]string) error {
	fail := func(what string, err error) error {
		return fmt.Errorf("sandbox: cannot stage %s for the run: %w. Check the file paths and that the temp directory is writable", what, err)
	}
	if err := os.Mkdir(root, 0o755); err != nil { //nolint:gosec // G301: the container user (65534) must be able to traverse it; the parent is 0700
		return fail("the files", err)
	}
	for key, content := range files {
		local := filepath.FromSlash(key)
		// Defense in depth behind validateRelPath; IsLocal also knows the reserved device
		// names of a Windows host.
		if !filepath.IsLocal(local) {
			return fmt.Errorf("sandbox: file path %q does not stay inside the work directory on this host. Use a plain relative path", key)
		}
		dest := filepath.Join(root, local)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil { //nolint:gosec // G301: readable by the unprivileged container user by design
			return fail(key, err)
		}
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil { //nolint:gosec // G306: readable by the unprivileged container user by design
			return fail(key, err)
		}
	}
	// The modes above are subject to the umask; set them explicitly so a strict umask on the
	// host cannot make the files unreadable in the container.
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fail(path, err)
		}
		mode := fs.FileMode(0o644)
		if d.IsDir() {
			mode = 0o755
		}
		if err := os.Chmod(path, mode); err != nil { //nolint:gosec // G302: readable by the unprivileged container user by design
			return fail(path, err)
		}
		return nil
	})
}

// capWriter keeps the first limit bytes and discards the rest. It never reports a short
// write, so a noisy program cannot block or kill the CLI by filling a pipe.
type capWriter struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.limit - w.buf.Len(); len(p) > room {
		w.truncated = true
		w.buf.Write(p[:max(room, 0)])
	} else {
		w.buf.Write(p)
	}
	return len(p), nil
}

func (w *capWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.truncated {
		return w.buf.String() + truncatedNote
	}
	return w.buf.String()
}
