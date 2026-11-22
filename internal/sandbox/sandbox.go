// Package sandbox runs untrusted code (model-written proofs of concept and candidate fixes)
// inside a locked-down container by driving the docker or podman CLI.
//
// Nothing in this package executes target or model-written code on the host. When no container
// runtime is available Detect returns ErrNoRuntime and the caller marks proofs as not run.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrNoRuntime reports that no usable container runtime was found, so nothing was executed.
var ErrNoRuntime = errors.New("no container runtime")

const (
	networkNone  = "none"
	networkScope = "scope"

	defaultMemoryMB = 1024
	defaultCPUs     = 2
	defaultPIDs     = 256
	defaultTimeout  = 2 * time.Minute
	// maxTimeout bounds how long one untrusted run can hold a container, whatever config says.
	maxTimeout = 15 * time.Minute

	subdirEnv = "SPACKLE_SUBDIR"

	// bootstrapFailExit and bootstrapMarker let Run tell "the work directory could not be
	// prepared" apart from "the program ran and failed". Without that, a failed source copy
	// would look like a proof that no longer reproduces, which could wrongly pass a fix.
	bootstrapFailExit = 122
	bootstrapMarker   = "spackle-bootstrap: "

	// bootstrap is the only shell text this package ever runs. It is a constant on purpose:
	// Cmd arrives as positional parameters and the subdirectory as an environment variable,
	// so no caller-supplied or model-supplied text is ever parsed as shell.
	bootstrap = `fail() { echo "spackle-bootstrap: $1" >&2; exit 122; }; ` +
		`if [ -d /src ]; then cp -R /src/. /work/ || fail "could not copy the source into /work"; fi; ` +
		`if [ -d /spackle-in ]; then cp -R /spackle-in/. /work/ || fail "could not copy the staged files into /work"; fi; ` +
		`if [ -n "${SPACKLE_SUBDIR:-}" ]; then cd "/work/${SPACKLE_SUBDIR}" || fail "the work subdirectory does not exist"; fi; ` +
		`exec "$@"`
)

var (
	envNameRe       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	containerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

// fixedEnv is applied to every run, in this order. GOPROXY=off is added separately because it
// only makes sense when the container has no network.
var fixedEnv = [][2]string{
	{"HOME", "/tmp/home"},
	{"GOCACHE", "/tmp/gocache"},
	{"GOPATH", "/tmp/gopath"},
	{"GOFLAGS", "-mod=mod"},
	{"GOTOOLCHAIN", "local"},
}

var fixedEnvTail = [][2]string{
	{"PYTHONDONTWRITEBYTECODE", "1"},
	{"PIP_DISABLE_PIP_VERSION_CHECK", "1"},
	{"npm_config_update_notifier", "false"},
}

// Profile is the isolation applied to one run.
type Profile struct {
	// Network is "none" (default) or "scope". "scope" attaches the default bridge network so a
	// proof can reach an authorized running target; it is never chosen by this package.
	Network  string
	MemoryMB int           // default 1024
	CPUs     float64       // default 2
	PIDs     int           // default 256
	Timeout  time.Duration // default 2m; hard cap 15m
}

// Spec is one execution.
type Spec struct {
	Image string
	// Cmd is the program and arguments run inside the container, in the work directory.
	Cmd []string
	// SourceDir is a host directory mounted read-only and copied into the writable work
	// directory before Cmd runs. Empty means start with an empty work directory.
	SourceDir string
	// Files are extra files written into the work directory after the source copy (the PoC or
	// a patched file). Keys are forward-slash relative paths; they are validated.
	Files map[string]string
	// Subdir is a relative directory inside the work directory to run Cmd in.
	Subdir  string
	Env     map[string]string
	Profile Profile
}

// Result is the outcome of one execution.
type Result struct {
	ExitCode  int
	Stdout    string // capped at 1 MiB, with a truncation note
	Stderr    string // capped at 1 MiB
	TimedOut  bool
	Duration  time.Duration
	Isolation string   // human-readable summary of what was enforced, for the report
	Argv      []string // the runtime command line that was executed
}

// Runtime is a container engine that can run a Spec.
type Runtime interface {
	Name() string // "docker" or "podman"
	Run(ctx context.Context, spec Spec) (Result, error)
	ImagePresent(ctx context.Context, image string) bool
	Pull(ctx context.Context, image string) error
}

// WithDefaults returns the profile with every zero field replaced by its default.
func (p Profile) WithDefaults() Profile {
	if p.Network == "" {
		p.Network = networkNone
	}
	if p.MemoryMB == 0 {
		p.MemoryMB = defaultMemoryMB
	}
	if p.CPUs == 0 {
		p.CPUs = defaultCPUs
	}
	if p.PIDs == 0 {
		p.PIDs = defaultPIDs
	}
	if p.Timeout == 0 {
		p.Timeout = defaultTimeout
	}
	return p
}

// Summary describes the isolation this profile enforces, for the report. Run prefixes it with
// the runtime name to form Result.Isolation.
func (p Profile) Summary() string {
	p = p.WithDefaults()
	network := p.Network
	if network == networkScope {
		network = "bridge (scope)"
	}
	cpus := formatCPUs(p.CPUs) + " CPUs"
	if p.CPUs == 1 {
		cpus = "1 CPU"
	}
	return fmt.Sprintf("network %s, capabilities dropped, read-only root, non-root user, %d MB memory, %s, %d processes, %s timeout",
		network, p.MemoryMB, cpus, p.PIDs, p.Timeout)
}

func formatCPUs(c float64) string {
	return strconv.FormatFloat(c, 'f', -1, 64)
}

func (p Profile) validate() error {
	if p.Network != networkNone && p.Network != networkScope {
		return fmt.Errorf("sandbox: network %q is not allowed: only \"none\" and \"scope\" exist so a run can never join the host network. Set the profile network to \"none\" or \"scope\"", p.Network)
	}
	if p.MemoryMB < 0 || p.PIDs < 0 || p.CPUs < 0 || math.IsNaN(p.CPUs) || math.IsInf(p.CPUs, 0) {
		return fmt.Errorf("sandbox: memory (%d MB), CPUs (%v) and process limit (%d) must be positive numbers so the limits are real. Fix the [sandbox] values or leave them unset for the defaults", p.MemoryMB, p.CPUs, p.PIDs)
	}
	if p.Timeout < 0 {
		return fmt.Errorf("sandbox: timeout %s is negative. Use a positive duration or leave it unset for the %s default", p.Timeout, defaultTimeout)
	}
	if p.Timeout > maxTimeout {
		return fmt.Errorf("sandbox: timeout %s is above the hard cap of %s for one untrusted run. Lower the [sandbox] timeout", p.Timeout, maxTimeout)
	}
	return nil
}

// validateRelPath rejects anything that is not a plain forward-slash relative path. The same
// path is used on the host (stage directory, possibly Windows) and in the container, so it
// has to be unambiguous on both.
func validateRelPath(kind, p string) error {
	bad := func(why string) error {
		return fmt.Errorf("sandbox: %s %q %s. Use a forward-slash path relative to the work directory, for example \"poc/main.go\"", kind, p, why)
	}
	switch {
	case p == "":
		return bad("is empty")
	case strings.HasPrefix(p, "/"):
		return bad("is absolute")
	case strings.HasPrefix(p, "-"):
		return bad("starts with a dash and could be read as an option")
	case strings.Contains(p, ".."):
		return bad("contains \"..\" and could leave the work directory")
	case strings.Contains(p, `\`):
		return bad("contains a backslash")
	case strings.Contains(p, ":"):
		// Covers drive letters and NTFS alternate data streams, which would silently drop
		// the content on a Windows host.
		return bad("contains a colon (drive letter or stream name)")
	case strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return bad("contains a control character")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			return bad("has an empty path element")
		}
	}
	return nil
}

func validateImage(image string) error {
	switch {
	case image == "":
		return errors.New("sandbox: the image is empty, so there is nothing to run in. Set an image for this language under [sandbox.images]")
	case strings.HasPrefix(image, "-"):
		return fmt.Errorf("sandbox: image %q starts with a dash and would be read as a runtime option. Use an image reference such as \"golang:1.27\"", image)
	case strings.ContainsFunc(image, func(r rune) bool { return r <= 0x20 || r == 0x7f }):
		return fmt.Errorf("sandbox: image %q contains whitespace or a control character. Use an image reference such as \"golang:1.27\"", image)
	}
	return nil
}

// mountSource returns the absolute form of a host directory for a --mount flag. --mount takes
// comma-separated fields, so a comma or quote in the path would be parsed as extra mount
// options; that is refused rather than escaped.
func mountSource(kind, dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("sandbox: cannot resolve %s %q to an absolute path: %w. Pass an existing directory", kind, dir, err)
	}
	if strings.ContainsAny(abs, ",\"\r\n\x00") {
		return "", fmt.Errorf("sandbox: %s %q contains a comma, quote or line break, which the runtime would read as extra mount options. Move or rename the directory", kind, abs)
	}
	return abs, nil
}

// validated is a Spec after every check passed.
type validated struct {
	profile Profile
	source  string   // absolute SourceDir, or empty
	env     []string // caller NAME=value pairs, sorted by name
}

func validateSpec(spec Spec) (validated, error) {
	var v validated
	if err := validateImage(spec.Image); err != nil {
		return v, err
	}
	if len(spec.Cmd) == 0 {
		return v, errors.New("sandbox: the command is empty, so there is nothing to run. Set Cmd to the program and its arguments")
	}
	for _, c := range spec.Cmd {
		if strings.ContainsRune(c, 0) {
			return v, errors.New("sandbox: a command argument contains a NUL byte, which cannot be passed to a process. Remove it")
		}
	}
	v.profile = spec.Profile.WithDefaults()
	if err := v.profile.validate(); err != nil {
		return v, err
	}
	for key := range spec.Files {
		if err := validateRelPath("file path", key); err != nil {
			return v, err
		}
	}
	if spec.Subdir != "" {
		if err := validateRelPath("subdirectory", spec.Subdir); err != nil {
			return v, err
		}
	}
	if spec.SourceDir != "" {
		info, err := os.Stat(spec.SourceDir)
		if err != nil {
			return v, fmt.Errorf("sandbox: source directory %q cannot be read: %w. Pass an existing directory", spec.SourceDir, err)
		}
		if !info.IsDir() {
			return v, fmt.Errorf("sandbox: source %q is a file, and only a directory can be mounted. Pass the directory that holds it", spec.SourceDir)
		}
		if v.source, err = mountSource("source directory", spec.SourceDir); err != nil {
			return v, err
		}
	}

	reserved := map[string]bool{subdirEnv: true}
	for _, kv := range fixedEnv {
		reserved[kv[0]] = true
	}
	for _, kv := range fixedEnvTail {
		reserved[kv[0]] = true
	}
	if v.profile.Network == networkNone {
		reserved["GOPROXY"] = true
	}
	names := make([]string, 0, len(spec.Env))
	for name, value := range spec.Env {
		if !envNameRe.MatchString(name) {
			return v, fmt.Errorf("sandbox: environment variable name %q is not valid. Use letters, digits and underscores, not starting with a digit", name)
		}
		if reserved[name] {
			return v, fmt.Errorf("sandbox: environment variable %s is fixed by the sandbox and cannot be overridden. Remove it from Env", name)
		}
		if strings.ContainsAny(value, "\x00\n\r") {
			return v, fmt.Errorf("sandbox: the value of environment variable %s contains a NUL or a line break. Remove it or encode the value", name)
		}
		names = append(names, name)
	}
	// Sorted so the same spec always yields the same command line in the ledger.
	sort.Strings(names)
	for _, name := range names {
		v.env = append(v.env, name+"="+spec.Env[name])
	}
	return v, nil
}

// BuildArgs returns the full runtime argument vector for a spec, without executing anything.
// stageDir is the host directory holding Files (mounted read-only at /spackle-in);
// name is the container name. It is exported so the isolation defaults are unit-testable
// without a runtime.
func BuildArgs(spec Spec, stageDir, name string) ([]string, error) {
	v, err := validateSpec(spec)
	if err != nil {
		return nil, err
	}
	if !containerNameRe.MatchString(name) {
		return nil, fmt.Errorf("sandbox: container name %q is not valid. Use letters, digits, dot, dash and underscore, starting with a letter or digit", name)
	}
	stage := ""
	if len(spec.Files) > 0 {
		if stageDir == "" {
			return nil, errors.New("sandbox: the spec has Files but no stage directory was given to hold them. Pass the directory the files were written to")
		}
		if stage, err = mountSource("stage directory", stageDir); err != nil {
			return nil, err
		}
	}

	p := v.profile
	network := networkNone
	if p.Network == networkScope {
		network = "bridge"
	}
	memory := strconv.Itoa(p.MemoryMB) + "m"
	args := []string{
		"run", "--rm", "--name", name, "--network", network,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--pids-limit", strconv.Itoa(p.PIDs),
		"--memory", memory,
		// Same value as --memory: the container gets no swap to hide in.
		"--memory-swap", memory,
		"--cpus", formatCPUs(p.CPUs),
		"--user", "65534:65534",
		"--tmpfs", "/work:rw,exec,nosuid,size=1g,mode=1777",
		"--tmpfs", "/tmp:rw,exec,nosuid,size=512m,mode=1777",
		"--workdir", "/work",
	}
	for _, kv := range fixedEnv {
		args = append(args, "-e", kv[0]+"="+kv[1])
	}
	if p.Network == networkNone {
		// With no network a module download can only hang until the timeout; fail fast instead.
		args = append(args, "-e", "GOPROXY=off")
	}
	for _, kv := range fixedEnvTail {
		args = append(args, "-e", kv[0]+"="+kv[1])
	}
	if spec.Subdir != "" {
		args = append(args, "-e", subdirEnv+"="+spec.Subdir)
	}
	for _, kv := range v.env {
		args = append(args, "-e", kv)
	}
	// --mount rather than -v: a Windows path with a drive letter or a space is unambiguous.
	if v.source != "" {
		args = append(args, "--mount", "type=bind,source="+v.source+",target=/src,readonly")
	}
	if stage != "" {
		args = append(args, "--mount", "type=bind,source="+stage+",target=/spackle-in,readonly")
	}
	args = append(args, "--stop-timeout", "2", spec.Image, "sh", "-c", bootstrap, "sh")
	return append(args, spec.Cmd...), nil
}
