package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testImage = "alpine:3.20"

func baseSpec() Spec {
	return Spec{Image: testImage, Cmd: []string{"true"}}
}

// hasSeq reports whether seq appears as a contiguous run inside args.
func hasSeq(args []string, seq ...string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		if slices.Equal(args[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}

func mustBuild(t *testing.T, spec Spec, stageDir string) []string {
	t.Helper()
	args, err := BuildArgs(spec, stageDir, "spackle-0123456789ab")
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	return args
}

func TestBuildArgsRequiredArguments(t *testing.T) {
	src := t.TempDir()
	stage := t.TempDir()
	spec := Spec{
		Image:     testImage,
		Cmd:       []string{"go", "test", "./..."},
		SourceDir: src,
		Files:     map[string]string{"poc/poc_test.go": "package poc"},
		Subdir:    "poc",
		Env:       map[string]string{"ZED": "1", "ALPHA": "a b"},
	}
	args := mustBuild(t, spec, stage)

	prefix := []string{"run", "--rm", "--name", "spackle-0123456789ab", "--network", "none"}
	if !slices.Equal(args[:len(prefix)], prefix) {
		t.Fatalf("args start with %q, want %q", args[:len(prefix)], prefix)
	}
	absSrc, err := filepath.Abs(src)
	if err != nil {
		t.Fatal(err)
	}
	absStage, err := filepath.Abs(stage)
	if err != nil {
		t.Fatal(err)
	}
	required := [][]string{
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"},
		{"--read-only"},
		{"--pids-limit", "256"},
		{"--memory", "1024m"},
		{"--memory-swap", "1024m"},
		{"--cpus", "2"},
		{"--user", "65534:65534"},
		{"--tmpfs", "/work:rw,exec,nosuid,size=1g,mode=1777"},
		{"--tmpfs", "/tmp:rw,exec,nosuid,size=512m,mode=1777"},
		{"--workdir", "/work"},
		{"-e", "HOME=/tmp/home"},
		{"-e", "GOCACHE=/tmp/gocache"},
		{"-e", "GOPATH=/tmp/gopath"},
		{"-e", "GOFLAGS=-mod=mod"},
		{"-e", "GOTOOLCHAIN=local"},
		{"-e", "GOPROXY=off"},
		{"-e", "PYTHONDONTWRITEBYTECODE=1"},
		{"-e", "PIP_DISABLE_PIP_VERSION_CHECK=1"},
		{"-e", "npm_config_update_notifier=false"},
		{"-e", "SPACKLE_SUBDIR=poc"},
		{"-e", "ALPHA=a b", "-e", "ZED=1"},
		{"--mount", "type=bind,source=" + absSrc + ",target=/src,readonly"},
		{"--mount", "type=bind,source=" + absStage + ",target=/spackle-in,readonly"},
		{"--stop-timeout", "2", testImage, "sh", "-c", bootstrap, "sh", "go", "test", "./..."},
	}
	for _, seq := range required {
		if !hasSeq(args, seq...) {
			t.Errorf("missing argument sequence %q in %q", seq, args)
		}
	}
	tail := []string{testImage, "sh", "-c", bootstrap, "sh", "go", "test", "./..."}
	if !slices.Equal(args[len(args)-len(tail):], tail) {
		t.Errorf("args end with %q, want %q", args[len(args)-len(tail):], tail)
	}
	// Caller variables must come after the fixed ones so the ordering matches the brief and a
	// reader of the report sees the enforced defaults first.
	if slices.Index(args, "ALPHA=a b") < slices.Index(args, "npm_config_update_notifier=false") {
		t.Error("caller env appears before the fixed env")
	}
}

func TestBuildArgsCustomLimits(t *testing.T) {
	spec := baseSpec()
	spec.Profile = Profile{MemoryMB: 512, CPUs: 0.5, PIDs: 64}
	args := mustBuild(t, spec, "")
	for _, seq := range [][]string{
		{"--memory", "512m"}, {"--memory-swap", "512m"}, {"--cpus", "0.5"}, {"--pids-limit", "64"},
	} {
		if !hasSeq(args, seq...) {
			t.Errorf("missing %q in %q", seq, args)
		}
	}
}

func TestBuildArgsScopeNetwork(t *testing.T) {
	spec := baseSpec()
	spec.Profile.Network = "scope"
	spec.Env = map[string]string{"GOPROXY": "https://proxy.example"}
	args := mustBuild(t, spec, "")
	if !hasSeq(args, "--network", "bridge") {
		t.Errorf("scope network must map to the bridge network: %q", args)
	}
	if slices.Contains(args, "GOPROXY=off") {
		t.Errorf("GOPROXY=off must only be set when the network is none: %q", args)
	}
	if !hasSeq(args, "-e", "GOPROXY=https://proxy.example") {
		t.Errorf("caller GOPROXY should be allowed with the scope network: %q", args)
	}
}

func TestBuildArgsNoMountsWithoutSourceOrFiles(t *testing.T) {
	args := mustBuild(t, baseSpec(), "")
	if slices.Contains(args, "--mount") {
		t.Errorf("no mount expected without SourceDir and Files: %q", args)
	}
	for _, a := range args {
		if strings.HasPrefix(a, "SPACKLE_SUBDIR=") {
			t.Errorf("SPACKLE_SUBDIR must not be set without a Subdir: %q", args)
		}
	}
}

func TestBuildArgsFilesNeedStageDir(t *testing.T) {
	spec := baseSpec()
	spec.Files = map[string]string{"a.txt": "a"}
	if _, err := BuildArgs(spec, "", "spackle-0123456789ab"); err == nil {
		t.Fatal("expected an error when Files are set and stageDir is empty")
	}
}

func TestBuildArgsForbiddenArguments(t *testing.T) {
	src := t.TempDir()
	stage := t.TempDir()
	specs := []Spec{
		baseSpec(),
		{Image: testImage, Cmd: []string{"id"}, SourceDir: src, Files: map[string]string{"a": "b"}, Subdir: "x", Env: map[string]string{"A": "b"}},
		{Image: testImage, Cmd: []string{"id"}, Profile: Profile{Network: "scope"}},
	}
	forbiddenExact := []string{"-v", "--volume", "--privileged", "--pid", "--cap-add", "--device", "--ipc", "--userns", "--volumes-from"}
	forbiddenSub := []string{"docker.sock", "podman.sock", "--privileged", "--cap-add", "--pid=", "--network=host", "--net=host", "seccomp=unconfined", "apparmor=unconfined"}
	for _, spec := range specs {
		args := mustBuild(t, spec, stage)
		for i, a := range args {
			if slices.Contains(forbiddenExact, a) {
				t.Errorf("forbidden argument %q in %q", a, args)
			}
			for _, sub := range forbiddenSub {
				if strings.Contains(a, sub) {
					t.Errorf("forbidden text %q in argument %q", sub, a)
				}
			}
			if (a == "--network" || a == "--net" || a == "--pid") && i+1 < len(args) && args[i+1] == "host" {
				t.Errorf("host namespace requested: %q", args)
			}
			if a == "--mount" && !strings.HasSuffix(args[i+1], ",readonly") {
				t.Errorf("mount is not read-only: %q", args[i+1])
			}
		}
	}
}

func TestBuildArgsValidation(t *testing.T) {
	src := t.TempDir()
	notDir := filepath.Join(src, "file.txt")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Spec){
		"empty image":           func(s *Spec) { s.Image = "" },
		"image dash":            func(s *Spec) { s.Image = "--privileged" },
		"image space":           func(s *Spec) { s.Image = "alpine 3.20" },
		"image tab":             func(s *Spec) { s.Image = "alpine\t3.20" },
		"image newline":         func(s *Spec) { s.Image = "alpine\n" },
		"empty cmd":             func(s *Spec) { s.Cmd = nil },
		"cmd nul":               func(s *Spec) { s.Cmd = []string{"a\x00b"} },
		"file absolute":         func(s *Spec) { s.Files = map[string]string{"/etc/passwd": "x"} },
		"file dotdot":           func(s *Spec) { s.Files = map[string]string{"a/../../b": "x"} },
		"file backslash":        func(s *Spec) { s.Files = map[string]string{`a\b`: "x"} },
		"file drive":            func(s *Spec) { s.Files = map[string]string{"C:/x": "x"} },
		"file drive relative":   func(s *Spec) { s.Files = map[string]string{"c:x": "x"} },
		"file dash":             func(s *Spec) { s.Files = map[string]string{"-rf": "x"} },
		"file empty":            func(s *Spec) { s.Files = map[string]string{"": "x"} },
		"file trailing slash":   func(s *Spec) { s.Files = map[string]string{"a/": "x"} },
		"file nul":              func(s *Spec) { s.Files = map[string]string{"a\x00b": "x"} },
		"subdir absolute":       func(s *Spec) { s.Subdir = "/etc" },
		"subdir dotdot":         func(s *Spec) { s.Subdir = "../x" },
		"subdir backslash":      func(s *Spec) { s.Subdir = `a\b` },
		"subdir drive":          func(s *Spec) { s.Subdir = "D:" },
		"subdir dash":           func(s *Spec) { s.Subdir = "-x" },
		"source missing":        func(s *Spec) { s.SourceDir = filepath.Join(src, "missing") },
		"source not a dir":      func(s *Spec) { s.SourceDir = notDir },
		"network host":          func(s *Spec) { s.Profile.Network = "host" },
		"network bridge":        func(s *Spec) { s.Profile.Network = "bridge" },
		"timeout over cap":      func(s *Spec) { s.Profile.Timeout = 15*time.Minute + time.Second },
		"timeout negative":      func(s *Spec) { s.Profile.Timeout = -time.Second },
		"memory negative":       func(s *Spec) { s.Profile.MemoryMB = -1 },
		"cpus negative":         func(s *Spec) { s.Profile.CPUs = -1 },
		"pids negative":         func(s *Spec) { s.Profile.PIDs = -1 },
		"env bad name":          func(s *Spec) { s.Env = map[string]string{"1A": "x"} },
		"env name with equals":  func(s *Spec) { s.Env = map[string]string{"A=B": "x"} },
		"env empty name":        func(s *Spec) { s.Env = map[string]string{"": "x"} },
		"env value newline":     func(s *Spec) { s.Env = map[string]string{"A": "x\ny"} },
		"env value nul":         func(s *Spec) { s.Env = map[string]string{"A": "x\x00y"} },
		"env override HOME":     func(s *Spec) { s.Env = map[string]string{"HOME": "/root"} },
		"env override GOPROXY":  func(s *Spec) { s.Env = map[string]string{"GOPROXY": "https://proxy.example"} },
		"env override GOFLAGS":  func(s *Spec) { s.Env = map[string]string{"GOFLAGS": "-mod=vendor"} },
		"env override toolchn":  func(s *Spec) { s.Env = map[string]string{"GOTOOLCHAIN": "auto"} },
		"env override subdir":   func(s *Spec) { s.Env = map[string]string{"SPACKLE_SUBDIR": "../.."} },
		"env override npm":      func(s *Spec) { s.Env = map[string]string{"npm_config_update_notifier": "true"} },
		"env override pip":      func(s *Spec) { s.Env = map[string]string{"PIP_DISABLE_PIP_VERSION_CHECK": "0"} },
		"env override python":   func(s *Spec) { s.Env = map[string]string{"PYTHONDONTWRITEBYTECODE": "0"} },
		"env override gocache":  func(s *Spec) { s.Env = map[string]string{"GOCACHE": "/x"} },
		"env override gopath":   func(s *Spec) { s.Env = map[string]string{"GOPATH": "/x"} },
		"timeout way over cap":  func(s *Spec) { s.Profile.Timeout = time.Hour },
		"image leading newline": func(s *Spec) { s.Image = "\nalpine" },
	}
	stage := t.TempDir()
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := baseSpec()
			mutate(&spec)
			args, err := BuildArgs(spec, stage, "spackle-0123456789ab")
			if err == nil {
				t.Fatalf("expected a validation error, got args %q", args)
			}
			if args != nil {
				t.Errorf("args must be nil on error, got %q", args)
			}
		})
	}

	t.Run("bad container name", func(t *testing.T) {
		for _, name := range []string{"", "-x", "a b", "--privileged"} {
			if _, err := BuildArgs(baseSpec(), stage, name); err == nil {
				t.Errorf("expected an error for container name %q", name)
			}
		}
	})
	t.Run("timeout at cap is allowed", func(t *testing.T) {
		spec := baseSpec()
		spec.Profile.Timeout = 15 * time.Minute
		if _, err := BuildArgs(spec, stage, "spackle-0123456789ab"); err != nil {
			t.Errorf("15m must be accepted: %v", err)
		}
	})
}

func TestBuildArgsRejectsMountOptionInjection(t *testing.T) {
	// A comma inside a --mount source would be parsed as another mount option.
	dir := filepath.Join(t.TempDir(), "a,target=x")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Skipf("cannot create a directory with a comma in its name: %v", err)
	}
	spec := baseSpec()
	spec.SourceDir = dir
	if _, err := BuildArgs(spec, "", "spackle-0123456789ab"); err == nil {
		t.Fatal("expected an error for a SourceDir containing a comma")
	}
}

func TestBuildArgsBootstrapIsFixed(t *testing.T) {
	hostile := "; rm -rf / #"
	benign := mustBuild(t, baseSpec(), "")
	spec := baseSpec()
	spec.Cmd = []string{"echo", hostile, "$(id)", "`id`"}
	args := mustBuild(t, spec, "")

	scriptIdx := slices.Index(args, bootstrap)
	if scriptIdx < 0 || slices.Index(benign, bootstrap) != scriptIdx {
		t.Fatalf("bootstrap script not found at the same position: %d in %q", scriptIdx, args)
	}
	if args[scriptIdx-1] != "-c" || args[scriptIdx-2] != "sh" || args[scriptIdx+1] != "sh" {
		t.Fatalf("bootstrap is not wrapped as sh -c <script> sh: %q", args)
	}
	want := []string{"echo", hostile, "$(id)", "`id`"}
	if !slices.Equal(args[scriptIdx+2:], want) {
		t.Fatalf("Cmd elements after the script are %q, want %q", args[scriptIdx+2:], want)
	}
	for i, a := range args[:scriptIdx+2] {
		if strings.Contains(a, hostile) || strings.Contains(a, "$(id)") {
			t.Errorf("Cmd content leaked into argument %d: %q", i, a)
		}
	}
	if strings.Contains(bootstrap, hostile) {
		t.Error("bootstrap script contains Cmd content")
	}
	if !strings.Contains(bootstrap, `exec "$@"`) {
		t.Error(`bootstrap must end by running exec "$@"`)
	}
}

func TestProfileWithDefaults(t *testing.T) {
	got := Profile{}.WithDefaults()
	want := Profile{Network: "none", MemoryMB: 1024, CPUs: 2, PIDs: 256, Timeout: 2 * time.Minute}
	if got != want {
		t.Errorf("WithDefaults() = %+v, want %+v", got, want)
	}
	custom := Profile{Network: "scope", MemoryMB: 64, CPUs: 0.25, PIDs: 8, Timeout: time.Second}
	if custom.WithDefaults() != custom {
		t.Errorf("WithDefaults() changed set fields: %+v", custom.WithDefaults())
	}
}

func TestProfileSummary(t *testing.T) {
	got := Profile{}.Summary()
	want := "network none, capabilities dropped, read-only root, non-root user, 1024 MB memory, 2 CPUs, 256 processes, 2m0s timeout"
	if got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
	scoped := Profile{Network: "scope", MemoryMB: 512, CPUs: 1, PIDs: 32, Timeout: 30 * time.Second}.Summary()
	wantScoped := "network bridge (scope), capabilities dropped, read-only root, non-root user, 512 MB memory, 1 CPU, 32 processes, 30s timeout"
	if scoped != wantScoped {
		t.Errorf("Summary() = %q, want %q", scoped, wantScoped)
	}
}

func TestCapWriter(t *testing.T) {
	w := &capWriter{limit: 10}
	for _, chunk := range []string{"12345", "67890abc", "more"} {
		n, err := w.Write([]byte(chunk))
		if err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = %d, %v; the writer must accept everything so the child never blocks", chunk, n, err)
		}
	}
	got := w.String()
	if !strings.HasPrefix(got, "1234567890") || strings.Contains(got, "abc") {
		t.Errorf("output not capped at the limit: %q", got)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("missing truncation note: %q", got)
	}
	small := &capWriter{limit: 10}
	_, _ = small.Write([]byte("ok"))
	if small.String() != "ok" {
		t.Errorf("untruncated output changed: %q", small.String())
	}
}

func TestDetectNoneAndUnknown(t *testing.T) {
	rt, err := Detect(context.Background(), "none")
	if !errors.Is(err, ErrNoRuntime) || rt != nil {
		t.Errorf(`Detect("none") = %v, %v; want ErrNoRuntime`, rt, err)
	}
	rt, err = Detect(context.Background(), "containerd")
	if err == nil || rt != nil {
		t.Errorf("Detect with an unknown runtime name must fail, got %v, %v", rt, err)
	}
}

func TestDetectNothingOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, preferred := range []string{"auto", "docker", "podman"} {
		rt, err := Detect(context.Background(), preferred)
		if !errors.Is(err, ErrNoRuntime) || rt != nil {
			t.Errorf("Detect(%q) with an empty PATH = %v, %v; want ErrNoRuntime", preferred, rt, err)
		}
	}
}
