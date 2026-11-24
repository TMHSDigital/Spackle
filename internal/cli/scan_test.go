package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/engine"
)

// Planted flaws the built-in rules report without a model: an f-string SQL
// query (critical) and an MD5 digest (medium).
const (
	criticalFlaw = "import sqlite3\n\ndef find(q):\n    return db.execute(f\"SELECT * FROM t WHERE a = '{q}'\")\n"
	mediumFlaw   = "import hashlib\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n"
)

// stateConfig writes a config file with no model and a state directory of
// its own, so a test never reads the developer's spackle.toml, never makes
// a paid run and never writes into the repository. runtime is the
// [sandbox] runtime setting: "none" keeps a test from probing for a
// container engine.
func stateConfig(t *testing.T, runtime string) (cfgPath, stateDir string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	body := "state_dir = " + strconv.Quote(filepath.ToSlash(stateDir)) + "\n\n[sandbox]\nruntime = " + strconv.Quote(runtime) + "\n"
	cfgPath = filepath.Join(dir, "spackle.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, stateDir
}

// plantedTarget writes a one-file Python project. The parent directory is
// made a git ceiling, so git never mistakes an enclosing repository (a home
// directory under version control, say) for the target's.
func plantedTarget(t *testing.T, source string) string {
	t.Helper()
	return plantedTargets(t, source)[0]
}

// plantedTargets writes one project per source under a single git ceiling
// and returns their directories in the same order.
func plantedTargets(t *testing.T, sources ...string) []string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", base)
	var roots []string
	for i, source := range sources {
		root := filepath.Join(base, "my app "+strconv.Itoa(i))
		if err := os.MkdirAll(root, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "app.py"), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
	}
	return roots
}

// runDirs lists the run directories under a state directory.
func runDirs(t *testing.T, stateDir string) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(engine.RunsDir(stateDir), "*"))
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

// onlyRunDir returns the single run directory a test's scan stored.
func onlyRunDir(t *testing.T, stateDir string) string {
	t.Helper()
	dirs := runDirs(t, stateDir)
	if len(dirs) != 1 {
		t.Fatalf("run directories = %v, want exactly one", dirs)
	}
	return dirs[0]
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a file the test itself wrote
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// scanReport is the part of the JSON report these tests look at.
type scanReport struct {
	Schema string `json:"schema"`
	Run    struct {
		Command string `json:"command"`
		Mode    string `json:"mode"`
		Outcome string `json:"outcome"`
	} `json:"run"`
	Findings []struct {
		Status   string `json:"status"`
		Location struct {
			File string `json:"file"`
		} `json:"location"`
		Severity struct {
			Label string `json:"label"`
		} `json:"severity"`
	} `json:"findings"`
}

func decodeReport(t *testing.T, stdout string) scanReport {
	t.Helper()
	var rep scanReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, stdout)
	}
	return rep
}

// labels returns the severity label of every finding in the report.
func (r scanReport) labels() []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Severity.Label)
	}
	return out
}

func TestScanPrintsJSONAndExitsOneOnAPlantedFlaw(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)

	code, stdout, stderr := run("scan", target, "--config", cfg, "--offline", "--format", "json")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitFindings, stderr)
	}
	rep := decodeReport(t, stdout)
	if rep.Schema != "spackle.report/v1" || rep.Run.Command != "scan" || rep.Run.Mode != "deterministic" || rep.Run.Outcome != "completed" {
		t.Errorf("report header = %+v", rep)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Location.File == "app.py" && f.Severity.Label == "critical" && f.Status == "open" {
			found = true
		}
	}
	if !found {
		t.Errorf("no open critical finding in app.py:\n%s", stdout)
	}
	runDir := onlyRunDir(t, stateDir)
	if !strings.Contains(stderr, "Run "+filepath.Base(runDir)+" stored in "+runDir) {
		t.Errorf("stderr does not say where the run was stored:\n%s", stderr)
	}
	// With one format on stdout, the same bytes are also kept with the run.
	if stored := mustRead(t, filepath.Join(runDir, "reports", "report.json")); string(stored) != stdout {
		t.Error("stdout differs from the report.json stored in the run directory")
	}
}

func TestScanFailOnDecidesTheExitCode(t *testing.T) {
	cfg, _ := stateConfig(t, "none")
	targets := plantedTargets(t, criticalFlaw, mediumFlaw)
	critical, medium := targets[0], targets[1]

	cases := []struct {
		name   string
		target string
		failOn string // empty: the default, high
		want   int
	}{
		{"critical flaw, critical", critical, "critical", ExitFindings},
		{"critical flaw, never", critical, "never", ExitOK},
		{"medium flaw, default threshold", medium, "", ExitOK},
		{"medium flaw, critical", medium, "critical", ExitOK},
		{"medium flaw, medium", medium, "medium", ExitFindings},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := []string{"scan", c.target, "--config", cfg, "--offline", "--format", "json"}
			if c.failOn != "" {
				args = append(args, "--fail-on", c.failOn)
			}
			code, stdout, stderr := run(args...)
			rep := decodeReport(t, stdout)
			if len(rep.Findings) == 0 {
				t.Fatalf("the planted flaw was not reported:\n%s", stderr)
			}
			if c.target == medium {
				// The case only means something when nothing above medium
				// was found.
				for _, label := range rep.labels() {
					if label == "high" || label == "critical" {
						t.Fatalf("the medium fixture produced a %s finding: %v", label, rep.labels())
					}
				}
			}
			if code != c.want {
				t.Errorf("exit = %d, want %d (severities %v)\nstderr: %s", code, c.want, rep.labels(), stderr)
			}
		})
	}
}

// An excluded file is not scanned, so its flaw cannot fail the run. The
// flag may be repeated.
func TestScanExcludeRemovesTheFlawedFile(t *testing.T) {
	cfg, _ := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)

	code, stdout, stderr := run("scan", target, "--config", cfg, "--offline", "--format", "json", "--exclude", "docs/**", "--exclude", "app.py")
	if rep := decodeReport(t, stdout); len(rep.Findings) != 0 {
		t.Errorf("findings in an excluded file: %v", rep.labels())
	}
	if code != ExitOK {
		t.Errorf("exit = %d, want %d\nstderr: %s", code, ExitOK, stderr)
	}
}

// The GitHub Action reads report.sarif and report.md from the --out
// directory, so the names and the place are part of the contract.
func TestScanOutWritesTheFilesTheActionReads(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	out := filepath.Join(t.TempDir(), "nested", "reports") // created on demand

	code, stdout, stderr := run("scan", target, "--config", cfg, "--offline", "--format", "sarif,markdown", "--out", out)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitFindings, stderr)
	}
	if stdout != "" {
		t.Errorf("with --out nothing belongs on stdout, got:\n%s", stdout)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "report.md,report.sarif" {
		t.Fatalf("files in --out = %v, want report.md and report.sarif only", names)
	}
	runDir := onlyRunDir(t, stateDir)
	for _, name := range names {
		path := filepath.Join(out, name)
		if !strings.Contains(stderr, "Wrote "+path+"\n") {
			t.Errorf("stderr has no \"Wrote\" line for %s:\n%s", path, stderr)
		}
		if !bytes.Equal(mustRead(t, path), mustRead(t, filepath.Join(runDir, "reports", name))) {
			t.Errorf("%s differs from the copy in the run directory", name)
		}
	}
	if n := strings.Count(stderr, "Wrote "); n != 2 {
		t.Errorf("%d \"Wrote\" lines, want 2:\n%s", n, stderr)
	}

	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(out, "report.sarif")), &sarif); err != nil {
		t.Fatalf("report.sarif is not JSON: %v", err)
	}
	if sarif.Version != "2.1.0" || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) == 0 {
		t.Errorf("report.sarif = %+v, want SARIF 2.1.0 with the planted flaw as a result", sarif)
	}
	if md := string(mustRead(t, filepath.Join(out, "report.md"))); !strings.HasPrefix(md, "# Spackle report") || !strings.Contains(md, "app.py") {
		t.Errorf("report.md does not look like the report:\n%.300s", md)
	}
}

func TestScanSeveralFormatsWithoutOutStayInTheRunDirectory(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)

	code, stdout, stderr := run("scan", target, "--config", cfg, "--offline", "--format", "sarif, markdown", "--fail-on", "never")
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitOK, stderr)
	}
	if stdout != "" {
		t.Errorf("two file formats must not be mixed on stdout, got:\n%s", stdout)
	}
	runDir := onlyRunDir(t, stateDir)
	for _, name := range []string{"report.sarif", "report.md"} {
		path := filepath.Join(runDir, "reports", name)
		if !strings.Contains(stderr, "Wrote "+path+"\n") {
			t.Errorf("stderr does not point at %s:\n%s", path, stderr)
		}
		if st, err := os.Stat(path); err != nil || st.Size() == 0 {
			t.Errorf("%s was announced but is missing or empty (%v)", path, err)
		}
	}
}

func TestScanTerminalReportGoesToStdoutBesideFilesInOut(t *testing.T) {
	cfg, _ := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	out := filepath.Join(t.TempDir(), "out")

	// No --format: the default is the terminal report.
	code, stdout, stderr := run("scan", target, "--config", cfg, "--offline")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitFindings, stderr)
	}
	if !strings.HasPrefix(stdout, "Spackle report") || !strings.Contains(stdout, "app.py") {
		t.Errorf("stdout is not the terminal report:\n%.300s", stdout)
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Error("color codes were written to something that is not a terminal")
	}

	code, stdout, stderr = run("scan", target, "--config", cfg, "--offline", "--format", "terminal,json", "--out", out)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitFindings, stderr)
	}
	if !strings.HasPrefix(stdout, "Spackle report") {
		t.Errorf("the terminal format must still go to stdout with --out:\n%.300s", stdout)
	}
	decodeReport(t, string(mustRead(t, filepath.Join(out, "report.json"))))
	if _, err := os.Stat(filepath.Join(out, "report.txt")); err == nil {
		t.Error("the terminal format was also written to --out")
	}
}

func TestScanUsageErrors(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	missingConfig := filepath.Join(t.TempDir(), "absent.toml")

	cases := []struct {
		name string
		args []string
		want []string // every one must be on stderr
	}{
		{"two targets", []string{"scan", target, target, "--config", cfg}, []string{"expected one target, got 2", "Quote a path"}},
		{"fix and no-fix", []string{"scan", target, "--config", cfg, "--fix", "--no-fix"}, []string{"--fix and --no-fix", "choose one"}},
		{"unknown format", []string{"scan", target, "--config", cfg, "--format", "pdf"}, []string{`unknown report format "pdf"`, "terminal", "markdown", "html", "json", "sarif"}},
		{"unknown format beside a good one", []string{"scan", target, "--config", cfg, "--format", "json,pdf"}, []string{`unknown report format "pdf"`}},
		{"unknown fail-on", []string{"scan", target, "--config", cfg, "--fail-on", "sometimes"}, []string{"fail_on", "sometimes", "critical, high, medium, low, never"}},
		{"config file that does not exist", []string{"scan", target, "--config", missingConfig}, []string{"read config", "--config"}},
		{"unknown flag", []string{"scan", target, "--config", cfg, "--no-such-flag"}, []string{"no-such-flag"}},
		{"flag value of the wrong type", []string{"scan", target, "--config", cfg, "--budget-tokens", "many"}, []string{"budget-tokens"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := run(c.args...)
			if code != ExitUsage {
				t.Errorf("exit = %d, want %d\nstderr: %s", code, ExitUsage, stderr)
			}
			if stdout != "" {
				t.Errorf("a usage error wrote to stdout: %q", stdout)
			}
			for _, want := range c.want {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr)
				}
			}
		})
	}
	if dirs := runDirs(t, stateDir); len(dirs) != 0 {
		t.Errorf("a usage error started a run: %v", dirs)
	}
}

func TestScanHelpIsNotAnError(t *testing.T) {
	code, stdout, stderr := run("scan", "--help")
	if code != ExitOK || stdout != "" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	for _, want := range []string{AuthorizedUse, "spackle scan [flags] [path|url]", "--fail-on severity", "--out directory", "--yes"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("help lacks %q:\n%s", want, stderr)
		}
	}
}

// A target that does not exist is a refused run: exit 2, and nothing is
// left in the state directory.
func TestScanMissingTargetIsRefused(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	missing := filepath.Join(t.TempDir(), "nope")

	code, stdout, stderr := run("scan", missing, "--config", cfg, "--offline", "--format", "json")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitUsage, stderr)
	}
	if stdout != "" {
		t.Errorf("a refused run printed a report: %q", stdout)
	}
	if !strings.Contains(stderr, "spackle scan: run refused") || !strings.Contains(stderr, "does not exist") {
		t.Errorf("stderr does not say why the run was refused:\n%s", stderr)
	}
	if dirs := runDirs(t, stateDir); len(dirs) != 0 {
		t.Errorf("a refused run left a run directory behind: %v", dirs)
	}
}

// TestScanPaidRunWithoutATerminalIsRefused checks the "a pipe is not consent
// to spend" rule end to end. The run is refused before any model call, so
// no request is made; the key is a placeholder that is never sent anywhere.
// PATH is emptied so that no installed scanner is started either: without
// --offline some of them would fetch rules from the network.
func TestScanPaidRunWithoutATerminalIsRefused(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	t.Setenv("ANTHROPIC_API_KEY", "placeholder-"+"not-a-key")
	t.Setenv("PATH", t.TempDir())

	var out, errb bytes.Buffer
	stdin := strings.NewReader("y\n") // an answer in a pipe is still not a terminal
	code := Main([]string{"scan", target, "--config", cfg, "--format", "json", "--provider", "anthropic", "--model", "some-model"}, stdin, &out, &errb)
	stderr := errb.String()
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitUsage, stderr)
	}
	for _, want := range []string{"some-model", "there is no terminal to confirm on", "the run was not confirmed", "--yes"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "Proceed?") {
		t.Errorf("a prompt was shown although nobody can answer it:\n%s", stderr)
	}
	if stdin.Len() != 2 {
		t.Error("the piped answer was read")
	}
	if out.Len() != 0 {
		t.Errorf("a refused run printed a report: %q", out.String())
	}
	if dirs := runDirs(t, stateDir); len(dirs) != 0 {
		t.Errorf("a refused run left a run directory behind: %v", dirs)
	}
}

// TestScanUnattendedDollarCapNeedsAPrice checks that --yes with a dollar cap
// does not start a run the cap cannot stop. "some-model" has no price, so
// the run is refused before any model call and the message carries the
// table to add and the flag that opts in.
func TestScanUnattendedDollarCapNeedsAPrice(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	t.Setenv("ANTHROPIC_API_KEY", "placeholder-"+"not-a-key")
	t.Setenv("PATH", t.TempDir())

	code, out, stderr := run("scan", target, "--config", cfg, "--format", "json", "--yes",
		"--provider", "anthropic", "--model", "some-model", "--budget-usd", "2")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitUsage, stderr)
	}
	for _, want := range []string{"$2.00 cannot be enforced", `[pricing."some-model"]`, "input_per_mtok", "--allow-unpriced", "allow_unpriced = true"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if out != "" {
		t.Errorf("a refused run printed a report: %q", out)
	}
	if dirs := runDirs(t, stateDir); len(dirs) != 0 {
		t.Errorf("a refused run left a run directory behind: %v", dirs)
	}
}

// TestScanSinceNeedsARepository checks that --since reaches the engine and
// that a target git cannot compare is a usage error, not a full scan.
func TestScanSinceNeedsARepository(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	t.Setenv("PATH", t.TempDir())
	code, out, stderr := run("scan", target, "--config", cfg, "--format", "json", "--since", "main")
	if code != ExitUsage || !strings.Contains(stderr, "--since needs a git repository") {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitUsage, stderr)
	}
	if out != "" {
		t.Errorf("a refused run printed a report: %q", out)
	}
	if dirs := runDirs(t, stateDir); len(dirs) != 0 {
		t.Errorf("a refused run left a run directory behind: %v", dirs)
	}
}

func TestConfirmer(t *testing.T) {
	paid := engine.Estimate{Investigations: 3, Model: "some-model", USD: 1.5, CostKnown: true}
	local := engine.Estimate{Investigations: 3, Model: "some-model", Local: true}

	t.Run("yes means no prompt at all", func(t *testing.T) {
		if confirmer(Env{Stdin: strings.NewReader(""), Stderr: &bytes.Buffer{}}, true) != nil {
			t.Fatal("--yes must not install a confirmation step")
		}
	})

	t.Run("no terminal refuses a paid run", func(t *testing.T) {
		var errb bytes.Buffer
		stdin := strings.NewReader("yes\n")
		confirm := confirmer(Env{Stdin: stdin, Stderr: &errb}, false)
		if confirm == nil {
			t.Fatal("without --yes there must be a confirmation step")
		}
		if confirm(paid) {
			t.Fatal("a paid run was confirmed without a terminal")
		}
		if !strings.Contains(errb.String(), "paid model") || !strings.Contains(errb.String(), "no terminal") {
			t.Errorf("stderr does not explain the refusal: %q", errb.String())
		}
		if strings.Contains(errb.String(), "Proceed?") || stdin.Len() != len("yes\n") {
			t.Errorf("the pipe was treated as a terminal: stderr %q, %d bytes left", errb.String(), stdin.Len())
		}
	})

	t.Run("a local model needs no consent", func(t *testing.T) {
		var errb bytes.Buffer
		confirm := confirmer(Env{Stdin: strings.NewReader(""), Stderr: &errb}, false)
		if !confirm(local) {
			t.Fatal("a local model costs nothing and must not be refused")
		}
		if errb.Len() != 0 {
			t.Errorf("a local run wrote a prompt or a refusal: %q", errb.String())
		}
	})

	// At a terminal where nobody types, the prompt is shown and no answer
	// is a "no".
	t.Run("no answer at the prompt is a no", func(t *testing.T) {
		old := isTerminal
		t.Cleanup(func() { isTerminal = old })
		isTerminal = func(io.Reader) bool { return true }
		null := strings.NewReader("")
		var errb bytes.Buffer
		confirm := confirmer(Env{Stdin: null, Stderr: &errb}, false)
		if confirm(paid) {
			t.Fatal("an empty answer confirmed a paid run")
		}
		if !strings.Contains(errb.String(), "Proceed? [y/N]") {
			t.Errorf("no prompt was shown: %q", errb.String())
		}
		if !confirm(local) {
			t.Fatal("a local model costs nothing and must not be refused")
		}
	})
}

func TestIsTerminal(t *testing.T) {
	if isTerminal(strings.NewReader("")) {
		t.Error("a reader that is not a file was taken for a terminal")
	}
	path := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(path, []byte("y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) //nolint:gosec // a file the test itself wrote
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if isTerminal(f) {
		t.Error("a regular file was taken for a terminal")
	}

	// The null device is a character device, and nobody can answer on it.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("the null device cannot be opened: %v", err)
	}
	defer func() { _ = null.Close() }()
	if isTerminal(null) {
		t.Error("the null device was taken for a terminal")
	}
}
