package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/seed"
)

// scanOnce stores one deterministic run of a planted critical flaw and
// returns the config that points at it and the run directory.
func scanOnce(t *testing.T, runtime string) (cfg, runDir string) {
	t.Helper()
	cfg, stateDir := stateConfig(t, runtime)
	target := plantedTarget(t, criticalFlaw)
	if code, _, stderr := run("scan", target, "--config", cfg, "--offline", "--format", "json"); code != ExitFindings {
		t.Fatalf("scan: exit = %d, want %d\nstderr: %s", code, ExitFindings, stderr)
	}
	return cfg, onlyRunDir(t, stateDir)
}

func TestReportReproducesTheStoredReport(t *testing.T) {
	cfg, runDir := scanOnce(t, "none")
	id := filepath.Base(runDir)

	for format, file := range map[string]string{
		"markdown": "report.md", "json": "report.json", "sarif": "report.sarif", "html": "report.html", "terminal": "report.txt",
	} {
		code, stdout, stderr := run("report", "latest", "--config", cfg, "--format", format)
		// A report is a rendering, not a gate: it exits 0 whatever the run found.
		if code != ExitOK {
			t.Errorf("%s: exit = %d, want %d\nstderr: %s", format, code, ExitOK, stderr)
			continue
		}
		if stdout != string(mustRead(t, filepath.Join(runDir, "reports", file))) {
			t.Errorf("report --format %s differs from %s in the run directory", format, file)
		}
		if stderr != "" {
			t.Errorf("%s: unexpected stderr: %s", format, stderr)
		}
	}

	want := string(mustRead(t, filepath.Join(runDir, "reports", "report.md")))
	for name, args := range map[string][]string{
		"no id means latest": {"report", "--config", cfg, "--format", "markdown"},
		"the full id":        {"report", id, "--config", cfg, "--format", "markdown"},
		"a unique prefix":    {"report", "--format", "markdown", id[:len(id)-3], "--config", cfg},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK || stdout != want {
			t.Errorf("%s: code=%d, same bytes=%v\nstderr: %s", name, code, stdout == want, stderr)
		}
	}
}

func TestReportOutWritesFiles(t *testing.T) {
	cfg, runDir := scanOnce(t, "none")
	out := filepath.Join(t.TempDir(), "out")

	code, stdout, stderr := run("report", "latest", "--config", cfg, "--format", "sarif,markdown", "--out", out)
	if code != ExitOK || stdout != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, name := range []string{"report.sarif", "report.md"} {
		path := filepath.Join(out, name)
		if !bytes.Equal(mustRead(t, path), mustRead(t, filepath.Join(runDir, "reports", name))) {
			t.Errorf("%s differs from the copy in the run directory", name)
		}
		if !strings.Contains(stderr, "Wrote "+path+"\n") {
			t.Errorf("stderr has no \"Wrote\" line for %s:\n%s", path, stderr)
		}
	}
}

func TestReportUsageErrors(t *testing.T) {
	cfg, runDir := scanOnce(t, "none")
	emptyState, _ := stateConfig(t, "none")

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"unknown run id", []string{"report", "nosuchid", "--config", cfg}, []string{`run "nosuchid" not found`, "the most recent run is " + filepath.Base(runDir)}},
		{"two run ids", []string{"report", "latest", "latest", "--config", cfg}, []string{"expected one run id, got 2"}},
		{"no runs stored", []string{"report", "latest", "--config", emptyState}, []string{"no runs found", "spackle scan"}},
		{"unknown format", []string{"report", "latest", "--config", cfg, "--format", "pdf"}, []string{`unknown report format "pdf"`}},
		{"unknown flag", []string{"report", "--no-such-flag"}, []string{"no-such-flag"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := run(c.args...)
			if code != ExitUsage || stdout != "" {
				t.Errorf("code=%d (want %d) stdout=%q\nstderr: %s", code, ExitUsage, stdout, stderr)
			}
			for _, want := range c.want {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr)
				}
			}
		})
	}
}

// A deterministic run stores no proofs, so verify has nothing to re-run and
// refuses with exit 2. Which refusal is given depends on the machine: with
// a container engine it is "no stored proofs", without one it is the
// missing runtime, which is checked first.
func TestVerifyDeterministicRunIsRefused(t *testing.T) {
	cfg, _ := scanOnce(t, "auto")

	code, stdout, stderr := run("verify", "latest", "--config", cfg)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitUsage, stderr)
	}
	if stdout != "" {
		t.Errorf("a refused verify printed outcomes: %q", stdout)
	}
	if !strings.Contains(stderr, "spackle verify: run refused") {
		t.Errorf("stderr does not report a refusal:\n%s", stderr)
	}
	if !strings.Contains(stderr, "no stored proofs") && !strings.Contains(stderr, "no container runtime") {
		t.Errorf("stderr names neither the missing proofs nor the missing runtime:\n%s", stderr)
	}
}

func TestVerifyWithTheSandboxDisabledIsRefused(t *testing.T) {
	cfg, _ := scanOnce(t, "none")

	code, stdout, stderr := run("verify", "--config", cfg) // no id: latest
	if code != ExitUsage || stdout != "" {
		t.Fatalf("code=%d (want %d) stdout=%q\nstderr: %s", code, ExitUsage, stdout, stderr)
	}
	for _, want := range []string{"spackle verify: run refused", "no container runtime", `set to "none"`} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestVerifyUsageErrors(t *testing.T) {
	cfg, _ := scanOnce(t, "none")
	emptyState, _ := stateConfig(t, "none")

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown run id", []string{"verify", "nosuchid", "--config", cfg}, `run "nosuchid" not found`},
		{"two run ids", []string{"verify", "a", "b", "--config", cfg}, "expected one run id, got 2"},
		{"no runs stored", []string{"verify", "latest", "--config", emptyState}, "no runs found"},
		{"a flag verify does not read", []string{"verify", "--config", cfg, "--fix"}, "flag provided but not defined: -fix"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := run(c.args...)
			if code != ExitUsage || stdout != "" || !strings.Contains(stderr, c.want) {
				t.Errorf("code=%d (want %d) stdout=%q, stderr should contain %q:\n%s", code, ExitUsage, stdout, c.want, stderr)
			}
		})
	}
}

func TestReadIssue(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	read := func(arg string) (text, stderr string, err error) {
		var errb bytes.Buffer
		text, err = readIssue(Env{Stderr: &errb}, arg)
		return text, errb.String(), err
	}

	t.Run("text is returned as it is", func(t *testing.T) {
		const issue = "  Login fails with a 500 when the name has a quote in it.\n"
		text, stderr, err := read(issue)
		if err != nil || text != issue || stderr != "" {
			t.Fatalf("text=%q stderr=%q err=%v", text, stderr, err)
		}
	})

	t.Run("a file is read", func(t *testing.T) {
		const body = "Title: crash on save\r\n\r\nSteps:\r\n1. open\r\n2. save\r\n"
		text, stderr, err := read(write("issue.md", body))
		if err != nil || text != body || stderr != "" {
			t.Fatalf("text=%q stderr=%q err=%v", text, stderr, err)
		}
	})

	t.Run("a directory is not a file to read", func(t *testing.T) {
		text, stderr, err := read(dir)
		if err != nil || text != dir || stderr != "" {
			t.Fatalf("text=%q stderr=%q err=%v", text, stderr, err)
		}
	})

	for name, body := range map[string]string{"an empty file": "", "a file of white space": " \r\n\t\n"} {
		t.Run(name+" is an error", func(t *testing.T) {
			path := write("blank.txt", body)
			text, _, err := read(path)
			if err == nil || text != "" {
				t.Fatalf("text=%q err=%v, want an error", text, err)
			}
			if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "is empty") {
				t.Errorf("the error does not name the file and the problem: %v", err)
			}
		})
	}

	t.Run("a file at the limit is used whole", func(t *testing.T) {
		body := strings.Repeat("a", maxIssueFile)
		text, stderr, err := read(write("limit.txt", body))
		if err != nil || text != body || stderr != "" {
			t.Fatalf("len=%d stderr=%q err=%v", len(text), stderr, err)
		}
	})

	t.Run("a file over the limit is cut with a warning", func(t *testing.T) {
		path := write("big.txt", strings.Repeat("a", maxIssueFile)+"TAIL")
		text, stderr, err := read(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(text) != maxIssueFile || strings.Contains(text, "T") {
			t.Errorf("len=%d, want the first %d bytes only", len(text), maxIssueFile)
		}
		if !strings.Contains(stderr, path) || !strings.Contains(stderr, "larger than 64 KiB") || !strings.Contains(stderr, "only the first 64 KiB are used") {
			t.Errorf("no warning about the cut: %q", stderr)
		}
	})
}

func TestDebugUsageErrors(t *testing.T) {
	cfg, stateDir := stateConfig(t, "none")
	target := plantedTarget(t, criticalFlaw)
	blank := filepath.Join(t.TempDir(), "issue.txt")
	if err := os.WriteFile(blank, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"nothing to debug", []string{"debug", target, "--config", cfg}, []string{"nothing to debug was given", "--test <name>", "--issue <file|text>"}},
		{"test and issue", []string{"debug", target, "--config", cfg, "--test", "TestX", "--issue", "it breaks"}, []string{"--test and --issue were both given"}},
		{"two paths", []string{"debug", target, target, "--config", cfg, "--test", "TestX"}, []string{"expected one path, got 2"}},
		{"fix and no-fix", []string{"debug", target, "--config", cfg, "--test", "TestX", "--fix", "--no-fix"}, []string{"--fix and --no-fix"}},
		{"empty issue file", []string{"debug", target, "--config", cfg, "--issue", blank}, []string{"the issue file", "is empty"}},
		{"unknown flag", []string{"debug", "--no-such-flag"}, []string{"no-such-flag"}},
		// No model and no runtime: the engine refuses, and that is exit 2.
		{"no model and no runtime", []string{"debug", target, "--config", cfg, "--issue", "it breaks"}, []string{"spackle debug: run refused", "needs both a model and a container runtime", "Nothing was run"}},
		{"missing directory", []string{"debug", filepath.Join(target, "nope"), "--config", cfg, "--test", "TestX"}, []string{"spackle debug: run refused"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := run(c.args...)
			if code != ExitUsage || stdout != "" {
				t.Errorf("code=%d (want %d) stdout=%q\nstderr: %s", code, ExitUsage, stdout, stderr)
			}
			for _, want := range c.want {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr)
				}
			}
		})
	}
	if dirs := runDirs(t, stateDir); len(dirs) != 0 {
		t.Errorf("a refused debug run left a run directory behind: %v", dirs)
	}
}

func TestMCPUsageErrors(t *testing.T) {
	cfg, _ := stateConfig(t, "none")
	root := t.TempDir()

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"positional argument", []string{"mcp", "extra-arg", "--config", cfg}, []string{`unexpected argument "extra-arg"`, "--root"}},
		{"empty root", []string{"mcp", "--config", cfg, "--root", ""}, []string{"a root cannot be empty"}},
		{"blank root", []string{"mcp", "--config", cfg, "--root", "  "}, []string{"a root cannot be empty"}},
		{"root that does not exist", []string{"mcp", "--config", cfg, "--root", filepath.Join(root, "nope")}, []string{"spackle mcp:", "--root"}},
		{"config file that does not exist", []string{"mcp", "--config", filepath.Join(root, "absent.toml"), "--root", root}, []string{"read config"}},
		// The server has its own short flag list: scan flags mean nothing to it.
		{"scan flag", []string{"mcp", "--config", cfg, "--root", root, "--yes"}, []string{"yes"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := run(c.args...)
			if code != ExitUsage {
				t.Errorf("exit = %d, want %d\nstderr: %s", code, ExitUsage, stderr)
			}
			// Standard output carries protocol messages only.
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
			for _, want := range c.want {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr)
				}
			}
		})
	}
}

// A client that closes standard input ends the server cleanly.
func TestMCPStdinAtEOFExitsCleanly(t *testing.T) {
	cfg, _ := stateConfig(t, "none")
	first, second := t.TempDir(), t.TempDir()

	code, stdout, stderr := run("mcp", "--config", cfg, "--root", first, "--root", second, "--offline")
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitOK, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want no protocol message without a request", stdout)
	}
	if !strings.Contains(stderr, "spackle mcp: serving on standard input and output") {
		t.Errorf("no status line on stderr:\n%s", stderr)
	}
}

func TestRootListCollectsEveryRoot(t *testing.T) {
	var roots rootList
	for _, v := range []string{"a", "b c"} {
		if err := roots.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := roots.Set(" \t"); err == nil {
		t.Error("a blank root was accepted")
	}
	if len(roots) != 2 || roots[0] != "a" || roots[1] != "b c" || roots.String() != "a, b c" {
		t.Errorf("roots = %q (%s)", []string(roots), roots.String())
	}
}

// doctorRows returns the check lines of doctor output: the ones that start
// with a status in brackets.
func doctorRows(stdout string) []string {
	var rows []string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "  [") {
			rows = append(rows, line)
		}
	}
	return rows
}

func TestDoctorPrintsOneRowPerCheckAndIsReadyWithoutAModel(t *testing.T) {
	cfg, _ := stateConfig(t, "none")

	code, stdout, stderr := run("doctor", "--config", cfg)
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, ExitOK, stdout, stderr)
	}
	if stderr != "" {
		t.Errorf("unexpected stderr: %s", stderr)
	}
	if !strings.HasPrefix(stdout, "spackle ") {
		t.Errorf("the output does not lead with the version:\n%s", stdout)
	}
	// One row for git, one for the disabled sandbox, one per seeder, one
	// for the model.
	rows := doctorRows(stdout)
	if want := 1 + 1 + len(seed.Builtin()) + len(seed.External()) + 1; len(rows) != want {
		t.Errorf("%d rows, want %d:\n%s", len(rows), want, stdout)
	}
	for _, s := range append(seed.Builtin(), seed.External()...) {
		n := 0
		for _, row := range rows {
			if fields := strings.Fields(row); len(fields) > 1 && fields[1] == s.Name() {
				n++
			}
		}
		if n != 1 {
			t.Errorf("seeder %s has %d rows, want 1:\n%s", s.Name(), n, stdout)
		}
	}
	// The areas come as headings, in this order.
	at := -1
	for _, area := range []string{"\nTools\n", "\nSandbox\n", "\nSeeders\n", "\nModel\n"} {
		i := strings.Index(stdout, area)
		if i <= at {
			t.Errorf("area heading %q is missing or out of order:\n%s", strings.TrimSpace(area), stdout)
		}
		at = i
	}
	for _, want := range []string{
		"[warn]     runtime            disabled in config",
		"[warn]     provider           none configured",
		"Result: ready.",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	for _, row := range rows {
		if strings.HasPrefix(row, "  [fail]") {
			t.Errorf("a failed check did not fail the command: %s", row)
		}
		if row != strings.TrimRight(row, " ") {
			t.Errorf("trailing spaces in %q", row)
		}
	}
}

// A model that cannot be used is a failed required check: exit 2. Neither
// case reaches a provider: the first has no key, the second is refused by
// offline mode before any request.
func TestDoctorFailsWhenTheModelCannotBeUsed(t *testing.T) {
	cfg, _ := stateConfig(t, "none")

	t.Run("no API key", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		code, stdout, _ := run("doctor", "--config", cfg, "--provider", "anthropic", "--model", "some-model")
		if code != ExitUsage {
			t.Fatalf("exit = %d, want %d\n%s", code, ExitUsage, stdout)
		}
		for _, want := range []string{"[fail]     model (default)", "anthropic some-model", "ANTHROPIC_API_KEY", "Result: a required check failed."} {
			if !strings.Contains(stdout, want) {
				t.Errorf("output lacks %q:\n%s", want, stdout)
			}
		}
		if strings.Contains(stdout, "Result: ready") {
			t.Errorf("a failed check was reported as ready:\n%s", stdout)
		}
	})

	t.Run("remote provider in offline mode", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "placeholder-"+"not-a-key")
		code, stdout, _ := run("doctor", "--config", cfg, "--provider", "anthropic", "--model", "some-model", "--offline")
		if code != ExitUsage {
			t.Fatalf("exit = %d, want %d\n%s", code, ExitUsage, stdout)
		}
		for _, want := range []string{"[fail]     model (default)", "offline mode", "Result: a required check failed."} {
			if !strings.Contains(stdout, want) {
				t.Errorf("output lacks %q:\n%s", want, stdout)
			}
		}
		if strings.Contains(stdout, "placeholder-") {
			t.Error("the key value was printed")
		}
	})
}

func TestDoctorUsageErrors(t *testing.T) {
	if code, stdout, stderr := run("doctor", "--config", filepath.Join(t.TempDir(), "absent.toml")); code != ExitUsage || stdout != "" || !strings.Contains(stderr, "spackle doctor: read config") {
		t.Errorf("missing config: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if code, _, stderr := run("doctor", "--no-such-flag"); code != ExitUsage || !strings.Contains(stderr, "no-such-flag") {
		t.Errorf("unknown flag: code=%d stderr=%q", code, stderr)
	}
	if code, stdout, stderr := run("doctor", "--help"); code != ExitOK || stdout != "" || !strings.Contains(stderr, "spackle doctor [flags]") {
		t.Errorf("help: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// Without --allow-model the MCP doctor tool must not look at the configured
// model at all: its rows are replaced by one that says why no model is used.
func TestMCPDoctorHidesTheModelWithoutAllowModel(t *testing.T) {
	cfg := config.Default()
	cfg.Sandbox.Runtime = "none"

	modelRows := func(allowModel bool) (rows []string, total int) {
		checks := mcpDoctor(cfg, allowModel)(context.Background())
		for _, c := range checks {
			if c.Area == "Model" {
				rows = append(rows, c.Status+" "+c.Name+": "+c.Note)
			}
		}
		return rows, len(checks)
	}
	want := 1 + 1 + len(seed.Builtin()) + len(seed.External()) + 1

	// No model configured: the plain "none configured" row, either way.
	for _, allow := range []bool{false, true} {
		rows, total := modelRows(allow)
		if len(rows) != 1 || !strings.HasPrefix(rows[0], "warn provider: none configured") || total != want {
			t.Errorf("no model, allow-model=%v: %d checks (want %d), model rows %q", allow, total, want, rows)
		}
	}

	// A model is configured but the server may not use it. The key is
	// absent, so a probe would show as a "fail" row if one were attempted.
	t.Setenv("ANTHROPIC_API_KEY", "")
	cfg.Model = config.Model{Provider: "anthropic", Model: "some-model"}
	rows, total := modelRows(false)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "warn provider: ") || !strings.Contains(rows[0], "without --allow-model") || total != want {
		t.Errorf("model held back: %d checks (want %d), model rows %q", total, want, rows)
	}

	// With --allow-model the model is checked, and the missing key shows.
	rows, _ = modelRows(true)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "fail model (default): ") || !strings.Contains(rows[0], "ANTHROPIC_API_KEY") {
		t.Errorf("model allowed: model rows %q", rows)
	}
}

func TestSplitList(t *testing.T) {
	cases := map[string][]string{
		"":                   nil,
		" , ,":               nil,
		"json":               {"json"},
		"sarif,markdown":     {"sarif", "markdown"},
		" sarif , markdown,": {"sarif", "markdown"},
	}
	for in, want := range cases {
		got := splitList(in)
		if strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Errorf("splitList(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWantColorOnlyOnATerminal(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm")
	if wantColor(&bytes.Buffer{}) {
		t.Error("color for a writer that is not a file")
	}
	path := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(path) //nolint:gosec // a file the test itself names
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if wantColor(f) {
		t.Error("color for a regular file")
	}

	// The null device is a character device, like a terminal, so it shows
	// that NO_COLOR and TERM=dumb win even there.
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("the null device cannot be opened: %v", err)
	}
	defer func() { _ = null.Close() }()
	t.Setenv("NO_COLOR", "1")
	if wantColor(null) {
		t.Error("color although NO_COLOR is set")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if wantColor(null) {
		t.Error("color although TERM is dumb")
	}
}
