// Command demoassets regenerates, or checks, every place in the repository
// that shows real output of a scan of the bundled demo application:
//
//   - docs/assets/demo.svg, the terminal picture of a deterministic scan
//   - docs/findings.md, the finding-json region (one finding of that scan)
//   - README.md, the finding region (one finding of a running-target scan)
//   - docs/index.html, the finding region (the same finding, as the site shows it)
//
// Nothing in those places is typed by hand, so they are only worth trusting
// while they match what the current code prints. Run from the repository
// root:
//
//	go run ./tools/demoassets            regenerate the picture and docs/findings.md
//	go run ./tools/demoassets -check     exit 1 when one of them is stale (CI runs this)
//	go run ./tools/demoassets -live      also start the demo application and regenerate
//	                                     the README.md and docs/index.html finding
//
// The deterministic scan runs with an empty PATH, so no installed scanner
// adds findings and the result is the same on every machine. The
// running-target finding is not: the path traversal probe reads a system
// file, and which one depends on the operating system. It is therefore not
// checked in CI. -live needs Python, and it starts examples/demo-app, which
// is vulnerable on purpose, on 127.0.0.1 for the length of the scan.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/cli"
	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/report"
)

const (
	demoDir   = "./examples/demo-app"
	svgTitle  = "spackle · deterministic scan of the bundled demo app, no model"
	liveHost  = "localhost:8081"
	liveClass = "path-traversal"
	jsonClass = "sql-injection"
)

var findingIDRe = regexp.MustCompile(`SPK-[0-9A-F]{8}`)

func main() { os.Exit(run()) }

func run() int {
	check := flag.Bool("check", false, "write nothing; exit 1 when a generated place is stale")
	live := flag.Bool("live", false, "also start the demo application and handle the running-target finding in README.md and docs/index.html")
	python := flag.String("python", "", "Python interpreter for -live (default: python3, then python)")
	flag.Parse()
	if _, err := os.Stat(filepath.FromSlash(demoDir + "/app.py")); err != nil {
		fmt.Fprintln(os.Stderr, "demoassets: run this from the repository root (examples/demo-app/app.py was not found)")
		return 2
	}
	work, err := os.MkdirTemp("", "spackle-demoassets-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "demoassets:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(work) }()
	ctx := context.Background()

	stale, err := deterministic(ctx, work, *check)
	if err == nil && *live {
		var more []string
		more, err = running(ctx, work, *check, *python)
		stale = append(stale, more...)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "demoassets:", err)
		return 1
	}
	if len(stale) > 0 {
		fmt.Fprintln(os.Stderr, "demoassets: generated output is stale:")
		for _, s := range stale {
			fmt.Fprintln(os.Stderr, "  "+s)
		}
		fmt.Fprintln(os.Stderr, "Regenerate with: go run ./tools/demoassets (add -live for README.md and docs/index.html), then read the diff.")
		return 1
	}
	if *check {
		fmt.Println("demoassets: the generated output is current")
	}
	return 0
}

// scan runs spackle in this process and returns what it printed and the run
// it stored. A scan exits 1 when it has findings, which is the point here.
func scan(work, name, config string, args ...string) (stdout, stderr string, run report.Run, runDir string, err error) {
	state := filepath.Join(work, name)
	cfg := filepath.Join(work, name+".toml")
	body := fmt.Sprintf("state_dir = %q\n%s", filepath.ToSlash(state), config)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		return "", "", report.Run{}, "", err
	}
	var out, errb bytes.Buffer
	code := cli.Main(append(args, "--config", cfg), strings.NewReader(""), &out, &errb)
	if code != cli.ExitOK && code != cli.ExitFindings {
		return "", "", report.Run{}, "", fmt.Errorf("spackle %s exited with code %d:\n%s", strings.Join(args, " "), code, errb.String())
	}
	if runDir, err = engine.ResolveRun(state, "latest"); err != nil {
		return "", "", report.Run{}, "", err
	}
	run, err = report.Load(runDir)
	return out.String(), errb.String(), run, runDir, err
}

// deterministic handles the picture and the worked example of
// docs/findings.md, both from one scan of the demo application's files.
func deterministic(ctx context.Context, work string, check bool) ([]string, error) {
	// With an empty PATH no external scanner is found, so the scan uses
	// the built-in rules only and gives the same result everywhere.
	path := os.Getenv("PATH")
	empty := filepath.Join(work, "empty-path")
	if err := os.Mkdir(empty, 0o700); err != nil {
		return nil, err
	}
	if err := os.Setenv("PATH", empty); err != nil {
		return nil, err
	}
	stdout, stderr, run, runDir, err := scan(work, "files", "", "scan", demoDir)
	if rerr := os.Setenv("PATH", path); rerr != nil {
		return nil, rerr
	}
	if err != nil {
		return nil, err
	}
	outFile, errFile := filepath.Join(work, "out.txt"), filepath.Join(work, "err.txt")
	if err := os.WriteFile(outFile, []byte(stdout), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(errFile, []byte(stderr), 0o600); err != nil {
		return nil, err
	}
	var stale []string
	note := func(what string, err error) error {
		if err != nil && check {
			stale = append(stale, what)
			return nil
		}
		return err
	}
	svg := []string{"-stdout", outFile, "-stderr", errFile, "-cmd", "spackle scan " + demoDir, "-title", svgTitle, "-out", "docs/assets/demo.svg"}
	if err := note("docs/assets/demo.svg", tool(ctx, check, "./tools/demosvg", svg...)); err != nil {
		return nil, err
	}

	f, ok := first(run, jsonClass)
	if !ok {
		return nil, fmt.Errorf("the scan of %s reported no %s finding to show in docs/findings.md", demoDir, jsonClass)
	}
	raw, err := os.ReadFile(filepath.Join(runDir, "findings", f.ID, "finding.json")) //nolint:gosec // a file of the run this tool just stored
	if err != nil {
		return nil, err
	}
	block := filepath.Join(work, "finding.json.md")
	if err := os.WriteFile(block, []byte("```json\n"+strings.TrimSpace(string(raw))+"\n```\n"), 0o600); err != nil { //nolint:gosec // a file in this tool's own temporary directory
		return nil, err
	}
	if err := note("docs/findings.md (finding-json region)", tool(ctx, check, "./tools/readme", "-readme", "docs/findings.md", "-marker", "finding-json", "-from", block)); err != nil {
		return nil, err
	}
	// The sentence above the region names the finding's file by id.
	s, err := mentions("docs/findings.md", regexp.MustCompile(`findings/SPK-[0-9A-F]{8}/finding\.json`), "findings/"+f.ID+"/finding.json", check)
	return append(stale, s...), err
}

// running handles the finding of a running-target scan, in README.md and
// on the site. It starts the demo application for the length of the scan.
func running(ctx context.Context, work string, check bool, python string) ([]string, error) {
	stop, err := startDemo(ctx, python)
	if err != nil {
		return nil, err
	}
	_, _, run, _, err := scan(work, "live", fmt.Sprintf("\n[scope]\nhosts = [%q]\n", liveHost), "scan", "http://"+liveHost, "--yes")
	stop()
	if err != nil {
		return nil, err
	}
	f, ok := first(run, liveClass)
	if !ok {
		return nil, fmt.Errorf("the scan of http://%s reported no %s finding to show", liveHost, liveClass)
	}
	var md bytes.Buffer
	if err := report.Render("markdown", run, &md); err != nil {
		return nil, err
	}
	section, err := findingSection(md.String(), f.ID)
	if err != nil {
		return nil, err
	}
	var stale []string
	for _, region := range []struct{ file, content, ext string }{
		{"README.md", section, "md"},
		{"docs/index.html", siteFinding(f), "html"},
	} {
		from := filepath.Join(work, "finding."+region.ext)
		if err := os.WriteFile(from, []byte(region.content), 0o600); err != nil {
			return nil, err
		}
		if err := tool(ctx, check, "./tools/readme", "-readme", region.file, "-marker", "finding", "-from", from); err != nil {
			if !check {
				return nil, err
			}
			stale = append(stale, region.file+" (finding region)")
		}
		// Prose around the region names the finding by id. It is written
		// by hand, so a new id is reported instead of being patched in.
		raw, err := os.ReadFile(region.file)
		if err != nil {
			return nil, err
		}
		for _, id := range uniq(findingIDRe.FindAllString(string(raw), -1)) {
			if id != f.ID && namesLiveFinding(string(raw), id) {
				stale = append(stale, fmt.Sprintf("%s names %s next to the finding, and the finding is now %s: update the text by hand", region.file, id, f.ID))
			}
		}
	}
	if !check && len(stale) > 0 {
		for _, s := range stale {
			fmt.Fprintln(os.Stderr, "demoassets: "+s)
		}
		return nil, nil
	}
	return stale, nil
}

// namesLiveFinding reports whether id appears on a line that also names the
// running-target finding's title, which is how the hand-written text around
// the generated region refers to it.
func namesLiveFinding(doc, id string) bool {
	for _, l := range strings.Split(doc, "\n") {
		if strings.Contains(l, id) && (strings.Contains(l, "running-target scan") || strings.Contains(l, "One finding, start to finish")) {
			return true
		}
	}
	return false
}

// first returns the highest ranked finding of a class.
func first(run report.Run, class string) (finding.Finding, bool) {
	for _, f := range run.Findings {
		if f.Class == class {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// tool runs one of the paste tools, with -check when asked.
func tool(ctx context.Context, check bool, pkg string, args ...string) error {
	full := append([]string{"run", pkg}, args...)
	if check {
		full = append(full, "-check")
	}
	cmd := exec.CommandContext(ctx, "go", full...) //nolint:gosec // fixed program and package, arguments built here
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = nil, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %s", pkg, strings.TrimSpace(out.String()))
	}
	return nil
}

// mentions makes the first match of re in file read want. In check mode it
// reports a difference instead of writing.
func mentions(file string, re *regexp.Regexp, want string, check bool) ([]string, error) {
	raw, err := os.ReadFile(file) //nolint:gosec // a fixed file of this repository
	if err != nil {
		return nil, err
	}
	have := re.FindString(string(raw))
	switch {
	case have == want:
		return nil, nil
	case have == "":
		return nil, fmt.Errorf("%s no longer names %s: the text around the generated region changed", file, want)
	case check:
		return []string{fmt.Sprintf("%s names %s, and the scan now gives %s", file, have, want)}, nil
	}
	return nil, os.WriteFile(file, []byte(strings.Replace(string(raw), have, want, 1)), 0o644) //nolint:gosec // a public file
}

// findingSection cuts one finding out of a Markdown report and moves its
// headings one level down, so that it sits under a README heading.
func findingSection(md, id string) (string, error) {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	start := -1
	end := len(lines)
	for i, l := range lines {
		switch {
		case start < 0 && strings.HasPrefix(l, "### "+id+":"):
			start = i
		case start >= 0 && (strings.HasPrefix(l, "### ") || strings.HasPrefix(l, "## ")):
			end = i
		}
		if end != len(lines) {
			break
		}
	}
	if start < 0 {
		return "", fmt.Errorf("the Markdown report has no section for %s", id)
	}
	fenced := false
	var out []string
	for _, l := range lines[start:end] {
		if strings.HasPrefix(l, "```") {
			fenced = !fenced
		}
		if !fenced && strings.HasPrefix(l, "#") {
			l = "#" + l
		}
		out = append(out, l)
	}
	return strings.TrimSpace(strings.Join(out, "\n")) + "\n", nil
}

// siteFinding renders the finding as the four steps the site opens with.
// Every sentence is a field of the finding; only the layout is added.
func siteFinding(f finding.Finding) string {
	e := html.EscapeString
	sev := strings.ToUpper(f.Severity.Label)
	if !f.Severity.Unscored {
		sev += fmt.Sprintf(" %.1f", f.Severity.Score)
	}
	observed, rest := f.Flaw.Description, ""
	if i := strings.Index(f.Flaw.Description, ". "); i >= 0 {
		observed, rest = f.Flaw.Description[:i], f.Flaw.Description[i+2:]
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w(`  <p class="kicker"><b>One finding, start to finish.</b> %s, from a scan of the bundled demo app.</p>`, e(f.ID))
	w(`  <ol class="chain">`)
	w(`    <li>`)
	w(`      <p class="verb">Find it.</p>`)
	w(`      <div class="ev">`)
	w(`        <p class="hd">%s <span class="sev">[%s]</span> %s</p>`, e(f.ID), e(sev), e(f.Title))
	w(`        <p>%s <span class="k">·</span> %s <span class="k">·</span> %s</p>`, e(f.Location.String()), e(strings.Join(f.CWE, ", ")), e(f.Severity.Vector))
	w(`      </div>`)
	w(`    </li>`)
	w(`    <li>`)
	w(`      <p class="verb">Prove it.</p>`)
	w(`      <div class="ev">`)
	w(`        <p>Confidence: <span class="conf">%s</span> <span class="k">·</span> %s</p>`, e(f.Confidence.Level), e(strings.Join(f.Proof.Artifacts, ", ")))
	w(`        <p>%s:</p>`, e(observed))
	w(`        <code class="out">%s</code>`, e(f.Proof.Result))
	w(`      </div>`)
	w(`    </li>`)
	w(`    <li>`)
	w(`      <p class="verb">Explain it.</p>`)
	w(`      <div class="ev">`)
	w(`        <p class="say">%s</p>`, e(rest))
	if len(f.Exploitation.ChainsInto) > 0 {
		w(`        <p>Chains into: %s.</p>`, e(lowerFirst(f.Exploitation.ChainsInto[0])))
	}
	w(`      </div>`)
	w(`    </li>`)
	w(`    <li>`)
	w(`      <p class="verb"><mark>Fix it.</mark></p>`)
	w(`      <div class="ev">`)
	w(`        <p class="say">%s</p>`, e(f.Remediation.Summary))
	w(`        <p>Verification: %s <span class="k">(this run had no model, so no patch was written)</span></p>`, e(f.Remediation.Verification))
	w(`      </div>`)
	w(`    </li>`)
	w(`  </ol>`)
	return b.String()
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// startDemo starts the demo application and waits until it answers. The
// returned function stops it.
func startDemo(ctx context.Context, python string) (stop func(), err error) {
	candidates := []string{python}
	if python == "" {
		candidates = []string{"python3", "python"}
	}
	var bin string
	for _, c := range candidates {
		if p, lerr := exec.LookPath(c); lerr == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, errors.New("-live needs Python to start the demo application, and none was found on PATH (pass -python)")
	}
	if listening(ctx) {
		return nil, fmt.Errorf("something already listens on %s: stop it first, so the scan talks to the demo application this tool starts", liveHost)
	}
	cmd := exec.CommandContext(ctx, bin, "app.py") //nolint:gosec // the repository's own demo application
	cmd.Dir = filepath.FromSlash(demoDir)
	// No bytecode cache: the run must leave nothing behind in the fixture.
	cmd.Env = append(os.Environ(), "PORT=8081", "PYTHONDONTWRITEBYTECODE=1")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the demo application: %w", err)
	}
	stop = func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if listening(ctx) {
			return stop, nil
		}
	}
	stop()
	return nil, fmt.Errorf("the demo application did not start listening on %s within 15 seconds", liveHost)
}

// listening reports whether something accepts connections on the demo
// application's address.
func listening(ctx context.Context) bool {
	d := net.Dialer{Timeout: 300 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp", liveHost)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
