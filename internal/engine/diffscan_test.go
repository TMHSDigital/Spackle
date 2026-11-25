package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// diffTarget makes the test target a git repository of its own with two
// commits: the base holds app.py and old.py, and the second commit changes
// app.py only. It returns the base commit.
func diffTarget(t *testing.T, root string) string {
	t.Helper()
	if !gitx.Available() {
		t.Skip("git is not installed; a diff scan needs it")
	}
	git := func(args ...string) string {
		t.Helper()
		return gitIn(t, root, args...)
	}
	old := "import os\n\ndef run(cmd):\n    os.system(cmd)\n"
	if err := os.WriteFile(filepath.Join(root, "old.py"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	git("init", "-q", "-b", "main")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	base := git("rev-parse", "HEAD")
	f, err := os.OpenFile(filepath.Join(root, "app.py"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n# changed\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	git("commit", "-q", "-m", "change app.py")
	return base
}

// gitIn runs git in dir with a fixed identity and no line ending
// conversion, and returns its trimmed output.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestSinceLimitsTheScanToChangedFiles(t *testing.T) {
	inOld := sqlLead()
	inOld.File, inOld.RuleID, inOld.Class, inOld.Title = "old.py", "py-os-system", "command-injection", "os.system with a variable"
	noFile := sqlLead()
	noFile.File, noFile.Line, noFile.RuleID = "", 0, "whole-project"
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), inOld, noFile}})
	o.Since = diffTarget(t, o.Target)

	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 || res.Run.Findings[0].Location.File != "app.py" {
		t.Fatalf("findings = %+v, want only the one in the changed file", res.Run.Findings)
	}
	want := "Diff scan against " + o.Since + ": 1 changed files. Only leads in those files are reported; 2 leads in other files were left out."
	if !containsNote(res.Run.Notes, want) {
		t.Fatalf("the report does not say it was a diff scan: %q", res.Run.Notes)
	}

	// The same limit applies to a dry run, which reports the plan only.
	o = opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), inOld}})
	o.Since, o.DryRun = diffTarget(t, o.Target), true
	res, err = Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Plan == nil || res.Plan.Leads != 1 || !containsNote(res.Plan.Notes, "Diff scan against") {
		t.Fatalf("plan = %+v", res.Plan)
	}

	// Without --since the same target reports both files.
	o = opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), inOld}})
	diffTarget(t, o.Target)
	if res, err = Run(context.Background(), o); err != nil || len(res.Run.Findings) != 2 {
		t.Fatalf("full scan: findings = %d, err = %v", len(res.Run.Findings), err)
	}
}

// --changed covers what a commit made now would add: an edited file (staged
// or not) and a new untracked file, and not the committed files.
func TestChangedLimitsTheScanToUncommittedFiles(t *testing.T) {
	inOld := sqlLead()
	inOld.File, inOld.RuleID, inOld.Class, inOld.Title = "old.py", "py-os-system", "command-injection", "os.system with a variable"
	inNew := sqlLead()
	inNew.File = "new.py"
	inIgnored := sqlLead()
	inIgnored.File = "build.py"
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), inOld, inNew, inIgnored}})
	diffTarget(t, o.Target)
	for name, body := range map[string]string{"new.py": "x = 1\n", "build.py": "y = 2\n", ".gitignore": "build.py\n"} {
		if err := os.WriteFile(filepath.Join(o.Target, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// app.py is edited and not committed; old.py is left as committed.
	if err := os.WriteFile(filepath.Join(o.Target, "app.py"), append(mustReadFile(t, filepath.Join(o.Target, "app.py")), []byte("# edited\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	o.Changed = true
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range res.Run.Findings {
		files = append(files, f.Location.File)
	}
	if strings.Join(files, ",") != "app.py,new.py" && strings.Join(files, ",") != "new.py,app.py" {
		t.Fatalf("findings in %v, want app.py and new.py only", files)
	}
	if !containsNote(res.Run.Notes, "Diff scan against the last commit (uncommitted changes)") {
		t.Fatalf("notes = %q", res.Run.Notes)
	}
	o.Since = "HEAD"
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) {
		t.Fatalf("--since with --changed: err = %v, want a refusal", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func containsNote(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

func TestSinceRefusals(t *testing.T) {
	// A revision git does not know: the usual cause is a shallow CI clone.
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	diffTarget(t, o.Target)
	o.Since = "no-such-branch"
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "fetch-depth") {
		t.Fatalf("unknown revision: err = %v", err)
	}
	// A revision that would be read as a git option.
	o.Since = "--output=x"
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("option-like revision: err = %v", err)
	}
	if entries, _ := os.ReadDir(RunsDir(o.Config.StateDir)); len(entries) != 0 {
		t.Fatal("a refused run left a run directory")
	}

	// A directory with no tracked files, also when it sits inside some
	// unrelated repository.
	o = opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	o.Since = "main"
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--since needs a git repository") {
		t.Fatalf("not a repository: err = %v", err)
	}

	// A git URL and a running target have no checkout to compare.
	for _, target := range []string{"https://example.test/owner/repo.git", "http://localhost:8081"} {
		o = opts(t)
		o.Target, o.Since = target, "main"
		if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--since") {
			t.Fatalf("%s: err = %v", target, err)
		}
	}
	// --changed on a git URL names --changed, not --since.
	o = opts(t)
	o.Target, o.Changed = "https://example.test/owner/repo.git", true
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "--changed lists the uncommitted work") || strings.Contains(err.Error(), "--since") {
		t.Fatalf("--changed on a git URL: err = %v", err)
	}
	// The report's label for --changed given as a revision is a revision,
	// not a request for a --changed scan.
	o = opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	diffTarget(t, o.Target)
	o.Since = diffBase(Options{Changed: true}).label
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "fetch-depth") {
		t.Fatalf("the --changed label as --since: err = %v", err)
	}
}

func TestChangedMapNarrowsWhatThePlannerSees(t *testing.T) {
	m := mapper.Map{
		FileCount:  3,
		Frameworks: []string{"flask"},
		Files:      []walk.File{{Rel: "app.py"}, {Rel: "old.py"}, {Rel: "Dockerfile"}},
		Entry:      []mapper.EntryPoint{{File: "app.py", Line: 3}, {File: "old.py", Line: 9}},
		Boundaries: []mapper.Boundary{{Kind: "process", File: "old.py", Line: 4}, {Kind: "database", File: "app.py", Line: 4}},
		InfraFiles: []string{"Dockerfile"},
	}
	got := changedMap(m, map[string]bool{"app.py": true})
	if len(got.Files) != 1 || got.Files[0].Rel != "app.py" || len(got.Entry) != 1 || got.Entry[0].File != "app.py" ||
		len(got.Boundaries) != 1 || got.Boundaries[0].File != "app.py" || len(got.InfraFiles) != 0 {
		t.Fatalf("narrowed map = %+v", got)
	}
	if got.FileCount != 3 || len(got.Frameworks) != 1 {
		t.Fatalf("facts about the whole target were lost: %+v", got)
	}
	if len(m.Files) != 3 || len(m.Entry) != 2 {
		t.Fatal("the full map was changed")
	}
}

// A seeder's lead count is taken after the leads were filtered, so the
// counts add up to the leads the scan reports.
func TestSeederLeadCountsMatchTheLeadsTheScanReports(t *testing.T) {
	inOld := sqlLead()
	inOld.File, inOld.RuleID, inOld.Class, inOld.Title = "old.py", "py-os-system", "command-injection", "os.system with a variable"
	seeders := func() []seed.Seeder {
		return []seed.Seeder{
			fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), inOld}},
			fakeSeeder{name: "other", leads: []seed.Lead{inOld}},
		}
	}
	total := func(statuses []seed.Status) int {
		n := 0
		for _, st := range statuses {
			n += st.Leads
		}
		return n
	}

	t.Run("diff scan, dry run", func(t *testing.T) {
		o := opts(t, seeders()...)
		o.Since, o.DryRun = diffTarget(t, o.Target), true
		res, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		p := res.Plan
		if p.Leads != 1 || total(p.Seeders) != p.Leads || p.Seeders[0].Leads != 1 || p.Seeders[1].Leads != 0 {
			t.Fatalf("leads = %d, seeders = %+v", p.Leads, p.Seeders)
		}
	})
	t.Run("diff scan, stored run", func(t *testing.T) {
		o := opts(t, seeders()...)
		o.Since = diffTarget(t, o.Target)
		res, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Run.Seeders; len(res.Run.Findings) != 1 || len(got) != 2 || got[0].Leads != 1 || got[1].Leads != 0 {
			t.Fatalf("findings = %d, seeders = %+v", len(res.Run.Findings), got)
		}
	})
	t.Run("excluded path and disabled rule", func(t *testing.T) {
		o := opts(t, seeders()...)
		o.DryRun = true
		o.Config.Scan.Exclude = []string{"old.py"}
		res, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if p := res.Plan; p.Leads != 1 || total(p.Seeders) != 1 {
			t.Fatalf("exclude: leads = %d, seeders = %+v", p.Leads, p.Seeders)
		}
		o = opts(t, seeders()...)
		o.DryRun = true
		o.Config.Scan.DisableRules = []string{"py-os-system"}
		if res, err = Run(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if p := res.Plan; p.Leads != 1 || total(p.Seeders) != 1 {
			t.Fatalf("disable_rules: leads = %d, seeders = %+v", p.Leads, p.Seeders)
		}
	})
}

// --changed works before the first commit: every staged or untracked file
// is uncommitted work.
func TestChangedBeforeTheFirstCommit(t *testing.T) {
	if !gitx.Available() {
		t.Skip("git is not installed; a diff scan needs it")
	}
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	o.Changed = true
	gitIn(t, o.Target, "init", "-q", "-b", "main")
	gitIn(t, o.Target, "add", "app.py")
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Run.Findings) != 1 || !containsNote(res.Run.Notes, ": 1 changed files.") {
		t.Fatalf("findings = %d, notes = %q", len(res.Run.Findings), res.Run.Notes)
	}
}

func TestStateDirUnder(t *testing.T) {
	root := t.TempDir()
	for _, c := range []struct {
		stateDir string
		want     string
	}{
		{filepath.Join(root, ".spackle"), ".spackle"},
		{filepath.Join(root, "sub", "state"), filepath.Join("sub", "state")},
		{root, ""},
		{filepath.Join(filepath.Dir(root), "elsewhere"), ""},
	} {
		got := strings.Join(stateDirUnder(root, c.stateDir), "")
		if got != c.want {
			t.Errorf("stateDirUnder(%q) = %q, want %q", c.stateDir, got, c.want)
		}
	}
}

// --diff-scope lines reports a lead in a changed file only when it is on a
// changed line. A lead with no line (a dependency in a lockfile, say) is
// about the whole file and stays. The note counts what was left out.
func TestDiffScopeLinesReportsOnlyTheChangedLines(t *testing.T) {
	// diffTarget's second commit appends lines 5 and 6 to app.py; the lead
	// of sqlLead is on line 4, which did not change.
	onChanged := sqlLead()
	onChanged.RuleID, onChanged.Line = "on-changed-line", 6
	wholeFile := sqlLead()
	wholeFile.RuleID, wholeFile.Line, wholeFile.Class, wholeFile.Title = "whole-file", 0, "vulnerable-dependency", "a dependency"
	inOld := sqlLead()
	inOld.File, inOld.RuleID, inOld.Class, inOld.Title = "old.py", "py-os-system", "command-injection", "os.system with a variable"
	leads := []seed.Lead{sqlLead(), onChanged, wholeFile, inOld}

	o := opts(t, fakeSeeder{name: "fake", leads: leads})
	o.Since, o.DiffScope = diffTarget(t, o.Target), DiffScopeLines
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Run.Findings {
		got = append(got, f.Location.String())
	}
	if len(got) != 2 || !slices.Contains(got, "app.py:6") || !slices.Contains(got, "app.py") {
		t.Fatalf("findings at %q, want app.py:6 and the whole-file lead", got)
	}
	if !containsNote(res.Run.Notes, "1 leads in other files were left out") || !containsNote(res.Run.Notes, diffLinesNote(1)) {
		t.Fatalf("notes = %q", res.Run.Notes)
	}
	if res.Run.DiffScope != DiffScopeLines {
		t.Fatalf("the run does not record its diff scope: %q", res.Run.DiffScope)
	}

	// The default scope, and "file", report every lead of the changed file.
	for _, scope := range []string{"", DiffScopeFile} {
		o = opts(t, fakeSeeder{name: "fake", leads: leads})
		o.Since, o.DiffScope = diffTarget(t, o.Target), scope
		if res, err = Run(context.Background(), o); err != nil || len(res.Run.Findings) != 3 || containsNote(res.Run.Notes, "changed lines") || res.Run.DiffScope != "" {
			t.Fatalf("scope %q: findings = %d, notes = %q, err = %v", scope, len(res.Run.Findings), res.Run.Notes, err)
		}
	}
}

// --diff-scope lines with --changed covers the edited lines of a tracked
// file and every line of an untracked one.
func TestDiffScopeLinesWithChanged(t *testing.T) {
	onEdit := sqlLead()
	onEdit.RuleID, onEdit.Line = "on-edit", 7
	inNew := sqlLead()
	inNew.File = "new.py"
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead(), onEdit, inNew}})
	diffTarget(t, o.Target)
	if err := os.WriteFile(filepath.Join(o.Target, "new.py"), []byte("1\n2\n3\n4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// app.py has 6 committed lines; line 7 is the uncommitted edit.
	if err := os.WriteFile(filepath.Join(o.Target, "app.py"), append(mustReadFile(t, filepath.Join(o.Target, "app.py")), []byte("# edited\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	o.Changed, o.DiffScope = true, DiffScopeLines
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Run.Findings {
		got = append(got, f.Location.String())
	}
	if len(got) != 2 || !slices.Contains(got, "app.py:7") || !slices.Contains(got, "new.py:4") {
		t.Fatalf("findings at %q, want app.py:7 and new.py:4", got)
	}
	if !containsNote(res.Run.Notes, diffLinesNote(1)) {
		t.Fatalf("notes = %q", res.Run.Notes)
	}
}

func TestDiffScopeRefusals(t *testing.T) {
	o := opts(t, fakeSeeder{name: "fake", leads: []seed.Lead{sqlLead()}})
	o.DiffScope = DiffScopeLines
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "give --since or --changed") {
		t.Fatalf("lines without a diff scan: err = %v", err)
	}
	o.Since, o.DiffScope = "main", "hunks"
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), `not "hunks"`) {
		t.Fatalf("unknown scope: err = %v", err)
	}
	if entries, _ := os.ReadDir(RunsDir(o.Config.StateDir)); len(entries) != 0 {
		t.Fatal("a refused run left a run directory")
	}
}
