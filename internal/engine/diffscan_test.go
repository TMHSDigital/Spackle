package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
