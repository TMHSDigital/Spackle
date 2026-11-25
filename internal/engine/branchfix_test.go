package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/gitx"
)

// fixRepo makes a git repository with a.py and b.py committed, and a lab
// over it whose fixes branchFixes will commit.
func fixRepo(t *testing.T, fixes ...acceptedFix) (*lab, string) {
	t.Helper()
	if !gitx.Available() {
		t.Skip("git is not installed; the fix branch needs it")
	}
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// pkg is a tracked directory: a fix that names it as a file cannot be
	// written, which is how the tests below make a write fail.
	for name, content := range map[string]string{"a.py": "x = 0\n", "b.py": "y = 0\n", filepath.Join("pkg", "c.py"): "z = 0\n"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, root, "init", "-q", "-b", "main")
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "commit", "-q", "-m", "base")
	// The worktree commits with the machine's identity; give it one.
	gitIn(t, root, "config", "user.name", "t")
	gitIn(t, root, "config", "user.email", "t@example.test")
	gitIn(t, root, "config", "commit.gpgsign", "false")
	gitIn(t, root, "config", "core.autocrlf", "false")
	cfg := config.Default()
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	return &lab{r: &runner{runID: "20261125-000000-aaaaaa", cfg: cfg}, root: root, fixes: fixes}, root
}

// Two fixes to one file conflict: the first is committed and the second is
// named as skipped. A fix to another file gets its own commit.
func TestBranchFixesSkipsASecondFixToTheSameFile(t *testing.T) {
	l, root := fixRepo(t,
		acceptedFix{id: "SPK-00000001", title: "first", files: map[string]string{"a.py": "x = 1\n"}},
		acceptedFix{id: "SPK-00000002", title: "second", files: map[string]string{"a.py": "x = 2\n"}},
		acceptedFix{id: "SPK-00000003", title: "third", files: map[string]string{"b.py": "y = 1\n"}},
	)
	branch, note := l.branchFixes(context.Background())
	if branch != "spackle/20261125-000000-aaaaaa" {
		t.Fatalf("branch = %q, note = %q", branch, note)
	}
	if !strings.Contains(note, "2 fix(es) committed") || !strings.Contains(note, "SPK-00000002 also changes a.py, which the fix for SPK-00000001 already changed") {
		t.Fatalf("note = %q", note)
	}
	if got := gitIn(t, root, "show", branch+":a.py"); got != "x = 1" {
		t.Fatalf("a.py on the branch = %q, want the first fix", got)
	}
	if got := gitIn(t, root, "rev-list", "--count", "main.."+branch); got != "2" {
		t.Fatalf("commits on the branch = %s, want 2", got)
	}
	if !l.branched["SPK-00000001"] || l.branched["SPK-00000002"] || !l.branched["SPK-00000003"] || l.worktree == "" {
		t.Fatalf("branched = %v, worktree = %q", l.branched, l.worktree)
	}
	// The operator's working tree is untouched.
	if b, _ := os.ReadFile(filepath.Join(root, "a.py")); string(b) != "x = 0\n" {
		t.Fatalf("the working tree changed: a.py = %q", b)
	}
}

// When every fix is skipped there is no branch and no worktree.
func TestBranchFixesWithEveryFixSkipped(t *testing.T) {
	l, root := fixRepo(t, acceptedFix{id: "SPK-00000001", title: "first", files: map[string]string{"a.py": "x = 1\n"}})
	if err := os.WriteFile(filepath.Join(root, "a.py"), []byte("x = 'local edit'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	branch, note := l.branchFixes(context.Background())
	if branch != "" || l.worktree != "" || !strings.Contains(note, "No fix branch was created") || !strings.Contains(note, "uncommitted changes") {
		t.Fatalf("branch = %q, worktree = %q, note = %q", branch, l.worktree, note)
	}
	if out := gitIn(t, root, "branch", "--list", "spackle/*"); out != "" {
		t.Fatalf("a branch was created: %q", out)
	}
}

// A fix whose file cannot be written in the worktree is skipped with the
// reason, and the next fix still gets its commit.
func TestBranchFixesSkipsAFixThatCannotBeWritten(t *testing.T) {
	l, root := fixRepo(t,
		acceptedFix{id: "SPK-00000001", title: "first", files: map[string]string{"pkg": "not a directory\n"}},
		acceptedFix{id: "SPK-00000002", title: "second", files: map[string]string{"b.py": "y = 1\n"}},
	)
	branch, note := l.branchFixes(context.Background())
	if branch != "spackle/20261125-000000-aaaaaa" {
		t.Fatalf("branch = %q, note = %q", branch, note)
	}
	if !strings.Contains(note, "1 fix(es) committed") || !strings.Contains(note, "SPK-00000001 could not be written to the fix branch") {
		t.Fatalf("note = %q", note)
	}
	if got := gitIn(t, root, "show", branch+":b.py"); got != "y = 1" {
		t.Fatalf("b.py on the branch = %q, want the second fix", got)
	}
	if got := gitIn(t, root, "rev-list", "--count", "main.."+branch); got != "1" {
		t.Fatalf("commits on the branch = %s, want 1", got)
	}
	if l.branched["SPK-00000001"] || !l.branched["SPK-00000002"] {
		t.Fatalf("branched = %v", l.branched)
	}
}

// A fix that cannot be committed (here: it changes nothing) is skipped and
// undone: the files it wrote no longer count as changed, so a later fix to
// the same file is committed instead of being called a conflict.
func TestBranchFixesUndoesAFixThatCannotBeCommitted(t *testing.T) {
	l, root := fixRepo(t,
		acceptedFix{id: "SPK-00000001", title: "first", files: map[string]string{"a.py": "x = 0\n"}},
		acceptedFix{id: "SPK-00000002", title: "second", files: map[string]string{"a.py": "x = 2\n"}},
	)
	branch, note := l.branchFixes(context.Background())
	if branch != "spackle/20261125-000000-aaaaaa" {
		t.Fatalf("branch = %q, note = %q", branch, note)
	}
	if !strings.Contains(note, "1 fix(es) committed") || !strings.Contains(note, "SPK-00000001 could not be committed") || strings.Contains(note, "also changes") {
		t.Fatalf("note = %q", note)
	}
	if got := gitIn(t, root, "show", branch+":a.py"); got != "x = 2" {
		t.Fatalf("a.py on the branch = %q, want the second fix", got)
	}
	if l.branched["SPK-00000001"] || !l.branched["SPK-00000002"] {
		t.Fatalf("branched = %v", l.branched)
	}
}

// When the worktree was made but no fix could be committed to it, no
// branch is returned and the lab holds no worktree to open a PR from.
func TestBranchFixesWithNoFixCommitted(t *testing.T) {
	l, _ := fixRepo(t, acceptedFix{id: "SPK-00000001", title: "first", files: map[string]string{"pkg": "not a directory\n"}})
	branch, note := l.branchFixes(context.Background())
	if branch != "" || l.worktree != "" || len(l.branched) != 0 {
		t.Fatalf("branch = %q, worktree = %q, branched = %v", branch, l.worktree, l.branched)
	}
	if !strings.Contains(note, "0 fix(es) committed") || !strings.Contains(note, "SPK-00000001 could not be written to the fix branch") {
		t.Fatalf("note = %q", note)
	}
}
