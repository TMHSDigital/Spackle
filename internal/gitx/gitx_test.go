package gitx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newRepo creates a git repository with one commit and returns its path.
func newRepo(t *testing.T) string {
	t.Helper()
	if !Available() {
		t.Skip("git is not installed; skipping git plumbing tests")
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	writeFile(t, dir, "a.txt", "one\n")
	commit(t, dir, "first")
	return dir
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, msg string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", msg)
	return git(t, dir, "rev-parse", "HEAD")
}

func TestHeadSHAAndClean(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	sha, err := HeadSHA(ctx, dir)
	if err != nil || len(sha) != 40 {
		t.Fatalf("sha=%q err=%v", sha, err)
	}
	if clean, err := IsClean(ctx, dir); err != nil || !clean {
		t.Fatalf("clean=%v err=%v", clean, err)
	}
	writeFile(t, dir, "b.txt", "x\n")
	if clean, _ := IsClean(ctx, dir); clean {
		t.Fatal("an untracked file must make the tree dirty")
	}
}

func TestHeadSHAOutsideRepo(t *testing.T) {
	if !Available() {
		t.Skip("git is not installed")
	}
	// GIT_CEILING_DIRECTORIES stops git from finding a repository above
	// the temp dir on machines where the temp dir is inside one.
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	if _, err := HeadSHA(context.Background(), dir); !errors.Is(err, ErrNotRepo) {
		t.Fatalf("err = %v, want ErrNotRepo", err)
	}
}

func TestWorktreeLeavesWorkingTreeUntouched(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	writeFile(t, dir, "wip.txt", "uncommitted work\n")
	before, _ := Status(ctx, dir)

	wt := filepath.Join(t.TempDir(), "wt")
	if err := AddWorktree(ctx, dir, wt, "spackle/test-run"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, wt, "a.txt", "fixed\n")
	if err := CommitAll(ctx, wt, "fix: something"); err != nil {
		t.Fatal(err)
	}

	after, _ := Status(ctx, dir)
	if before != after {
		t.Fatalf("working tree changed:\nbefore %q\nafter  %q", before, after)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(got) != "one\n" {
		t.Fatalf("a.txt in the working tree was modified: %q", got)
	}
	if branch := git(t, dir, "rev-parse", "--abbrev-ref", "HEAD"); branch != "main" {
		t.Fatalf("operator's branch changed to %s", branch)
	}
}

func TestArchiveExportsACommitWithoutTouchingTheIndex(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	first, _ := HeadSHA(ctx, dir)
	writeFile(t, dir, "a.txt", "two\n")
	commit(t, dir, "second")
	writeFile(t, dir, "staged.txt", "staged\n")
	git(t, dir, "add", "staged.txt")
	before, _ := Status(ctx, dir)

	dest := t.TempDir()
	if err := Archive(ctx, dir, first, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "a.txt")); string(got) != "one\n" {
		t.Fatalf("exported a.txt = %q, want the first commit's content", got)
	}
	if after, _ := Status(ctx, dir); after != before {
		t.Fatalf("Archive changed the operator's index:\nbefore %q\nafter  %q", before, after)
	}
}

func TestRevListAndLog(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	first, _ := HeadSHA(ctx, dir)
	writeFile(t, dir, "a.txt", "two\n")
	second := commit(t, dir, "second")
	writeFile(t, dir, "a.txt", "three\n")
	third := commit(t, dir, "third")

	revs, err := RevList(ctx, dir, first, third)
	if err != nil || len(revs) != 2 || revs[0] != second || revs[1] != third {
		t.Fatalf("revs=%v err=%v", revs, err)
	}
	log, err := Log(ctx, dir, "a.txt", 2)
	if err != nil || !strings.Contains(log, "third") || !strings.Contains(log, "second") || strings.Contains(log, "first") {
		t.Fatalf("log=%q err=%v", log, err)
	}
}

func TestOptionInjectionIsRefused(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	if err := Clone(ctx, "--upload-pack=touch pwned", t.TempDir()); err == nil {
		t.Error("Clone accepted a remote that starts with a dash")
	}
	if _, err := Show(ctx, dir, "--output=pwned", ""); err == nil {
		t.Error("Show accepted a revision that starts with a dash")
	}
	if err := AddWorktree(ctx, dir, t.TempDir(), "-b"); err == nil {
		t.Error("AddWorktree accepted a branch that starts with a dash")
	}
}

func TestApplyPatch(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	patch := "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-one\n+patched\n"
	pf := filepath.Join(t.TempDir(), "fix.patch")
	if err := os.WriteFile(pf, []byte(patch), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyCheck(ctx, dir, pf); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, dir, pf); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); strings.TrimSpace(string(got)) != "patched" {
		t.Fatalf("a.txt = %q", got)
	}
	if err := ApplyCheck(ctx, dir, pf); err == nil {
		t.Fatal("a patch that no longer applies must fail the check")
	}
}

func TestDirtyAndResetWorktree(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	if dirty, err := Dirty(ctx, dir, "a.txt"); err != nil || dirty {
		t.Fatalf("a clean file is dirty=%v err=%v", dirty, err)
	}
	writeFile(t, dir, "a.txt", "edited")
	writeFile(t, dir, "sub/new.txt", "new")
	if dirty, err := Dirty(ctx, dir, "a.txt"); err != nil || !dirty {
		t.Fatalf("an edited file is dirty=%v err=%v", dirty, err)
	}
	if err := ResetWorktree(ctx, dir); err != nil {
		t.Fatal(err)
	}
	if clean, err := IsClean(ctx, dir); err != nil || !clean {
		t.Fatalf("after a reset: clean=%v err=%v", clean, err)
	}
}
