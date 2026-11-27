package gitx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"}, args...)
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

// The export is bind-mounted into a container whose user is neither the
// owner nor in the group, so it must be readable and traversable by others.
func TestArchiveExportIsWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	dir := newRepo(t)
	ctx := context.Background()
	writeFile(t, dir, "pkg/sub/b.txt", "b\n")
	writeFile(t, dir, "run.sh", "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(dir, "run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	head := commit(t, dir, "more")
	parent, err := os.MkdirTemp("", "spackle-export-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(parent) }()
	src, err := ExportDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := Archive(ctx, dir, head, src); err != nil {
		t.Fatal(err)
	}
	want := map[string]os.FileMode{".": 0o755, "pkg": 0o755, "pkg/sub": 0o755, "pkg/sub/b.txt": 0o644, "a.txt": 0o644, "run.sh": 0o755}
	for rel, mode := range want {
		st, err := os.Stat(filepath.Join(src, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != mode {
			t.Errorf("%s has mode %o, want %o", rel, got, mode)
		}
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

func TestChangedSince(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "keep.txt", "one\n")
	writeFile(t, dir, "gone.txt", "one\n")
	commit(t, dir, "base")
	git(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, dir, "a.txt", "two\n")
	writeFile(t, dir, "sub/new file.txt", "one\n")
	if err := os.Remove(filepath.Join(dir, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	commit(t, dir, "feature work")
	// The base branch moves on after the fork: that is not part of the change.
	git(t, dir, "checkout", "-q", "main")
	writeFile(t, dir, "keep.txt", "two\n")
	commit(t, dir, "main moves on")
	git(t, dir, "checkout", "-q", "feature")
	// Work that is not committed is not part of the change either.
	writeFile(t, dir, "keep.txt", "wip\n")

	ctx := context.Background()
	got, err := ChangedSince(ctx, dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "a.txt|sub/new file.txt" {
		t.Fatalf("changed = %q, want the added and the modified file", got)
	}
	// From a subdirectory the paths are relative to it and limited to it.
	got, err = ChangedSince(ctx, filepath.Join(dir, "sub"), "main")
	if err != nil || strings.Join(got, "|") != "new file.txt" {
		t.Fatalf("changed under sub = %q, err = %v", got, err)
	}
	if got, err = ChangedSince(ctx, dir, "HEAD"); err != nil || len(got) != 0 {
		t.Fatalf("against HEAD itself: %q, err = %v", got, err)
	}
	for _, rev := range []string{"", "-x", "--output=/tmp/x", "no-such-rev"} {
		if _, err := ChangedSince(ctx, dir, rev); err == nil {
			t.Errorf("revision %q was accepted", rev)
		}
	}
}

func TestChangedUncommitted(t *testing.T) {
	ctx := context.Background()
	dir := newRepo(t)
	writeFile(t, dir, "staged.txt", "one\n")
	writeFile(t, dir, "gone.txt", "one\n")
	writeFile(t, dir, "old name.txt", "one\n")
	writeFile(t, dir, ".gitignore", "*.log\n")
	commit(t, dir, "base")
	if got, err := ChangedUncommitted(ctx, dir); err != nil || len(got) != 0 {
		t.Fatalf("clean tree: %q, err = %v", got, err)
	}

	writeFile(t, dir, "a.txt", "two\n") // unstaged edit
	writeFile(t, dir, "staged.txt", "two\n")
	git(t, dir, "add", "staged.txt") // staged edit
	if err := os.Remove(filepath.Join(dir, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "sub/naïve.txt", "new\n") // untracked
	git(t, dir, "mv", "old name.txt", "sub/new name.txt")
	writeFile(t, dir, "debug.log", "ignored\n")
	writeFile(t, dir, ".spackle/runs/r1/ledger.jsonl", "{}\n")
	writeFile(t, dir, ".spackle/cache/map.json", "{}\n")

	sorted := func(files []string) string {
		s := append([]string(nil), files...)
		sort.Strings(s)
		return strings.Join(s, "|")
	}
	got, err := ChangedUncommitted(ctx, dir, ".spackle")
	if err != nil {
		t.Fatal(err)
	}
	if want := "a.txt|staged.txt|sub/naïve.txt|sub/new name.txt"; sorted(got) != want {
		t.Fatalf("changed = %q, want %q", sorted(got), want)
	}
	// Without the exclusion the state directory would count.
	if got, _ = ChangedUncommitted(ctx, dir); !strings.Contains(sorted(got), ".spackle/") {
		t.Fatalf("changed without exclusion = %q", got)
	}
	// From a subdirectory the paths are relative to it and limited to it.
	if got, err = ChangedUncommitted(ctx, filepath.Join(dir, "sub")); err != nil || sorted(got) != "naïve.txt|new name.txt" {
		t.Fatalf("changed under sub = %q, err = %v", got, err)
	}

	// Before the first commit, staged and untracked files are all changed.
	fresh := t.TempDir()
	git(t, fresh, "init", "-q", "-b", "main")
	writeFile(t, fresh, "main.go", "package main\n")
	writeFile(t, fresh, "notes.txt", "x\n")
	writeFile(t, fresh, ".spackle/summary.json", "{}\n")
	git(t, fresh, "add", "main.go")
	if got, err = ChangedUncommitted(ctx, fresh, ".spackle"); err != nil || sorted(got) != "main.go|notes.txt" {
		t.Fatalf("no commit yet: %q, err = %v", got, err)
	}

	outside := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(outside))
	if _, err := ChangedUncommitted(ctx, outside); !errors.Is(err, ErrNotRepo) {
		t.Fatalf("outside a repository: err = %v, want ErrNotRepo", err)
	}
}

// ChangedStaged lists what the next commit would add or change: staged
// edits and staged new files, not unstaged edits, untracked files or
// deletions. UnstagedFiles lists the edits that are not staged.
func TestChangedStaged(t *testing.T) {
	ctx := context.Background()
	dir := newRepo(t)
	writeFile(t, dir, "both.txt", "one\n")
	writeFile(t, dir, "gone.txt", "one\n")
	commit(t, dir, "base")
	if got, err := ChangedStaged(ctx, dir); err != nil || len(got) != 0 {
		t.Fatalf("clean tree: %q, err = %v", got, err)
	}

	writeFile(t, dir, "a.txt", "two\n") // unstaged edit only
	writeFile(t, dir, "both.txt", "two\n")
	git(t, dir, "add", "both.txt")
	writeFile(t, dir, "both.txt", "three\n") // staged, then edited again
	writeFile(t, dir, "new.txt", "new\n")
	git(t, dir, "add", "new.txt")           // staged new file
	writeFile(t, dir, "scratch.txt", "x\n") // untracked
	git(t, dir, "rm", "-q", "gone.txt")     // staged deletion
	writeFile(t, dir, ".spackle/runs/r1/ledger.jsonl", "{}\n")
	git(t, dir, "add", "-f", ".spackle")

	sorted := func(files []string) string {
		s := append([]string(nil), files...)
		sort.Strings(s)
		return strings.Join(s, "|")
	}
	got, err := ChangedStaged(ctx, dir, ".spackle")
	if err != nil || sorted(got) != "both.txt|new.txt" {
		t.Fatalf("staged = %q, err = %v", sorted(got), err)
	}
	if got, err = UnstagedFiles(ctx, dir, ".spackle"); err != nil || sorted(got) != "a.txt|both.txt" {
		t.Fatalf("unstaged = %q, err = %v", sorted(got), err)
	}
	lines, err := ChangedLinesStaged(ctx, dir, ".spackle")
	if err != nil || len(lines) != 2 || len(lines["new.txt"]) != 1 || lines["new.txt"][0] != (LineRange{1, 1}) {
		t.Fatalf("staged lines = %v, err = %v", lines, err)
	}

	// Before the first commit every staged file counts, and an untracked
	// one does not.
	fresh := t.TempDir()
	git(t, fresh, "init", "-q", "-b", "main")
	writeFile(t, fresh, "main.go", "package main\n")
	writeFile(t, fresh, "notes.txt", "x\n")
	git(t, fresh, "add", "main.go")
	if got, err = ChangedStaged(ctx, fresh); err != nil || sorted(got) != "main.go" {
		t.Fatalf("no commit yet: %q, err = %v", got, err)
	}
}
