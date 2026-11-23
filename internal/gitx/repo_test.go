package gitx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fileURL turns a local path into a file:// URL. git only honors --depth
// over a real transport, and a plain path is copied as a local clone.
func fileURL(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a drive letter path on Windows
	}
	return "file://" + p
}

// newBare creates an empty bare repository and returns its path.
func newBare(t *testing.T) string {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "origin.git")
	git(t, filepath.Dir(bare), "init", "-q", "--bare", "-b", "main", bare)
	return bare
}

func TestCloneIsShallowAndLeavesSubmodulesOut(t *testing.T) {
	src := newRepo(t)
	ctx := context.Background()

	// A second repository is added as a submodule of the first.
	sub := t.TempDir()
	git(t, sub, "init", "-q", "-b", "main")
	writeFile(t, sub, "inner.txt", "inner\n")
	commit(t, sub, "inner")
	git(t, src, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "--", fileURL(sub), "vendor/dep")
	commit(t, src, "add a submodule")
	writeFile(t, src, "a.txt", "three\n")
	head := commit(t, src, "third")
	if n := git(t, src, "rev-list", "--count", "HEAD"); n != "3" {
		t.Fatalf("the source has %s commits, want 3", n)
	}

	bare := newBare(t)
	git(t, src, "push", "-q", bare, "main")

	dest := filepath.Join(t.TempDir(), "clone")
	if err := Clone(ctx, fileURL(bare), dest); err != nil {
		t.Fatal(err)
	}
	if got := git(t, dest, "rev-parse", "HEAD"); got != head {
		t.Fatalf("clone HEAD = %s, want %s", got, head)
	}
	if n := git(t, dest, "rev-list", "--count", "HEAD"); n != "1" {
		t.Fatalf("the clone has %s commits, want a shallow clone with 1", n)
	}
	if got := git(t, dest, "rev-parse", "--is-shallow-repository"); got != "true" {
		t.Fatalf("is-shallow-repository = %s, want true", got)
	}
	// Clone checks out with the machine's own git configuration, so with
	// core.autocrlf on (the default on Windows runners) the file has CRLF.
	cloned, rerr := os.ReadFile(filepath.Join(dest, "a.txt"))
	if rerr != nil || strings.ReplaceAll(string(cloned), "\r\n", "\n") != "three\n" {
		t.Fatalf("cloned a.txt = %q, %v", cloned, rerr)
	}
	if _, err := os.Stat(filepath.Join(dest, ".gitmodules")); err != nil {
		t.Fatalf("the clone has no .gitmodules, the submodule check proves nothing: %v", err)
	}
	// The submodule path is at most an empty directory: its code was not
	// fetched.
	if _, err := os.Stat(filepath.Join(dest, "vendor", "dep", "inner.txt")); err == nil {
		t.Fatal("the submodule was checked out")
	}
	if entries, err := os.ReadDir(filepath.Join(dest, "vendor", "dep")); err == nil && len(entries) != 0 {
		t.Fatalf("the submodule directory holds %d entries, want none", len(entries))
	}
	if entries, err := os.ReadDir(filepath.Join(dest, ".git", "modules")); err == nil && len(entries) != 0 {
		t.Fatalf(".git/modules holds %d entries, want none", len(entries))
	}
}

func TestCloneOfAMissingRepositoryExplainsWhatToCheck(t *testing.T) {
	if !Available() {
		t.Skip("git is not installed")
	}
	parent := t.TempDir()
	remote := filepath.Join(parent, "missing.git")
	dest := filepath.Join(parent, "clone")
	err := Clone(context.Background(), remote, dest)
	if err == nil {
		t.Fatal("Clone of a path that does not exist returned no error")
	}
	for _, want := range []string{"clone " + remote + ": ", "Check the URL and your access, or clone it yourself and pass the directory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
	if strings.ContainsAny(err.Error(), "\r\n") {
		t.Errorf("err = %q, want one line", err)
	}
	if _, serr := os.Stat(filepath.Join(dest, ".git")); serr == nil {
		t.Error("a failed clone left a repository behind")
	}
}

func TestTracked(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	writeFile(t, dir, "pkg/b.txt", "b\n")
	commit(t, dir, "second")
	writeFile(t, dir, "untracked.txt", "u\n")

	if !Tracked(ctx, dir, "a.txt") {
		t.Error("a committed file is reported as not tracked")
	}
	if !Tracked(ctx, dir, "a.txt", "pkg/b.txt") {
		t.Error("two committed files are reported as not tracked")
	}
	if !Tracked(ctx, filepath.Join(dir, "pkg"), "b.txt") {
		t.Error("a committed file named relative to a subdirectory is reported as not tracked")
	}
	if Tracked(ctx, dir, "untracked.txt") {
		t.Error("an untracked file is reported as tracked")
	}
	if Tracked(ctx, dir, "a.txt", "untracked.txt") {
		t.Error("one untracked path among tracked ones must make the answer false")
	}
	if Tracked(ctx, dir, "does-not-exist.txt") {
		t.Error("a path that does not exist is reported as tracked")
	}
	if Tracked(ctx, dir) {
		t.Error("no paths must give false")
	}
	// A path that looks like an option is a path: it comes after "--".
	if Tracked(ctx, dir, "--others") {
		t.Error("a path that looks like an option is reported as tracked")
	}
}

// A directory can sit inside a repository it is not part of, which is the
// case on a machine whose home directory is a repository.
func TestTrackedAndHasTrackedInsideAnUnrelatedRepository(t *testing.T) {
	outer := newRepo(t)
	ctx := context.Background()
	writeFile(t, outer, "scratch/target/main.go", "package main\n")
	nested := filepath.Join(outer, "scratch", "target")

	if top, err := TopLevel(ctx, nested); err != nil || !sameDir(t, top, outer) {
		t.Fatalf("TopLevel(nested) = %q, %v; the directory must be inside the outer repository for this test", top, err)
	}
	if Tracked(ctx, nested, "main.go") {
		t.Error("a file in a directory nested in an unrelated repository is reported as tracked")
	}
	if HasTracked(ctx, nested) {
		t.Error("a directory nested in an unrelated repository is reported as holding tracked files")
	}
	if !HasTracked(ctx, outer) {
		t.Error("the repository itself is reported as holding no tracked files")
	}
	// Once the file is committed the same questions answer yes.
	commit(t, outer, "adopt the directory")
	if !Tracked(ctx, nested, "main.go") || !HasTracked(ctx, nested) {
		t.Error("a committed file is reported as not tracked")
	}
}

func TestHasTrackedOutsideARepository(t *testing.T) {
	if !Available() {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	writeFile(t, dir, "a.txt", "a\n")
	ctx := context.Background()
	if HasTracked(ctx, dir) {
		t.Error("a plain directory is reported as holding tracked files")
	}
	if Tracked(ctx, dir, "a.txt") {
		t.Error("a file in a plain directory is reported as tracked")
	}
}

// sameDir compares two spellings of a directory. git prints long names with
// forward slashes on Windows and resolves symlinks on macOS, so the strings
// differ while the directory is the same.
func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	sa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(sa, sb)
}

func TestPrefixAndTopLevel(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	writeFile(t, dir, "sub/dir/c.txt", "c\n")

	cases := []struct {
		dir  string
		want string
	}{
		{dir, ""},
		{filepath.Join(dir, "sub"), "sub"},
		{filepath.Join(dir, "sub", "dir"), "sub/dir"},
	}
	for _, c := range cases {
		got, err := Prefix(ctx, c.dir)
		if err != nil || got != c.want {
			t.Errorf("Prefix(%s) = %q, %v; want %q", c.dir, got, err, c.want)
		}
		top, err := TopLevel(ctx, c.dir)
		if err != nil {
			t.Errorf("TopLevel(%s): %v", c.dir, err)
			continue
		}
		if !sameDir(t, top, dir) {
			t.Errorf("TopLevel(%s) = %q, want the repository root %q", c.dir, top, dir)
		}
		if runtime.GOOS != "windows" && !filepath.IsAbs(top) {
			t.Errorf("TopLevel(%s) = %q, want an absolute path", c.dir, top)
		}
	}
}

func TestTopLevelAndPrefixOutsideARepository(t *testing.T) {
	if !Available() {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	ctx := context.Background()
	if top, err := TopLevel(ctx, dir); !errors.Is(err, ErrNotRepo) || top != "" {
		t.Errorf("TopLevel = %q, %v; want ErrNotRepo", top, err)
	}
	if prefix, err := Prefix(ctx, dir); !errors.Is(err, ErrNotRepo) || prefix != "" {
		t.Errorf("Prefix = %q, %v; want ErrNotRepo", prefix, err)
	}
}

// A named branch or tag is cloned instead of the default branch, and a ref
// that could be read as an option is refused.
func TestCloneRef(t *testing.T) {
	src := newRepo(t)
	ctx := context.Background()
	mainHead := git(t, src, "rev-parse", "HEAD")
	git(t, src, "checkout", "-q", "-b", "release")
	writeFile(t, src, "a.txt", "release\n")
	releaseHead := commit(t, src, "on release")
	git(t, src, "tag", "v1.0.0")
	bare := newBare(t)
	git(t, src, "push", "-q", bare, "main", "release", "v1.0.0")

	for ref, want := range map[string]string{"": mainHead, "release": releaseHead, "v1.0.0": releaseHead} {
		dest := filepath.Join(t.TempDir(), "clone")
		if err := CloneRef(ctx, fileURL(bare), dest, ref); err != nil {
			t.Fatalf("ref %q: %v", ref, err)
		}
		if got := git(t, dest, "rev-parse", "HEAD"); got != want {
			t.Errorf("ref %q: HEAD = %s, want %s", ref, got, want)
		}
	}
	for _, bad := range []string{"--upload-pack=x", "a b"} {
		if err := CloneRef(ctx, fileURL(bare), filepath.Join(t.TempDir(), "c"), bad); err == nil || !strings.Contains(err.Error(), "refusing git ref") {
			t.Errorf("ref %q: err = %v", bad, err)
		}
	}
	if err := CloneRef(ctx, fileURL(bare), filepath.Join(t.TempDir(), "c"), "no-such-branch"); err == nil || !strings.Contains(err.Error(), "branch or tag exists") {
		t.Errorf("a missing ref: err = %v", err)
	}
}
