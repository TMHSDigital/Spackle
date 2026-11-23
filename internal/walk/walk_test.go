package walk

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rels(res Result) string {
	var out []string
	for _, f := range res.Files {
		out = append(out, f.Rel)
	}
	return strings.Join(out, ",")
}

func TestListSkipsDependencyDirsBinariesAndHugeFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "my app") // a space in the path is deliberate
	write(t, root, "main.go", "package main\n")
	write(t, root, "src/app.py", "print(1)\n")
	write(t, root, "node_modules/x/index.js", "x")
	write(t, root, ".git/config", "x")
	write(t, root, "vendor/v.go", "package v\n")
	write(t, root, "bin/tool", "ELF\x00\x01\x02")
	write(t, root, "big.txt", strings.Repeat("a", MaxFileSize+1))

	res, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := rels(res); got != "main.go,src/app.py" {
		t.Fatalf("files = %s", got)
	}
	// The pruned directories are reported; version control data is not.
	var skipped []string
	for _, s := range res.Skipped {
		skipped = append(skipped, s.Rel)
	}
	if got := strings.Join(skipped, ","); got != "big.txt,node_modules,vendor" {
		t.Fatalf("skipped = %+v", res.Skipped)
	}
	if !strings.Contains(res.Skipped[0].Reason, "larger than") || res.Skipped[1].Reason != SkippedDirReason {
		t.Fatalf("skipped = %+v", res.Skipped)
	}
	if res.Files[0].Lang != "go" || res.Files[1].Lang != "python" {
		t.Fatalf("langs = %+v", res.Files)
	}
}

func TestListRefusesSymlinkOutOfRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "target")
	write(t, root, "ok.py", "x = 1\n")
	write(t, base, "outside/secret.txt", "top secret\n")
	if err := os.Symlink(filepath.Join(base, "outside", "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("cannot create symlinks here (%v); on Windows this needs Developer Mode", err)
	}
	if err := os.Symlink(filepath.Join(root, "ok.py"), filepath.Join(root, "inner.py")); err != nil {
		t.Fatal(err)
	}
	res, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := rels(res); got != "inner.py,ok.py" {
		t.Fatalf("files = %s", got)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "outside the target") {
		t.Fatalf("skipped = %+v", res.Skipped)
	}
}

func TestListErrors(t *testing.T) {
	if _, err := List(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing target must be an error")
	}
	dir := t.TempDir()
	write(t, dir, "f.go", "package f\n")
	if _, err := List(filepath.Join(dir, "f.go")); err == nil || !strings.Contains(err.Error(), "is a file") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveConfinesPaths(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "target")
	write(t, root, "a/b.go", "package a\n")
	write(t, base, "outside.txt", "no\n")

	if p, err := Resolve(root, "a/b.go"); err != nil || !strings.HasSuffix(filepath.ToSlash(p), "target/a/b.go") {
		t.Fatalf("p=%s err=%v", p, err)
	}
	if _, err := Resolve(root, `a\b.go`); err != nil {
		t.Fatalf("backslash-separated relative paths should resolve: %v", err)
	}
	bad := []string{"", "../outside.txt", "a/../../outside.txt", "/etc/passwd", `\Windows\system.ini`, "nope.go"}
	if runtime.GOOS == "windows" {
		bad = append(bad, `C:\Windows\win.ini`, `C:outside.txt`)
	}
	for _, in := range bad {
		if p, err := Resolve(root, in); err == nil {
			t.Errorf("Resolve(%q) = %s, want an error", in, p)
		}
	}
}

func TestResolveRefusesSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "target")
	write(t, root, "ok.txt", "ok\n")
	write(t, base, "outside/secret.txt", "s\n")
	if err := os.Symlink(filepath.Join(base, "outside"), filepath.Join(root, "esc")); err != nil {
		t.Skipf("cannot create symlinks here (%v)", err)
	}
	if _, err := Resolve(root, "esc/secret.txt"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("got %v", err)
	}
}

func TestReadTextNormalizesCRLFAndBOM(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "w.py", "\xEF\xBB\xBFa = 1\r\nb = 2\r\n")
	got, err := ReadText(filepath.Join(dir, "w.py"))
	if err != nil || got != "a = 1\nb = 2\n" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestLangOf(t *testing.T) {
	cases := map[string]string{
		"Dockerfile": "dockerfile", "docker/Dockerfile.prod": "dockerfile", "api.dockerfile": "dockerfile",
		".env": "dotenv", ".env.production": "dotenv", "a/b/main.tf": "terraform",
		"x.TSX": "typescript", "k8s/deploy.yaml": "yaml", "README": "",
	}
	for in, want := range cases {
		if got := LangOf(in); got != want {
			t.Errorf("LangOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListWithExcludesAndIncludes(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"main.go", "bench/corpus/a/app.py", "build/gen.go", "src/build/x.go",
		"web/app.min.js", "web/app.js", "pkg/testdata/fixture.go", "vendor/lib/lib.go",
	} {
		write(t, root, rel, "x")
	}
	res, err := ListWith(root, Options{
		Exclude: []string{"bench/corpus/**", "*.min.js", "**/testdata/**"},
		Include: []string{"build"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rels(res), "build/gen.go,main.go,src/build/x.go,web/app.js"; got != want {
		t.Errorf("files = %s, want %s", got, want)
	}
	var skipped []string
	for _, s := range res.Skipped {
		if s.Reason != "excluded by configuration" {
			continue
		}
		skipped = append(skipped, s.Rel)
	}
	if got, want := strings.Join(skipped, ","), "bench/corpus,pkg/testdata,web/app.min.js"; got != want {
		t.Errorf("skipped = %s, want %s", got, want)
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, rel string
		want         bool
	}{
		{"bench/corpus/**", "bench/corpus/a/b.py", true},
		{"bench/corpus/**", "bench/corpus", true},
		{"bench/corpus/**", "bench/corpusx/a.py", false},
		{"bench/corpus", "bench/corpus/a/b.py", true},
		{"**/gen/*.go", "a/b/gen/x.go", true},
		{"**/gen/*.go", "gen/x.go", true},
		{"*.pb.go", "api/v1/svc.pb.go", true},
		{"docs", "src/docs/a.md", true},
		{"src/*.go", "src/sub/a.go", false},
		{"./examples/", "examples/demo/app.py", true},
	}
	for _, c := range cases {
		if got := Match([]string{c.pattern}, c.rel); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.rel, got, c.want)
		}
	}
	for _, bad := range []string{"", "../x", "/abs", "a" + string(rune(92)) + "b", "[z"} {
		if CheckPattern(bad) == nil {
			t.Errorf("CheckPattern(%q) accepted a bad pattern", bad)
		}
	}
}

func TestOutputDirectoriesArePrunedOnlyWhereTheyAreOutput(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"build/out.js",                           // at the root: pruned
		"internal/target/target.go",              // a first-party package named target
		"app/build/handler.py",                   // nested, no marker: read
		"web/package.json", "web/dist/bundle.js", // nested beside a manifest: pruned
		"svc/go.mod", "svc/vendor/lib/lib.go", // nested beside go.mod: pruned
		"rust/target/CACHEDIR.TAG", "rust/target/debug/x.rs", // marker inside: pruned
		"pkg/node_modules/dep/index.js", // always pruned
	} {
		write(t, root, rel, "x")
	}
	res, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rels(res), "app/build/handler.py,internal/target/target.go,svc/go.mod,web/package.json"; got != want {
		t.Errorf("files = %s, want %s", got, want)
	}
	var pruned []string
	for _, s := range res.Skipped {
		if s.Reason == SkippedDirReason {
			pruned = append(pruned, s.Rel)
		}
	}
	if got, want := strings.Join(pruned, ","), "build,pkg/node_modules,rust/target,svc/vendor,web/dist"; got != want {
		t.Errorf("pruned = %s, want %s", got, want)
	}
}
