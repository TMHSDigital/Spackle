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
	if len(res.Skipped) != 1 || res.Skipped[0].Rel != "big.txt" || !strings.Contains(res.Skipped[0].Reason, "larger than") {
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
