package mapper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/version"
	"github.com/TMHSDigital/spackle/internal/walk"
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

func pyApp(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "my app") // space in the path on purpose
	// CRLF on purpose: line numbers must not shift on Windows checkouts.
	write(t, root, "app.py", strings.ReplaceAll(`from flask import Flask, request
import sqlite3, subprocess, os

app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q")
    return db.execute("SELECT * FROM t WHERE a = '" + q + "'")

@app.post("/run")
def run():
    return subprocess.run(request.form["cmd"], shell=True)

if __name__ == "__main__":
    app.run()
`, "\n", "\r\n"))
	write(t, root, "tests/test_app.py", "import unittest\n")
	write(t, root, "requirements.txt", "flask==3.0\npytest\n")
	write(t, root, "Dockerfile", "FROM python:3.12\n")
	write(t, root, ".github/workflows/ci.yml", "on: push\n")
	write(t, root, "static/site.js", "console.log(1)\n")
	return root
}

func TestBuildMapsAPythonApp(t *testing.T) {
	m, err := Build(context.Background(), pyApp(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.LanguageNames(); len(got) == 0 || got[0] != "python" {
		t.Fatalf("languages = %v", got)
	}
	if strings.Join(m.Frameworks, ",") != "flask" {
		t.Fatalf("frameworks = %v", m.Frameworks)
	}
	want := map[string]int{"/search": 6, "/run": 11}
	found := 0
	for _, e := range m.Entry {
		if line, ok := want[e.Detail]; ok {
			found++
			if e.Kind != "http-route" || e.Line != line || e.File != "app.py" {
				t.Errorf("entry %+v, want http-route at app.py:%d", e, line)
			}
		}
	}
	if found != 2 {
		t.Fatalf("entry points = %+v", m.Entry)
	}
	kinds := map[string]bool{}
	for _, b := range m.Boundaries {
		kinds[b.Kind] = true
	}
	for _, k := range []string{"http-input", "database", "process"} {
		if !kinds[k] {
			t.Errorf("missing %s boundary in %+v", k, m.Boundaries)
		}
	}
	if !m.Tests.HasTests || m.Tests.TestCommand != "python -m pytest -q" || m.Tests.Language != "python" {
		t.Fatalf("harness = %+v", m.Tests)
	}
	if strings.Join(m.InfraFiles, ",") != ".github/workflows/ci.yml,Dockerfile" {
		t.Fatalf("infra = %v", m.InfraFiles)
	}
}

func TestBuildMapsGoAndNode(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/x\n\ngo 1.22\n")
	write(t, root, "main.go", `package main

import "net/http"

func main() {
	http.HandleFunc("/health", health)
	http.ListenAndServe("127.0.0.1:0", nil)
}

func health(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("x")
}
`)
	write(t, root, "main_test.go", "package main\n")
	write(t, root, "web/server.js", "const express = require('express')\nconst app = express()\napp.get('/users/:id', (req, res) => res.send(req.params.id))\n")
	write(t, root, "web/package.json", `{"scripts":{"test":"node --test"}}`)

	m, err := Build(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Tests.Language != "go" || m.Tests.TestCommand != "go test ./..." || !m.Tests.HasTests {
		t.Fatalf("harness = %+v", m.Tests)
	}
	fw := strings.Join(m.Frameworks, ",")
	if !strings.Contains(fw, "net/http") || !strings.Contains(fw, "express") {
		t.Fatalf("frameworks = %s", fw)
	}
	var routes []string
	for _, e := range m.Entry {
		if e.Kind == "http-route" {
			routes = append(routes, e.Detail)
		}
	}
	if strings.Join(routes, ",") != "/health,/users/:id" {
		t.Fatalf("routes = %v", routes)
	}
}

// The mapper hands over the text of every file it read, as ReadText gives
// it, so the seeders do not read those files again. Files it did not read
// are not handed over, and the map is the same with or without the handoff.
func TestBuildHandsOverTheTextsItRead(t *testing.T) {
	root := pyApp(t)
	texts := walk.NewTexts()
	with, err := Build(context.Background(), root, Options{Texts: texts})
	if err != nil {
		t.Fatal(err)
	}
	without, err := Build(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(with, without) {
		t.Fatalf("the handoff changed the map:\n%+v\n%+v", with, without)
	}
	abs := func(rel string) string {
		for _, f := range with.Files {
			if f.Rel == rel {
				return f.Abs
			}
		}
		t.Fatalf("%s is not in the listing", rel)
		return ""
	}
	for _, rel := range []string{"app.py", "requirements.txt", "static/site.js"} {
		text, ok := texts.Get(abs(rel))
		if !ok {
			t.Errorf("%s was read by the mapper but not handed over", rel)
		}
		if strings.Contains(text, "\r") {
			t.Errorf("%s was handed over without line ending normalization", rel)
		}
	}
	// Neither infrastructure nor test code is read by the mapper: a test
	// file's path is all it needs.
	for _, rel := range []string{"Dockerfile", "tests/test_app.py"} {
		if _, ok := texts.Get(abs(rel)); ok {
			t.Errorf("%s is not read by the mapper, so there is nothing to hand over", rel)
		}
	}
	if !with.Tests.HasTests {
		t.Error("the test file was not noticed")
	}
}

// A cache entry written by another build of Spackle is not used: that
// build may have listed or read the target differently.
func TestCacheEntryOfAnotherBuildIsNotUsed(t *testing.T) {
	dir := t.TempDir()
	const commit = "0123456789abcdef0123456789abcdef01234567"
	if err := saveCache(dir, commit, Map{Commit: commit, FileCount: 7}, map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	if c, ok := loadCache(dir, commit); !ok || c.Map.FileCount != 7 {
		t.Fatalf("the entry this build wrote was not found: %+v, %v", c.Map, ok)
	}
	old := version.Version
	version.Version = "v9.9.9"
	t.Cleanup(func() { version.Version = old })
	if _, ok := loadCache(dir, commit); ok {
		t.Fatal("an entry written by another build was used")
	}
	// The new build writes its own entry over the old one.
	if err := saveCache(dir, commit, Map{Commit: commit, FileCount: 8}, map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	if c, ok := loadCache(dir, commit); !ok || c.Map.FileCount != 8 {
		t.Fatalf("entry after the rewrite: %+v, %v", c.Map, ok)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d cache files, want one per commit", len(entries))
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	root := pyApp(t)
	a, err := Build(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Build(context.Background(), root, Options{})
	if len(a.Entry) != len(b.Entry) || len(a.Boundaries) != len(b.Boundaries) {
		t.Fatal("two builds of the same tree differ")
	}
	for i := range a.Entry {
		if a.Entry[i] != b.Entry[i] {
			t.Fatalf("entry %d differs: %+v vs %+v", i, a.Entry[i], b.Entry[i])
		}
	}
}

func TestBuildMissingTarget(t *testing.T) {
	if _, err := Build(context.Background(), filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
		t.Fatal("want an error for a missing target")
	}
}

func TestCacheIsKeyedByCleanCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; the map cache needs a commit hash")
	}
	root := pyApp(t)
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)
		cmd := exec.Command("git", full...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	// This test is about the cache key, not line endings. pyApp writes a
	// CRLF file, and a machine-wide core.autocrlf can make git report such
	// a file as modified right after committing it. Use LF here.
	appPath := filepath.Join(root, "app.py")
	raw, err := os.ReadFile(appPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(appPath, []byte(strings.ReplaceAll(string(raw), "\r\n", "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	git("init", "-q", "-b", "main")
	git("config", "core.autocrlf", "false")
	git("add", "-A")
	git("commit", "-q", "-m", "init")

	cache := t.TempDir()
	first, err := Build(context.Background(), root, Options{CacheDir: cache})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Commit) != 40 {
		t.Fatalf("commit = %q, want a full hash for a clean tree", first.Commit)
	}
	entries, _ := os.ReadDir(cache)
	if len(entries) != 1 || !strings.Contains(entries[0].Name(), first.Commit) {
		t.Fatalf("cache dir = %v", entries)
	}
	second, err := Build(context.Background(), root, Options{CacheDir: cache})
	if err != nil || len(second.Entry) != len(first.Entry) || len(second.Files) == 0 {
		t.Fatalf("cached build: entries %d vs %d, files %d, err %v", len(second.Entry), len(first.Entry), len(second.Files), err)
	}

	// The default state directory sits untracked inside the target. The
	// walk never reads it, so it must not make the tree count as changed:
	// the second scan has to find the entry the first one wrote there.
	inTarget := filepath.Join(root, ".spackle", "cache")
	for i := 1; i <= 2; i++ {
		m, err := Build(context.Background(), root, Options{CacheDir: inTarget})
		if err != nil {
			t.Fatal(err)
		}
		if m.Commit != first.Commit {
			t.Fatalf("build %d with the cache inside the target: commit = %q, want %s (the tree is clean apart from .spackle)", i, m.Commit, first.Commit)
		}
	}
	if entries, _ := os.ReadDir(inTarget); len(entries) != 1 {
		t.Fatalf("cache inside the target = %v, want one entry", entries)
	}

	// A dirty tree must not use or write the cache: the commit no longer
	// describes what is on disk.
	write(t, root, "new.py", "@app.route('/new')\ndef n(): pass\n")
	dirty, err := Build(context.Background(), root, Options{CacheDir: cache})
	if err != nil {
		t.Fatal(err)
	}
	if dirty.Commit != "" || len(dirty.Entry) != len(first.Entry)+1 {
		t.Fatalf("dirty build: commit=%q entries=%d (clean had %d)", dirty.Commit, len(dirty.Entry), len(first.Entry))
	}
}

// One map cache file is written per scanned commit. Only the newest
// maxCacheEntries are kept, and never the one just written.
func TestMapCacheIsPruned(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-time.Hour)
	for i := 0; i < 2*maxCacheEntries; i++ {
		p := cachePath(dir, fmt.Sprintf("%040x", i+1))
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Older files have older times: file 1 is the oldest.
		if err := os.Chtimes(p, old.Add(time.Duration(i)*time.Second), old.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	commit := fmt.Sprintf("%040x", 0xabc)
	if err := saveCache(dir, commit, Map{Commit: commit}, map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	maps, _ := filepath.Glob(filepath.Join(dir, "map-*.json"))
	if len(maps) != maxCacheEntries {
		t.Fatalf("%d map cache files remain, want %d", len(maps), maxCacheEntries)
	}
	if _, err := os.Stat(cachePath(dir, commit)); err != nil {
		t.Fatalf("the entry just written was pruned: %v", err)
	}
	newest := cachePath(dir, fmt.Sprintf("%040x", 2*maxCacheEntries))
	if _, err := os.Stat(newest); err != nil {
		t.Errorf("the newest older entry was pruned: %v", err)
	}
	if _, err := os.Stat(cachePath(dir, fmt.Sprintf("%040x", 1))); err == nil {
		t.Error("the oldest entry was kept")
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("a file that is not a map cache entry was removed: %v", err)
	}
}

// A --changed scan of a dirty tree reads only the changed files when the
// map of HEAD is cached, and gets the same map as a full build.
func TestChangedBuildUsesTheCacheOfHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; the map cache needs a commit hash")
	}
	root := pyApp(t)
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(root))
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"}, args...)
		cmd := exec.Command("git", full...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write(t, root, "lib.py", "from fastapi import FastAPI\nimport os\n\ndef env():\n    return os.environ['X']\n")
	write(t, root, "helpers.py", "import subprocess\n\ndef run(c):\n    return subprocess.run(c)\n")
	git("init", "-q", "-b", "main")
	git("config", "core.autocrlf", "false")
	git("add", "-A")
	git("commit", "-q", "-m", "init")
	cache := t.TempDir()
	if _, err := Build(context.Background(), root, Options{CacheDir: cache}); err != nil {
		t.Fatal(err)
	}

	// Modify, add and delete. lib.py was the only file importing fastapi,
	// so the framework has to go with it.
	write(t, root, "app.py", "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/other')\ndef other():\n    return open('x').read()\n")
	write(t, root, "new.py", "import django\n\n@app.route('/new')\ndef n(): pass\n")
	if err := os.Remove(filepath.Join(root, "lib.py")); err != nil {
		t.Fatal(err)
	}
	changed := map[string]bool{"app.py": true, "new.py": true}

	texts := walk.NewTexts()
	got, err := Build(context.Background(), root, Options{CacheDir: cache, Changed: changed, Texts: texts})
	if err != nil {
		t.Fatal(err)
	}
	want, err := Build(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got.Files, want.Files = nil, nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("map from the cache differs from a full build:\n got %+v\nwant %+v", got, want)
	}
	for _, f := range want.Frameworks {
		if f == "fastapi" {
			t.Fatal("the full build still reports the framework of the deleted file")
		}
	}
	readFiles := map[string]bool{}
	m, _ := Build(context.Background(), root, Options{})
	for _, f := range m.Files {
		if _, ok := texts.Get(f.Abs); ok {
			readFiles[f.Rel] = true
		}
	}
	if !readFiles["app.py"] || !readFiles["new.py"] || readFiles["helpers.py"] || readFiles["tests/test_app.py"] {
		t.Fatalf("files read = %v, want the changed files and not the others", readFiles)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 1 {
		t.Fatalf("cache dir = %v, want no entry written for a dirty tree", entries)
	}
}

// A language the mapper has no patterns for is counted but not read, and
// its test files still show that the project has tests.
func TestBuildDoesNotReadLanguagesWithoutPatterns(t *testing.T) {
	root := filepath.Join(t.TempDir(), "java app")
	write(t, root, "src/main/java/App.java", "class App { public static void main(String[] a) {} }\n")
	write(t, root, "src/test/java/AppTest.java", "class AppTest {}\n")
	texts := walk.NewTexts()
	m, err := Build(context.Background(), root, Options{Texts: texts})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range m.Files {
		if _, ok := texts.Get(f.Abs); ok {
			t.Errorf("%s was read", f.Rel)
		}
	}
	if len(m.Languages) != 1 || m.Languages[0].Lang != "java" || m.Languages[0].Files != 2 || !m.Tests.HasTests {
		t.Fatalf("map = %+v", m)
	}
}
