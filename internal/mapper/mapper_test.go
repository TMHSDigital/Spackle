package mapper

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
