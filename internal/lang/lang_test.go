package lang

import (
	"strings"
	"testing"
)

// Every language in the table must be complete: a missing field shows up
// only at run time otherwise, as a refusal or a wrong claim in a report.
func TestEveryLanguageHasEveryEntry(t *testing.T) {
	if len(Names()) == 0 {
		t.Fatal("the table is empty")
	}
	seen := map[string]bool{}
	for _, name := range Names() {
		if seen[name] {
			t.Errorf("%s is listed twice", name)
		}
		seen[name] = true
		p, ok := Lookup(name)
		if !ok || p.Name != name || !Supported(name) {
			t.Fatalf("Lookup(%q) = %+v, %v", name, p, ok)
		}
		if p.Display == "" || !strings.Contains(DisplayList(), p.Display) {
			t.Errorf("%s has no display name in %q", name, DisplayList())
		}
		if p.DefaultImage == "" || DefaultImages()[name] != p.DefaultImage {
			t.Errorf("%s has no default image", name)
		}
		if len(p.Programs) == 0 {
			t.Errorf("%s has no program a proof may start", name)
		}
		cmd := p.SingleTest("", "TestAdd")
		if len(cmd) == 0 {
			t.Errorf("%s has no single-test command", name)
			continue
		}
		if !contains(p.Programs, cmd[0]) {
			t.Errorf("%s runs a test with %q, which is not one of its programs %v", name, cmd[0], p.Programs)
		}
		if check := p.CompileCheck([]string{"a"}); len(check) > 0 && !contains(p.Programs, check[0]) {
			t.Errorf("%s compile-checks with %q, which is not one of its programs %v", name, check[0], p.Programs)
		}
	}
	if len(DefaultImages()) != len(Names()) {
		t.Errorf("DefaultImages has %d entries for %d languages", len(DefaultImages()), len(Names()))
	}
}

func TestUnknownLanguage(t *testing.T) {
	for _, name := range []string{"", "ruby", "Go", "java"} {
		p, ok := Lookup(name)
		if ok || Supported(name) {
			t.Errorf("%q is not a supported language", name)
		}
		if p.CompileCheck([]string{"a.rb"}) != nil || p.SingleTest("", "x") != nil {
			t.Errorf("%q has commands although it is not supported", name)
		}
	}
}

func TestSingleTestCommands(t *testing.T) {
	for _, c := range []struct{ lang, testCmd, want string }{
		{"go", "go test ./...", "go test -count=1 -run ^TestAdd$ ./..."},
		{"python", "python -m pytest -q", "python -m pytest -q -k TestAdd"},
		{"python", "python -m unittest discover", "python -m unittest -k TestAdd"},
		{"python", "", "python -m unittest -k TestAdd"},
		{"javascript", "npm test", "node --test --test-name-pattern TestAdd"},
		{"typescript", "", "node --test --test-name-pattern TestAdd"},
	} {
		p, _ := Lookup(c.lang)
		if got := strings.Join(p.SingleTest(c.testCmd, "TestAdd"), " "); got != c.want {
			t.Errorf("%s with %q: %q, want %q", c.lang, c.testCmd, got, c.want)
		}
	}
}

func TestCompileCheckCommands(t *testing.T) {
	for _, c := range []struct {
		lang    string
		changed []string
		want    string
	}{
		{"python", []string{"a.py", "pkg/b.py"}, "python -m py_compile a.py pkg/b.py"},
		{"go", []string{"main.go"}, "go build ./..."},
		{"go", nil, "go build ./..."},
		{"javascript", []string{"index.js"}, "node --check index.js"},
		{"javascript", []string{"a.js", "b.js"}, ""},
		{"typescript", []string{"a.ts"}, ""},
	} {
		p, _ := Lookup(c.lang)
		if got := strings.Join(p.CompileCheck(c.changed), " "); got != c.want {
			t.Errorf("%s compile check of %v = %q, want %q", c.lang, c.changed, got, c.want)
		}
	}
}

func TestDisplayList(t *testing.T) {
	if got, want := DisplayList(), "Go, Python, JavaScript and TypeScript"; got != want {
		t.Errorf("DisplayList() = %q, want %q", got, want)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
