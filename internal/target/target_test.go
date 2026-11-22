package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	dir := t.TempDir()
	hostLike := filepath.Join(dir, "example.com")
	if err := os.Mkdir(hostLike, 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		arg  string
		kind Kind
	}{
		{dir, KindPath},
		{hostLike, KindPath},
		{"https://github.com/TMHSDigital/Spackle", KindGit},
		{"https://github.com/TMHSDigital/Spackle.git", KindGit},
		{"https://git.example.test/team/app.git", KindGit},
		{"git@github.com:TMHSDigital/Spackle.git", KindGit},
		{"ssh://git@example.test/app.git", KindGit},
		{"http://localhost:8081", KindURL},
		{"https://staging.example.test/app", KindURL},
		{"https://github.com/TMHSDigital/Spackle/issues", KindURL},
		{"HTTP://127.0.0.1:8081/", KindURL},
	}
	for _, tc := range cases {
		got, err := Classify(tc.arg)
		if err != nil {
			t.Errorf("Classify(%q): %v", tc.arg, err)
			continue
		}
		if got.Kind != tc.kind {
			t.Errorf("Classify(%q) = %s, want %s", tc.arg, got.Kind, tc.kind)
		}
		if got.Live() != (tc.kind == KindURL) {
			t.Errorf("Classify(%q).Live() = %v", tc.arg, got.Live())
		}
	}
}

func TestClassifyEmptyIsCurrentDirectory(t *testing.T) {
	got, err := Classify("  ")
	if err != nil || got.Kind != KindPath || got.Raw != "." {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestClassifyRefusesToGuessBareHosts(t *testing.T) {
	for _, arg := range []string{"staging.example.test", "localhost:8081", "10.0.0.5"} {
		_, err := Classify(arg)
		if err == nil || !strings.Contains(err.Error(), "full URL") {
			t.Errorf("Classify(%q) = %v, want an error asking for a full URL", arg, err)
		}
	}
}

func TestClassifyErrors(t *testing.T) {
	for arg, want := range map[string]string{
		"./definitely/not/here": "does not exist",
		"ftp://example.test/x":  "not supported",
		"http://":               "not a valid URL",
	} {
		_, err := Classify(arg)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Classify(%q) = %v, want error containing %q", arg, err, want)
		}
	}
}

func TestDisplayStripsCredentials(t *testing.T) {
	got, err := Classify("https://user:hunter2@staging.example.test/app")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.Display, "hunter2") || strings.Contains(got.Display, "user") {
		t.Fatalf("Display leaks credentials: %s", got.Display)
	}
}
