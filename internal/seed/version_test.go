package seed

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The version output of each scanner, as the pinned releases print it,
// gives the bare version number. Nothing but digits and dots comes out.
func TestParseVersion(t *testing.T) {
	for out, want := range map[string]string{
		"1.187.0\n": "1.187.0",
		"v8.30.1\n": "8.30.1",
		"8.30.1":    "8.30.1",
		"osv-scanner version: 2.7.1\ncommit: n/a\nbuilt at: n/a\n": "2.7.1",
		"Version: 0.76.2\nVulnerability DB:\n  Version: 2\n":       "0.76.2",
		"Haskell Dockerfile Linter 2.15.1\n":                       "2.15.1",
		"no version here\n":                                        "",
		"1.2\n":                                                    "",
		"\x1b[31m 9.9.9-evil<script>\n":                            "9.9.9",
	} {
		if got := parseVersion(out); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", out, got, want)
		}
	}
}

// TestedVersions is the one Go table of tested scanner versions. It names
// every external scanner and equals the pins the scanners workflow
// installs, so the warning in spackle doctor tracks what CI tests.
func TestTestedVersionsMatchTheScannersWorkflow(t *testing.T) {
	var names []string
	for _, s := range External() {
		names = append(names, s.Name())
		if TestedVersions[s.Name()] == "" {
			t.Errorf("TestedVersions has no version for %s", s.Name())
		}
	}
	if len(TestedVersions) != len(names) {
		t.Errorf("TestedVersions names %d scanners, External has %d (%v)", len(TestedVersions), len(names), names)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "scanners.yml"))
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([A-Z_]+)_VERSION:\s*([0-9.]+)\s*$`).FindAllStringSubmatch(string(raw), -1) {
		pins[strings.ReplaceAll(strings.ToLower(m[1]), "_", "-")] = m[2]
	}
	var keys []string
	for k := range pins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(pins) != len(TestedVersions) {
		t.Fatalf("scanners.yml pins %v, TestedVersions has %v", keys, TestedVersions)
	}
	for name, v := range pins {
		if TestedVersions[name] != v {
			t.Errorf("%s: scanners.yml pins %s, TestedVersions says %q", name, v, TestedVersions[name])
		}
	}
}

// An adapter runs its tool's version command, and a run's seeder status
// carries the version.
func TestExternalVersionIsRecordedInTheStatus(t *testing.T) {
	stub := stubScanner(t, "stub-scanner version 3.4.5\n", "", 0)
	if got := stub.Version(context.Background()); got != "" {
		t.Fatalf("an adapter without a version command reported %q", got)
	}
	stub.versionArgs = []string{"--version"}
	if got := stub.Version(context.Background()); got != "3.4.5" {
		t.Fatalf("Version = %q, want 3.4.5", got)
	}
	// The stub prints the same text for the scan, and "[]" is needed for
	// the report: a scan run that fails to parse still records the version.
	_, statuses := RunAll(context.Background(), []Seeder{stub}, t.TempDir(), nil, nil)
	if len(statuses) != 1 || statuses[0].Version != "3.4.5" {
		t.Fatalf("statuses = %+v", statuses)
	}
}
