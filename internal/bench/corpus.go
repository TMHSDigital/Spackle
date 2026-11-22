// Package bench runs Spackle over the labelled corpus in bench/corpus and
// scores what it reports against each fixture's ground truth. The matching
// rule and the metrics are documented in bench/README.md; this package is
// the only producer of the files in bench/results.
package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Truth is one fixture's ground truth (bench/corpus/<fixture>/truth.json).
type Truth struct {
	Fixture         string `json:"fixture"`
	Language        string `json:"language"`
	Difficulty      string `json:"difficulty"`
	Clean           bool   `json:"clean"`
	Description     string `json:"description"`
	Vulnerabilities []Vuln `json:"vulnerabilities"`
}

// Vuln is one planted vulnerability.
type Vuln struct {
	Class string `json:"class"`
	CWE   string `json:"cwe"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Sink  string `json:"sink"`
	Note  string `json:"note"`
}

// markerFile is present in every fixture directory. Requiring it means the
// runner cannot be pointed at an arbitrary directory tree by mistake.
const markerFile = "SPACKLE_FIXTURE"

// LoadCorpus reads every fixture directory under dir (sorted by name). A
// directory without SPACKLE_FIXTURE, README.md or a parseable truth.json is an
// error naming the fixture.
func LoadCorpus(dir string) ([]Truth, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read benchmark corpus %s: %w. Pass --corpus with the directory that holds the fixtures (bench/corpus in the Spackle repository)", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := make([]Truth, 0, len(names))
	for _, name := range names {
		t, err := loadFixture(filepath.Join(dir, name), name)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func loadFixture(path, name string) (Truth, error) {
	for _, required := range []string{markerFile, "README.md"} {
		st, err := os.Stat(filepath.Join(path, required))
		if err != nil || st.IsDir() {
			return Truth{}, fmt.Errorf("fixture %s has no %s file: every fixture needs %s, README.md and truth.json (see bench/README.md)", name, required, markerFile)
		}
	}
	raw, err := os.ReadFile(filepath.Join(path, "truth.json")) //nolint:gosec // the path is built from the corpus directory the operator named
	if err != nil {
		return Truth{}, fmt.Errorf("fixture %s has no readable truth.json: %w. Add one that follows the schema in bench/README.md", name, err)
	}
	var t Truth
	if err := json.Unmarshal(raw, &t); err != nil {
		return Truth{}, fmt.Errorf("fixture %s has a truth.json that is not valid: %w. Fix it to follow the schema in bench/README.md", name, err)
	}
	// A truth file that disagrees with itself would silently skew every
	// metric, so it is refused instead of scored.
	switch {
	case t.Fixture != name:
		return Truth{}, fmt.Errorf("fixture %s: truth.json names fixture %q; the fixture field must equal the directory name", name, t.Fixture)
	case t.Clean && len(t.Vulnerabilities) > 0:
		return Truth{}, fmt.Errorf("fixture %s: truth.json is marked clean but lists %d vulnerabilities; a clean decoy must list none", name, len(t.Vulnerabilities))
	case !t.Clean && len(t.Vulnerabilities) == 0:
		return Truth{}, fmt.Errorf("fixture %s: truth.json is not marked clean but lists no vulnerabilities; list what is planted or set clean to true", name)
	}
	for i, v := range t.Vulnerabilities {
		if v.Class == "" || v.File == "" || v.Line < 1 {
			return Truth{}, fmt.Errorf("fixture %s: vulnerability %d in truth.json needs a class, a file and a 1-based line", name, i+1)
		}
	}
	return t, nil
}
