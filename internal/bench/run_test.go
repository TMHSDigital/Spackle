package bench

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/report"
)

const realCorpus = "../../bench/corpus"

// writeFixture creates a fixture directory with the given truth.json text.
func writeFixture(t *testing.T, corpus, name, truth string) {
	t.Helper()
	dir := filepath.Join(corpus, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		markerFile:   "Intentionally vulnerable test data for Spackle. Do not deploy.\n",
		"README.md":  "# " + name + "\n",
		"truth.json": truth,
		"app.py":     strings.Repeat("x = 1\n", 60),
	}
	for f, body := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func truthJSON(name, lang, difficulty string, vulns ...string) string {
	return fmt.Sprintf(`{"fixture":%q,"language":%q,"difficulty":%q,"clean":%t,"description":"d","vulnerabilities":[%s]}`,
		name, lang, difficulty, len(vulns) == 0, strings.Join(vulns, ","))
}

func vulnJSON(class string, line int) string {
	return fmt.Sprintf(`{"class":%q,"cwe":"CWE-1","file":"app.py","line":%d,"sink":"s","note":"n"}`, class, line)
}

// tempCorpus has two vulnerable fixtures and one decoy, in name order
// a-vuln, b-clean, c-vuln.
func tempCorpus(t *testing.T) string {
	t.Helper()
	corpus := t.TempDir()
	writeFixture(t, corpus, "a-vuln", truthJSON("a-vuln", "python", "easy", vulnJSON("sql-injection", 10), vulnJSON("xss", 30)))
	writeFixture(t, corpus, "b-clean", truthJSON("b-clean", "python", "easy"))
	writeFixture(t, corpus, "c-vuln", truthJSON("c-vuln", "go", "hard", vulnJSON("ssrf", 5)))
	return corpus
}

func TestLoadCorpusReal(t *testing.T) {
	corpus, err := LoadCorpus(realCorpus)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus) < 25 {
		t.Fatalf("corpus has %d fixtures, want at least 25", len(corpus))
	}
	for i, tr := range corpus {
		if i > 0 && corpus[i-1].Fixture >= tr.Fixture {
			t.Errorf("fixtures are not sorted by name: %s before %s", corpus[i-1].Fixture, tr.Fixture)
		}
		if tr.Clean && len(tr.Vulnerabilities) != 0 {
			t.Errorf("%s: clean fixture lists vulnerabilities", tr.Fixture)
		}
		if !tr.Clean && len(tr.Vulnerabilities) == 0 {
			t.Errorf("%s: vulnerable fixture lists nothing", tr.Fixture)
		}
		for _, v := range tr.Vulnerabilities {
			if _, ok := finding.DefaultVector(v.Class); !ok {
				t.Errorf("%s: class %q has no default vector in package finding", tr.Fixture, v.Class)
			}
			path := filepath.Join(realCorpus, tr.Fixture, filepath.FromSlash(v.File))
			n, err := countLines(path)
			if err != nil {
				t.Errorf("%s: truth file %s: %v", tr.Fixture, v.File, err)
				continue
			}
			if v.Line < 1 || v.Line > n {
				t.Errorf("%s: %s has %d lines, truth names line %d", tr.Fixture, v.File, n, v.Line)
			}
		}
	}
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
	}
	return n, sc.Err()
}

func TestLoadCorpusErrors(t *testing.T) {
	good := truthJSON("fx", "go", "easy")
	cases := []struct {
		name   string
		damage func(dir string) error
		want   string
	}{
		{"missing marker", func(d string) error { return os.Remove(filepath.Join(d, markerFile)) }, markerFile},
		{"missing readme", func(d string) error { return os.Remove(filepath.Join(d, "README.md")) }, "README.md"},
		{"missing truth", func(d string) error { return os.Remove(filepath.Join(d, "truth.json")) }, "truth.json"},
		{"bad json", func(d string) error { return os.WriteFile(filepath.Join(d, "truth.json"), []byte("{not json"), 0o600) }, "truth.json"},
		{"wrong name", func(d string) error {
			return os.WriteFile(filepath.Join(d, "truth.json"), []byte(truthJSON("other", "go", "easy")), 0o600)
		}, "directory name"},
		{"clean with entries", func(d string) error {
			body := strings.Replace(truthJSON("fx", "go", "easy", vulnJSON("xss", 1)), `"clean":false`, `"clean":true`, 1)
			return os.WriteFile(filepath.Join(d, "truth.json"), []byte(body), 0o600)
		}, "clean"},
		{"vulnerable without entries", func(d string) error {
			body := strings.Replace(good, `"clean":true`, `"clean":false`, 1)
			return os.WriteFile(filepath.Join(d, "truth.json"), []byte(body), 0o600)
		}, "lists no vulnerabilities"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			corpus := t.TempDir()
			writeFixture(t, corpus, "fx", good)
			if err := tc.damage(filepath.Join(corpus, "fx")); err != nil {
				t.Fatal(err)
			}
			_, err := LoadCorpus(corpus)
			if err == nil || !strings.Contains(err.Error(), "fx") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error naming the fixture and %q, got %v", tc.want, err)
			}
		})
	}
	if _, err := LoadCorpus(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing corpus directory must be an error")
	}
}

func found(class string, line int) finding.Finding {
	loc := finding.Location{File: "app.py", StartLine: line}
	return finding.Finding{ID: finding.MakeID(class, loc), Class: class, Location: loc, Status: finding.StatusOpen}
}

// canned returns a Scan that answers per fixture and records what it was asked.
func canned(answers map[string]engine.Result, fail map[string]error, seen *[]engine.Options) func(context.Context, engine.Options) (engine.Result, error) {
	return func(_ context.Context, o engine.Options) (engine.Result, error) {
		*seen = append(*seen, o)
		name := filepath.Base(o.Target)
		if err := fail[name]; err != nil {
			return engine.Result{}, err
		}
		return answers[name], nil
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 11, 22, 23, 30, 0, 0, time.FixedZone("west", -8*3600))
}

func TestRunAggregates(t *testing.T) {
	corpus := tempCorpus(t)
	fixed := found("xss", 31)
	fixed.Status = finding.StatusFixed
	fixed.Remediation.Verification = "verified"
	answers := map[string]engine.Result{
		"a-vuln": {Run: report.Run{
			Findings: []finding.Finding{found("sql-injection", 10), fixed, found("weak-hash", 50)},
			Usage:    report.Usage{CostUSD: 0.30, CostKnown: true, InputTokens: 1000, OutputTokens: 100},
		}},
		"b-clean": {Run: report.Run{
			Findings: []finding.Finding{found("xss", 3)},
			Usage:    report.Usage{CostUSD: 0.10, CostKnown: true, InputTokens: 500, OutputTokens: 50, Estimated: true},
		}},
		"c-vuln": {Run: report.Run{Usage: report.Usage{CostUSD: 0.20, CostKnown: true}}},
	}
	cfg := config.Default()
	cfg.Model = config.Model{Provider: config.ProviderOllama, Model: "test-model"}
	cfg.StateDir = "operator-state"
	var seen []engine.Options
	var progress bytes.Buffer
	res, err := Run(context.Background(), Options{
		CorpusDir: corpus, Config: cfg, Version: "v9", Now: fixedNow, Progress: &progress,
		Scan: canned(answers, nil, &seen),
	})
	if err != nil {
		t.Fatal(err)
	}
	// 23:30 at UTC-8 is already the next day in UTC.
	if res.Schema != Schema || res.Date != "2026-11-23" || res.Version != "v9" {
		t.Fatalf("header = %q %q %q", res.Schema, res.Date, res.Version)
	}
	if res.Mode != ModeAgentic || res.Provider != "ollama" || res.Model != "test-model" {
		t.Fatalf("mode/provider/model = %q/%q/%q", res.Mode, res.Provider, res.Model)
	}
	c := res.Corpus
	if c.Fixtures != 3 || c.Clean != 1 || c.Vulnerable != 2 || c.TruthEntries != 3 || c.ByLanguage["python"] != 2 || c.ByLanguage["go"] != 1 {
		t.Fatalf("corpus = %+v", c)
	}
	tot := res.Totals
	if tot.TruePositives != 2 || tot.FalsePositives != 2 || tot.FalseNegatives != 1 {
		t.Fatalf("totals = %+v", tot)
	}
	if tot.Precision != 0.5 || tot.Recall != 0.6667 || tot.VerifiedFixes != 1 || tot.VerifiedFixRate != 0.5 {
		t.Fatalf("rates = %+v", tot)
	}
	if tot.CostUSD != 0.6 || !tot.CostKnown || tot.CostPerFinding != 0.3 || tot.InputTokens != 1500 || !tot.TokensEstimated {
		t.Fatalf("cost = %+v", tot)
	}
	if tot.DecoysFlagged != 1 || tot.CleanFixtures != 1 {
		t.Fatalf("decoys = %+v", tot)
	}
	if res.ByLanguage["go"].FalseNegatives != 1 || res.ByLanguage["python"].TruePositives != 2 || res.ByDifficulty["hard"].Recall != 0 || res.ByDifficulty["easy"].Recall != 1 {
		t.Fatalf("splits = %+v / %+v", res.ByLanguage, res.ByDifficulty)
	}
	if len(res.Fixtures) != 3 || res.Fixtures[0].Fixture != "a-vuln" || res.Fixtures[2].Fixture != "c-vuln" || len(res.Notes) != 0 {
		t.Fatalf("fixtures = %+v notes = %v", res.Fixtures, res.Notes)
	}

	if len(seen) != 3 {
		t.Fatalf("scanned %d fixtures", len(seen))
	}
	states := map[string]bool{}
	for i, o := range seen {
		if o.Confirm != nil {
			t.Error("Confirm must be nil: the bench command has already asked")
		}
		if o.Config.StateDir == "operator-state" || !filepath.IsAbs(o.Config.StateDir) {
			t.Errorf("fixture %d used state dir %q, want a temporary one", i, o.Config.StateDir)
		}
		states[o.Config.StateDir] = true
		if _, err := os.Stat(o.Config.StateDir); err == nil {
			t.Errorf("state dir %s was not removed", o.Config.StateDir)
		}
	}
	// Each fixture gets what is left of the benchmark's spend cap.
	for i, want := range []float64{5, 4.7, 4.6} {
		if got := seen[i].Config.Budget.USD; got < want-1e-9 || got > want+1e-9 {
			t.Errorf("fixture %d budget = %v, want %v", i, got, want)
		}
	}
	if n := strings.Count(progress.String(), "\n"); n != 3 || !strings.Contains(progress.String(), "[2/3] b-clean") {
		t.Fatalf("progress:\n%s", progress.String())
	}
}

func TestRunStopsAtSpendCap(t *testing.T) {
	corpus := tempCorpus(t)
	answers := map[string]engine.Result{
		"a-vuln":  {Run: report.Run{Findings: []finding.Finding{found("xss", 30)}, Usage: report.Usage{CostUSD: 0.6, CostKnown: true}}},
		"b-clean": {Run: report.Run{Usage: report.Usage{CostUSD: 0.5, CostKnown: true}}},
		"c-vuln":  {Run: report.Run{Findings: []finding.Finding{found("ssrf", 5)}}},
	}
	cfg := config.Default()
	cfg.Model = config.Model{Provider: config.ProviderOllama, Model: "m"}
	cfg.Budget.USD = 1
	var seen []engine.Options
	res, err := Run(context.Background(), Options{CorpusDir: corpus, Config: cfg, Scan: canned(answers, nil, &seen)})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || len(res.Fixtures) != 2 {
		t.Fatalf("scanned %d, scored %d; the third fixture must not run", len(seen), len(res.Fixtures))
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "2 of 3") || !strings.Contains(res.Notes[0], "$1.00") {
		t.Fatalf("notes = %v", res.Notes)
	}
	if res.Corpus.Fixtures != 3 || res.Totals.TruePositives != 1 || res.Totals.CostUSD != 1.1 {
		t.Fatalf("corpus %+v totals %+v", res.Corpus, res.Totals)
	}
	if got := seen[1].Config.Budget.USD; got < 0.4-1e-9 || got > 0.4+1e-9 {
		t.Fatalf("second fixture budget = %v, want 0.4", got)
	}
}

func TestRunRecordsFailingFixture(t *testing.T) {
	corpus := tempCorpus(t)
	answers := map[string]engine.Result{
		"b-clean": {Run: report.Run{Usage: report.Usage{CostKnown: true}}},
		"c-vuln":  {Run: report.Run{Findings: []finding.Finding{found("ssrf", 5)}, Usage: report.Usage{CostKnown: true}}},
	}
	var seen []engine.Options
	// No model: a refusal is specific to the fixture, so the run continues.
	fail := map[string]error{"a-vuln": fmt.Errorf("%w: mapper could not read the target", engine.ErrRefused)}
	res, err := Run(context.Background(), Options{CorpusDir: corpus, Config: config.Default(), Scan: canned(answers, fail, &seen)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fixtures) != 3 || len(seen) != 3 {
		t.Fatalf("scored %d, scanned %d", len(res.Fixtures), len(seen))
	}
	bad := res.Fixtures[0]
	if !strings.Contains(bad.Error, "mapper could not read") || bad.FalseNegatives != 2 || bad.TruePositives != 0 {
		t.Fatalf("failed fixture = %+v", bad)
	}
	if res.Mode != ModeDeterministic || res.Model != "none" || res.Provider != "" || !res.Totals.CostKnown {
		t.Fatalf("mode %q model %q provider %q", res.Mode, res.Model, res.Provider)
	}
	// The failed fixture keeps its own record, but it is left out of the
	// totals and counted as failed there.
	if res.Totals.TruePositives != 1 || res.Totals.FalseNegatives != 0 || res.Totals.FailedFixtures != 1 {
		t.Fatalf("totals = %+v", res.Totals)
	}
}

func TestRunFailureWithModelMakesCostUnknown(t *testing.T) {
	corpus := tempCorpus(t)
	cfg := config.Default()
	cfg.Model = config.Model{Provider: config.ProviderOllama, Model: "m"}
	var seen []engine.Options
	fail := map[string]error{"b-clean": errors.New("provider returned 500")}
	res, err := Run(context.Background(), Options{CorpusDir: corpus, Config: cfg, Scan: canned(map[string]engine.Result{
		"a-vuln": {Run: report.Run{Usage: report.Usage{CostKnown: true}}},
		"c-vuln": {Run: report.Run{Usage: report.Usage{CostKnown: true}}},
	}, fail, &seen)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fixtures) != 3 || res.Totals.CostKnown || len(res.Notes) != 1 {
		t.Fatalf("fixtures %d, cost known %v, notes %v", len(res.Fixtures), res.Totals.CostKnown, res.Notes)
	}
}

func TestRunStopsWhenRefusedWithModel(t *testing.T) {
	corpus := tempCorpus(t)
	cfg := config.Default()
	cfg.Model = config.Model{Provider: config.ProviderAnthropic, Model: "m"}
	var seen []engine.Options
	fail := map[string]error{"a-vuln": fmt.Errorf("%w: no API key", engine.ErrRefused)}
	res, err := Run(context.Background(), Options{CorpusDir: corpus, Config: cfg, Scan: canned(nil, fail, &seen)})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || len(res.Fixtures) != 0 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "no API key") {
		t.Fatalf("scanned %d, fixtures %d, notes %v", len(seen), len(res.Fixtures), res.Notes)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	corpus := tempCorpus(t)
	ctx, cancel := context.WithCancel(context.Background())
	var seen []engine.Options
	scan := func(c context.Context, o engine.Options) (engine.Result, error) {
		seen = append(seen, o)
		cancel()
		return engine.Result{}, c.Err()
	}
	res, err := Run(ctx, Options{CorpusDir: corpus, Config: config.Default(), Scan: scan})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || len(res.Fixtures) != 0 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "cancelled") {
		t.Fatalf("scanned %d, fixtures %d, notes %v", len(seen), len(res.Fixtures), res.Notes)
	}
}

func TestRunEmptyOrMissingCorpus(t *testing.T) {
	if _, err := Run(context.Background(), Options{CorpusDir: t.TempDir()}); err == nil {
		t.Fatal("an empty corpus must be an error")
	}
	if _, err := Run(context.Background(), Options{CorpusDir: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Fatal("a missing corpus must be an error")
	}
}

// TestRunDeterministicRealCorpus scans the real corpus with no model. It
// asserts structure only: the numbers belong in a results file, not a test.
func TestRunDeterministicRealCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("scans the whole corpus; skipped with -short")
	}
	corpus, err := LoadCorpus(realCorpus)
	if err != nil {
		t.Fatal(err)
	}
	entries := 0
	for _, tr := range corpus {
		entries += len(tr.Vulnerabilities)
	}
	res, err := Run(context.Background(), Options{CorpusDir: realCorpus, Config: config.Default(), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != ModeDeterministic || res.Model != "none" {
		t.Fatalf("mode %q model %q", res.Mode, res.Model)
	}
	if len(res.Fixtures) != len(corpus) || res.Corpus.Fixtures != len(corpus) {
		t.Fatalf("scored %d of %d fixtures; notes: %v", len(res.Fixtures), len(corpus), res.Notes)
	}
	if got := res.Totals.TruePositives + res.Totals.FalseNegatives; got != entries || res.Corpus.TruthEntries != entries {
		t.Fatalf("TP+FN = %d, truth entries = %d", got, entries)
	}
	for _, fs := range res.Fixtures {
		if fs.Error != "" {
			t.Errorf("%s: scan failed: %s", fs.Fixture, fs.Error)
		}
	}
	if res.Totals.CostUSD != 0 || !res.Totals.CostKnown {
		t.Fatalf("a run without a model cannot cost anything: %+v", res.Totals)
	}
}

// A fixture whose scan failed found nothing because it never ran. It must
// not read as a decoy left alone, or as flaws that were missed.
func TestFailedFixturesAreLeftOutOfTheTotals(t *testing.T) {
	corpus := tempCorpus(t)
	answers := map[string]engine.Result{
		"a-vuln": {Run: report.Run{Findings: []finding.Finding{found("sql-injection", 10)}}},
	}
	fail := map[string]error{"b-clean": errors.New("scan broke"), "c-vuln": errors.New("scan broke")}
	var seen []engine.Options
	res, err := Run(context.Background(), Options{CorpusDir: corpus, Config: config.Default(), Scan: canned(answers, fail, &seen)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Totals.FailedFixtures != 2 {
		t.Fatalf("failed fixtures = %d, want 2", res.Totals.FailedFixtures)
	}
	if res.Totals.CleanFixtures != 0 || res.Totals.DecoysFlagged != 0 {
		t.Errorf("the failed clean fixture was counted: %d clean, %d flagged", res.Totals.CleanFixtures, res.Totals.DecoysFlagged)
	}
	if res.Totals.TruePositives != 1 || res.Totals.FalseNegatives != 1 {
		// a-vuln plants two flaws and one was found; c-vuln never ran.
		t.Errorf("totals = %+v, want only a-vuln's one hit and one miss", res.Totals)
	}
	if !strings.Contains(Summary(res), "Fixtures failed:   2") {
		t.Errorf("the summary does not report the failures:\n%s", Summary(res))
	}
}

// Bench never asks a fixture scan to open a pull request, whatever the
// configuration says.
func TestRunNeverOpensAPullRequest(t *testing.T) {
	corpus := tempCorpus(t)
	cfg := config.Default()
	cfg.Fix.PR = true
	var seen []engine.Options
	if _, err := Run(context.Background(), Options{CorpusDir: corpus, Config: cfg, Now: fixedNow, Scan: canned(map[string]engine.Result{}, nil, &seen)}); err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatal("no fixture was scanned")
	}
	for _, o := range seen {
		if o.Config.Fix.PR {
			t.Fatalf("%s was scanned with --pr", o.Target)
		}
	}
}
