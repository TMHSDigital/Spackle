package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTotalZeroDenominators(t *testing.T) {
	got := total(nil, nil)
	if got.Precision != 0 || got.Recall != 0 || got.F1 != 0 || got.VerifiedFixRate != 0 || got.CostPerFinding != 0 {
		t.Fatalf("zero denominators must give 0: %+v", got)
	}
	if !got.CostKnown {
		t.Fatal("a run with no model calls has a known cost of zero")
	}
	// Spend with no true positives: cost per finding stays 0, never Inf.
	got = total([]FixtureScore{{FalsePositives: 2}}, []spend{{costUSD: 1.5, costKnown: true}})
	if got.CostPerFinding != 0 || got.Precision != 0 || got.CostUSD != 1.5 {
		t.Fatalf("got %+v", got)
	}
}

func TestTotalMathAndRounding(t *testing.T) {
	scores := []FixtureScore{
		{TruePositives: 2, FalsePositives: 1, FalseNegatives: 0, VerifiedFixes: 1},
		{TruePositives: 0, FalsePositives: 0, FalseNegatives: 4},
		{Clean: true, FalsePositives: 3},
		{Clean: true},
	}
	spends := []spend{
		{costUSD: 0.10, costKnown: true, inputTokens: 100, outputTokens: 10},
		{costUSD: 0.20, costKnown: true, inputTokens: 200, outputTokens: 20},
		{costUSD: 0.05, costKnown: true, inputTokens: 50, outputTokens: 5},
		{costKnown: true},
	}
	got := total(scores, spends)
	if got.TruePositives != 2 || got.FalsePositives != 4 || got.FalseNegatives != 4 {
		t.Fatalf("sums wrong: %+v", got)
	}
	// 2/6 = 0.3333, 2/6 = 0.3333
	if got.Precision != 0.3333 || got.Recall != 0.3333 || got.F1 != 0.3333 {
		t.Fatalf("precision/recall/f1 = %v/%v/%v", got.Precision, got.Recall, got.F1)
	}
	if got.VerifiedFixes != 1 || got.VerifiedFixRate != 0.5 {
		t.Fatalf("verified fixes %d rate %v", got.VerifiedFixes, got.VerifiedFixRate)
	}
	if got.CostUSD != 0.35 || got.CostPerFinding != 0.175 || !got.CostKnown {
		t.Fatalf("cost %v per finding %v known %v", got.CostUSD, got.CostPerFinding, got.CostKnown)
	}
	if got.InputTokens != 350 || got.OutputTokens != 35 || got.TokensEstimated {
		t.Fatalf("tokens %d/%d estimated %v", got.InputTokens, got.OutputTokens, got.TokensEstimated)
	}
	if got.CleanFixtures != 2 || got.DecoysFlagged != 1 {
		t.Fatalf("clean %d flagged %d", got.CleanFixtures, got.DecoysFlagged)
	}
}

func TestTotalUnknownCostAndEstimatedTokens(t *testing.T) {
	got := total(
		[]FixtureScore{{TruePositives: 1}, {TruePositives: 1}},
		[]spend{{costUSD: 0.1, costKnown: true}, {costKnown: false, estimated: true}},
	)
	if got.CostKnown || !got.TokensEstimated {
		t.Fatalf("one unpriced or estimated fixture must taint the total: %+v", got)
	}
}

func TestSplit(t *testing.T) {
	scores := []FixtureScore{
		{Language: "go", Difficulty: "easy", TruePositives: 1},
		{Language: "go", Difficulty: "hard", FalseNegatives: 1},
		{Language: "python", Difficulty: "easy", TruePositives: 1, FalsePositives: 1},
	}
	spends := []spend{{costUSD: 1, costKnown: true}, {costUSD: 2, costKnown: true}, {costUSD: 4, costKnown: false}}
	lang := split(scores, spends, func(s FixtureScore) string { return s.Language })
	if len(lang) != 2 || lang["go"].Recall != 0.5 || lang["go"].CostUSD != 3 || !lang["go"].CostKnown {
		t.Fatalf("go = %+v", lang["go"])
	}
	if lang["python"].Precision != 0.5 || lang["python"].CostKnown {
		t.Fatalf("python = %+v", lang["python"])
	}
	diff := split(scores, spends, func(s FixtureScore) string { return s.Difficulty })
	if diff["easy"].TruePositives != 2 || diff["hard"].FalseNegatives != 1 || diff["hard"].Recall != 0 {
		t.Fatalf("difficulty = %+v", diff)
	}
}

func TestFileName(t *testing.T) {
	cases := map[string]string{
		"claude-opus-4-5":         "claude-opus-4-5",
		"Vendor/Some Model:8B":    "vendor-some-model-8b",
		"a//b  c":                 "a-b-c",
		"--weird--":               "weird",
		"../../etc/passwd":        "etc-passwd",
		"model_v1.5":              "model_v1.5",
		"":                        "none",
		"!!!":                     "none",
		"..":                      "none",
		"qwen2.5-coder:32b@local": "qwen2.5-coder-32b-local",
	}
	for model, want := range cases {
		got := FileName(Results{Date: "2026-11-22", Mode: ModeAgentic, Model: model})
		if got != "2026-11-22-"+want+".json" {
			t.Errorf("FileName(%q) = %q, want model part %q", model, got, want)
		}
	}
	if got := FileName(Results{Date: "2026-11-22", Mode: ModeDeterministic, Model: "anything"}); got != "2026-11-22-none.json" {
		t.Errorf("deterministic = %q", got)
	}
}

func sample(date, mode, model string) Results {
	return Results{Schema: Schema, Date: date, Version: "v0.1.0", Mode: mode, Model: model, Fixtures: []FixtureScore{}}
}

func TestWriteRefusesToOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "results")
	r := sample("2026-11-22", ModeDeterministic, "none")
	path, err := Write(dir, r, false)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "2026-11-22-none.json" {
		t.Fatalf("path = %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "}\n") || !strings.Contains(string(raw), "\n  \"schema\": \"spackle.bench/v1\"") {
		t.Fatalf("not indented JSON with a trailing newline:\n%s", raw)
	}

	r.Version = "v0.2.0"
	if _, err := Write(dir, r, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("second write must fail and name --force, got %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(raw) {
		t.Fatal("a refused write changed the file")
	}
	if _, err := Write(dir, r, true); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); !strings.Contains(string(after), "v0.2.0") {
		t.Fatal("force did not replace the file")
	}
}

func TestWriteRejectsBadDate(t *testing.T) {
	if _, err := Write(t.TempDir(), sample("../../x", ModeDeterministic, "none"), false); err == nil {
		t.Fatal("a date that is not YYYY-MM-DD must be refused")
	}
}

func TestLoadResultsOrderAndMissingDir(t *testing.T) {
	got, err := LoadResults(filepath.Join(t.TempDir(), "absent"))
	if err != nil || len(got) != 0 {
		t.Fatalf("missing dir: %v, %d results", err, len(got))
	}
	dir := t.TempDir()
	for _, r := range []Results{
		sample("2026-11-20", ModeDeterministic, "none"),
		sample("2026-11-22", ModeAgentic, "model-b"),
		sample("2026-11-22", ModeAgentic, "model-a"),
		sample("2026-11-21", ModeAgentic, "model-a"),
	} {
		if _, err := Write(dir, r, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not results"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = LoadResults(dir)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, r := range got {
		order = append(order, r.Date+"/"+r.Model)
	}
	want := "2026-11-22/model-a 2026-11-22/model-b 2026-11-21/model-a 2026-11-20/none"
	if strings.Join(order, " ") != want {
		t.Fatalf("order = %v, want %s", order, want)
	}
}

func TestLoadResultsRejectsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResults(dir); err == nil || !strings.Contains(err.Error(), "bad.json") {
		t.Fatalf("invalid JSON must be an error naming the file, got %v", err)
	}
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "other.json"), []byte(`{"schema":"something/else"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResults(dir); err == nil || !strings.Contains(err.Error(), "other.json") {
		t.Fatalf("a foreign schema must be an error naming the file, got %v", err)
	}
}

func TestTable(t *testing.T) {
	det := sample("2026-11-20", ModeDeterministic, "none")
	det.Totals = Totals{TruePositives: 3, Precision: 0.75, Recall: 0.5, CostKnown: true}
	known := sample("2026-11-22", ModeAgentic, "model-a")
	known.Totals = Totals{TruePositives: 4, Precision: 0.9, Recall: 0.8125, VerifiedFixRate: 0.25, CostUSD: 1, CostKnown: true, CostPerFinding: 0.25}
	unknown := sample("2026-11-21", ModeAgentic, "local|model")
	unknown.Totals = Totals{TruePositives: 4, Precision: 1, Recall: 1, CostKnown: false}

	got := Table([]Results{det, known, unknown})
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	want := []string{
		"| Date | Version | Model | Mode | Precision | Recall | Verified-fix rate | Cost per finding |",
		"|---|---|---|---|---|---|---|---|",
		"| 2026-11-22 | v0.1.0 | model-a | agentic | 90.0% | 81.2% | 25.0% | $0.2500 |",
		`| 2026-11-21 | v0.1.0 | local\|model | agentic | 100.0% | 100.0% | 0.0% | unknown |`,
		"| 2026-11-20 | v0.1.0 | none | deterministic | 75.0% | 50.0% | n/a | n/a |",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines:\n%s", len(lines), got)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d:\n got %s\nwant %s", i, lines[i], want[i])
		}
	}
}

func TestSummary(t *testing.T) {
	r := sample("2026-11-22", ModeDeterministic, "none")
	r.Corpus.Fixtures = 3
	r.Fixtures = []FixtureScore{{}, {}, {}}
	r.Totals = Totals{TruePositives: 1, FalsePositives: 1, FalseNegatives: 3, Precision: 0.5, Recall: 0.25, DecoysFlagged: 1, CleanFixtures: 2, CostKnown: true}
	got := Summary(r)
	for _, want := range []string{"3 of 3 fixtures", "Precision:         50.0%", "Recall:            25.0% (1 of 4", "Verified-fix rate: n/a", "Cost per finding:  n/a", "Decoys flagged:    1 of 2"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary lacks %q:\n%s", want, got)
		}
	}
}
