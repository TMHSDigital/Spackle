package bench

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Schema identifies the results file format.
const Schema = "spackle.bench/v1"

// Run modes, as recorded in a results file.
const (
	ModeDeterministic = "deterministic"
	ModeAgentic       = "agentic"
)

// Results is the file written to bench/results/<date>-<model>.json.
type Results struct {
	Schema       string            `json:"schema"`
	Date         string            `json:"date"` // YYYY-MM-DD (UTC)
	Version      string            `json:"spackle_version"`
	Commit       string            `json:"commit,omitempty"`
	Mode         string            `json:"mode"` // deterministic|agentic
	Provider     string            `json:"provider,omitempty"`
	Model        string            `json:"model"` // "none" for deterministic
	Corpus       CorpusInfo        `json:"corpus"`
	Totals       Totals            `json:"totals"`
	ByLanguage   map[string]Totals `json:"by_language"`
	ByDifficulty map[string]Totals `json:"by_difficulty"`
	Fixtures     []FixtureScore    `json:"fixtures"`
	Notes        []string          `json:"notes,omitempty"`
}

// CorpusInfo describes the corpus a run was measured against, so results from
// different corpus revisions are not compared as if they were the same.
type CorpusInfo struct {
	Fixtures     int            `json:"fixtures"`
	Clean        int            `json:"clean"`
	Vulnerable   int            `json:"vulnerable"`
	TruthEntries int            `json:"truth_entries"`
	ByLanguage   map[string]int `json:"by_language"`
}

// Totals aggregates a set of fixture scores.
type Totals struct {
	TruePositives  int `json:"true_positives"`
	FalsePositives int `json:"false_positives"`
	FalseNegatives int `json:"false_negatives"`
	// Precision, Recall and F1 are 0 when the denominator is 0, and are
	// rounded to 4 decimals.
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	F1            float64 `json:"f1"`
	VerifiedFixes int     `json:"verified_fixes"`
	// VerifiedFixRate is verified fixes / true positives.
	VerifiedFixRate float64 `json:"verified_fix_rate"`
	CostUSD         float64 `json:"cost_usd"`
	CostKnown       bool    `json:"cost_known"`
	InputTokens     int     `json:"input_tokens"`
	OutputTokens    int     `json:"output_tokens"`
	TokensEstimated bool    `json:"tokens_estimated"`
	// CostPerFinding is CostUSD / true positives; 0 when either is 0.
	CostPerFinding float64 `json:"cost_per_finding"`
	// DecoysFlagged counts clean fixtures with at least one false positive.
	DecoysFlagged int `json:"decoys_flagged"`
	CleanFixtures int `json:"clean_fixtures"`
	// FailedFixtures counts fixtures whose scan failed. They are left out
	// of every figure above: a scan that never ran found nothing, which
	// must not read as a decoy left alone or as a missed flaw.
	FailedFixtures int `json:"failed_fixtures,omitempty"`
}

// spend is the model accounting of one fixture's scan.
type spend struct {
	costUSD      float64
	costKnown    bool
	inputTokens  int
	outputTokens int
	estimated    bool
}

func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }

func ratio(num, den float64) float64 {
	if den == 0 {
		return 0
	}
	return round4(num / den)
}

// total aggregates scores with their spend; the two slices are parallel.
func total(scores []FixtureScore, spends []spend) Totals {
	t := Totals{CostKnown: true}
	for i, s := range scores {
		sp := spends[i]
		if s.Error != "" {
			// What the failed scan spent is still part of the run's cost.
			t.FailedFixtures++
			t.CostUSD += sp.costUSD
			t.CostKnown = t.CostKnown && sp.costKnown
			t.InputTokens += sp.inputTokens
			t.OutputTokens += sp.outputTokens
			t.TokensEstimated = t.TokensEstimated || sp.estimated
			continue
		}
		t.TruePositives += s.TruePositives
		t.FalsePositives += s.FalsePositives
		t.FalseNegatives += s.FalseNegatives
		t.VerifiedFixes += s.VerifiedFixes
		if s.Clean {
			t.CleanFixtures++
			if s.FalsePositives > 0 {
				t.DecoysFlagged++
			}
		}
		t.CostUSD += sp.costUSD
		t.CostKnown = t.CostKnown && sp.costKnown
		t.InputTokens += sp.inputTokens
		t.OutputTokens += sp.outputTokens
		t.TokensEstimated = t.TokensEstimated || sp.estimated
	}
	tp := float64(t.TruePositives)
	t.Precision = ratio(tp, tp+float64(t.FalsePositives))
	t.Recall = ratio(tp, tp+float64(t.FalseNegatives))
	if t.Precision+t.Recall > 0 {
		t.F1 = round4(2 * t.Precision * t.Recall / (t.Precision + t.Recall))
	}
	t.VerifiedFixRate = ratio(float64(t.VerifiedFixes), tp)
	// Summing many small costs leaves float noise that would make two
	// identical runs differ in the last digits of the file.
	t.CostUSD = math.Round(t.CostUSD*1e6) / 1e6
	t.CostPerFinding = ratio(t.CostUSD, tp)
	return t
}

// split groups totals by a key of the fixture score.
func split(scores []FixtureScore, spends []spend, key func(FixtureScore) string) map[string]Totals {
	groupScores := map[string][]FixtureScore{}
	groupSpends := map[string][]spend{}
	for i, s := range scores {
		k := key(s)
		groupScores[k] = append(groupScores[k], s)
		groupSpends[k] = append(groupSpends[k], spends[i])
	}
	out := make(map[string]Totals, len(groupScores))
	for k := range groupScores {
		out[k] = total(groupScores[k], groupSpends[k])
	}
	return out
}

func corpusInfo(corpus []Truth) CorpusInfo {
	info := CorpusInfo{Fixtures: len(corpus), ByLanguage: map[string]int{}}
	for _, t := range corpus {
		if t.Clean {
			info.Clean++
		} else {
			info.Vulnerable++
			info.TruthEntries += len(t.Vulnerabilities)
		}
		info.ByLanguage[t.Language]++
	}
	return info
}

// FileName returns "<date>-<model>.json" with the model sanitized to
// [a-z0-9._-] (other characters become "-", runs collapsed), "none" for
// deterministic.
func FileName(r Results) string {
	var b strings.Builder
	dash := false
	for _, c := range strings.ToLower(r.Model) {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_'
		if !ok {
			dash = true
			continue
		}
		if dash && b.Len() > 0 {
			b.WriteByte('-')
		}
		dash = false
		b.WriteRune(c)
	}
	// Leading dots would make a hidden file or a directory reference.
	model := strings.Trim(b.String(), ".-")
	if model == "" || r.Mode == ModeDeterministic {
		model = "none"
	}
	return r.Date + "-" + model + ".json"
}

// Write writes results as indented JSON with a trailing newline into dir,
// creating it. It refuses to overwrite an existing file unless force is true.
func Write(dir string, r Results, force bool) (string, error) {
	if _, err := dateOf(r); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode benchmark results: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create results directory %s: %w. Pass --out with a directory you can write to", dir, err)
	}
	path := filepath.Join(dir, FileName(r))
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !force {
		// O_EXCL makes the refusal atomic: two runs finishing together
		// cannot both believe the file was absent.
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o644) //nolint:gosec // results are committed to the repository and meant to be world-readable; the operator chose the directory
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("results file %s already exists: a results file is never overwritten silently. Pass --force to replace it with this run", path)
		}
		return "", fmt.Errorf("write results file %s: %w", path, err)
	}
	_, werr := f.Write(append(b, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", fmt.Errorf("write results file %s: %w", path, werr)
	}
	return path, nil
}

// dateOf rejects a results value whose date could not form a safe file name.
func dateOf(r Results) (string, error) {
	if len(r.Date) != len("2006-01-02") || strings.ContainsAny(r.Date, `/\.`) {
		return "", fmt.Errorf("benchmark results have date %q, which is not of the form YYYY-MM-DD: results must come from a benchmark run", r.Date)
	}
	return r.Date, nil
}

// LoadResults reads every *.json in dir (sorted newest first). A missing dir
// returns no results.
func LoadResults(dir string) ([]Results, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read results directory %s: %w", dir, err)
	}
	type named struct {
		name string
		r    Results
	}
	var all []named
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path) //nolint:gosec // the operator chose the results directory
		if err != nil {
			return nil, fmt.Errorf("read results file %s: %w", path, err)
		}
		var r Results
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("results file %s is not valid JSON: %w. Results files are written only by the bench command; restore it from git or delete it", path, err)
		}
		if r.Schema != Schema {
			return nil, fmt.Errorf("results file %s has schema %q, expected %q: it was not written by this version of the bench command. Move it out of %s or regenerate it", path, r.Schema, Schema, dir)
		}
		all = append(all, named{e.Name(), r})
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].r.Date != all[j].r.Date {
			return all[i].r.Date > all[j].r.Date
		}
		return all[i].name < all[j].name
	})
	out := make([]Results, 0, len(all))
	for _, n := range all {
		out = append(out, n.r)
	}
	return out, nil
}

func percent(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }

// fixRateText renders the verified-fix rate. A deterministic run never
// attempts a fix, so a percentage there would read as "every fix failed".
func fixRateText(r Results) string {
	if r.Mode != ModeAgentic {
		return "n/a"
	}
	return percent(r.Totals.VerifiedFixRate)
}

// costText renders cost per finding without ever inventing a number: no
// model means no cost, an unpriced model means the cost is not known, and
// with no true positives there is nothing to divide by.
func costText(r Results) string {
	switch {
	case r.Mode != ModeAgentic:
		return "n/a"
	case !r.Totals.CostKnown:
		return "unknown"
	case r.Totals.TruePositives == 0:
		return "n/a"
	}
	return fmt.Sprintf("$%.4f", r.Totals.CostPerFinding)
}

// cell keeps a value from breaking out of its table cell.
func cell(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ", "|", `\|`).Replace(s)
	return strings.TrimSpace(s)
}

// Table renders the README table (GitHub markdown) for one or more results,
// newest first: columns Date | Version | Model | Mode | Precision | Recall |
// Verified-fix rate | Cost per finding. Cost per finding shows "n/a" for
// deterministic runs and "unknown" when the cost is not known.
func Table(rs []Results) string {
	sorted := make([]Results, len(rs))
	copy(sorted, rs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Date > sorted[j].Date })
	var b strings.Builder
	b.WriteString("| Date | Version | Model | Mode | Precision | Recall | Verified-fix rate | Cost per finding |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, r := range sorted {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			cell(r.Date), cell(r.Version), cell(r.Model), cell(r.Mode),
			percent(r.Totals.Precision), percent(r.Totals.Recall), fixRateText(r), costText(r))
	}
	return b.String()
}

// Summary renders the short end-of-run report for the terminal.
func Summary(r Results) string {
	t := r.Totals
	var b strings.Builder
	fmt.Fprintf(&b, "Benchmark: %d of %d fixtures scored (%s, model %s)\n", len(r.Fixtures), r.Corpus.Fixtures, r.Mode, r.Model)
	fmt.Fprintf(&b, "Precision:         %s (%d true positives, %d false positives)\n", percent(t.Precision), t.TruePositives, t.FalsePositives)
	fmt.Fprintf(&b, "Recall:            %s (%d of %d planted flaws found)\n", percent(t.Recall), t.TruePositives, t.TruePositives+t.FalseNegatives)
	fmt.Fprintf(&b, "Verified-fix rate: %s\n", fixRateText(r))
	fmt.Fprintf(&b, "Cost per finding:  %s\n", costText(r))
	fmt.Fprintf(&b, "Decoys flagged:    %d of %d\n", t.DecoysFlagged, t.CleanFixtures)
	if t.FailedFixtures > 0 {
		fmt.Fprintf(&b, "Fixtures failed:   %d (their scans did not run to the end; they are left out of every figure above)\n", t.FailedFixtures)
	}
	return b.String()
}
