package bench

import (
	"path"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/finding"
)

// lineTolerance is how far a reported line may be from the truth line and
// still match (bench/README.md, "How matching works").
const lineTolerance = 3

// Reported is a finding reduced to what scoring needs.
type Reported struct {
	ID         string `json:"id"`
	Class      string `json:"class"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Confidence string `json:"confidence"`
	Status     string `json:"status"`
	// Fixed is true when the finding carries a verified fix.
	Fixed bool `json:"fixed"`
}

// Match pairs one truth entry with the reported finding that matched it.
type Match struct {
	Class        string `json:"class"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	FindingID    string `json:"finding_id"`
	ReportedLine int    `json:"reported_line"`
}

// FixtureScore is the outcome for one fixture.
type FixtureScore struct {
	Fixture        string     `json:"fixture"`
	Language       string     `json:"language"`
	Difficulty     string     `json:"difficulty"`
	Clean          bool       `json:"clean"`
	TruePositives  int        `json:"true_positives"`
	FalsePositives int        `json:"false_positives"`
	FalseNegatives int        `json:"false_negatives"`
	Matched        []Match    `json:"matched"`
	Missed         []Vuln     `json:"missed"`
	Spurious       []Reported `json:"spurious"`
	VerifiedFixes  int        `json:"verified_fixes"`
	// Error is set when the scan of this fixture failed.
	Error string `json:"error,omitempty"`
}

// FromFinding reduces a finding to what scoring needs. A fix counts as
// verified only when the finding is marked fixed and its verification record
// says so; a patch that was written but not verified does not count.
func FromFinding(f finding.Finding) Reported {
	return Reported{
		ID: f.ID, Class: f.Class, File: f.Location.File, Line: f.Location.StartLine,
		Confidence: f.Confidence.Level, Status: f.Status,
		Fixed: f.Status == finding.StatusFixed && strings.HasPrefix(f.Remediation.Verification, "verified"),
	}
}

// Score compares reported findings with a fixture's truth. A reported finding
// matches a truth entry when the class is equal, the file is equal (forward
// slashes, case-sensitive) and the line is within 3 lines. Each truth entry
// and each reported finding is matched at most once; when several candidates
// exist prefer the smallest line distance, then the lower finding id.
// Dismissed findings are ignored entirely (not TP, not FP). In a clean fixture
// every non-dismissed reported finding is a false positive.
func Score(t Truth, reported []Reported) FixtureScore {
	s := FixtureScore{
		Fixture: t.Fixture, Language: t.Language, Difficulty: t.Difficulty, Clean: t.Clean,
		Matched: []Match{}, Missed: []Vuln{}, Spurious: []Reported{},
	}
	var live []Reported
	for _, r := range reported {
		if r.Status != finding.StatusDismissed {
			live = append(live, r)
		}
	}
	// A decoy has nothing to match by definition, even if its truth file
	// were to list entries.
	var truth []Vuln
	if !t.Clean {
		truth = t.Vulnerabilities
	}

	type pair struct{ truth, rep, dist int }
	var pairs []pair
	for ti, v := range truth {
		for ri, r := range live {
			if r.Class != v.Class || slash(r.File) != slash(v.File) {
				continue
			}
			d := r.Line - v.Line
			if d < 0 {
				d = -d
			}
			if d <= lineTolerance {
				pairs = append(pairs, pair{ti, ri, d})
			}
		}
	}
	// Input order breaks the remaining ties so the result does not depend on
	// the sort implementation.
	sort.SliceStable(pairs, func(i, j int) bool {
		a, b := pairs[i], pairs[j]
		if a.dist != b.dist {
			return a.dist < b.dist
		}
		if live[a.rep].ID != live[b.rep].ID {
			return live[a.rep].ID < live[b.rep].ID
		}
		if a.rep != b.rep {
			return a.rep < b.rep
		}
		return a.truth < b.truth
	})
	truthTo := make([]int, len(truth))
	for i := range truthTo {
		truthTo[i] = -1
	}
	repUsed := make([]bool, len(live))
	for _, p := range pairs {
		if truthTo[p.truth] >= 0 || repUsed[p.rep] {
			continue
		}
		truthTo[p.truth] = p.rep
		repUsed[p.rep] = true
	}

	for ti, v := range truth {
		ri := truthTo[ti]
		if ri < 0 {
			s.Missed = append(s.Missed, v)
			continue
		}
		r := live[ri]
		s.Matched = append(s.Matched, Match{Class: v.Class, File: v.File, Line: v.Line, FindingID: r.ID, ReportedLine: r.Line})
		if r.Fixed {
			s.VerifiedFixes++
		}
	}
	for ri, r := range live {
		if !repUsed[ri] {
			s.Spurious = append(s.Spurious, r)
		}
	}
	s.TruePositives = len(s.Matched)
	s.FalseNegatives = len(s.Missed)
	s.FalsePositives = len(s.Spurious)
	return s
}

// slash normalizes a path for comparison without changing its case.
func slash(p string) string {
	return path.Clean(strings.ReplaceAll(p, `\`, "/"))
}
