package bench

import (
	"testing"

	"github.com/TMHSDigital/spackle/internal/finding"
)

func truthOf(clean bool, vs ...Vuln) Truth {
	return Truth{Fixture: "fx", Language: "go", Difficulty: "easy", Clean: clean, Vulnerabilities: vs}
}

func vuln(class, file string, line int) Vuln { return Vuln{Class: class, File: file, Line: line} }

func rep(id, class, file string, line int) Reported {
	return Reported{ID: id, Class: class, File: file, Line: line, Status: finding.StatusOpen}
}

func counts(t *testing.T, s FixtureScore, tp, fp, fn int) {
	t.Helper()
	if s.TruePositives != tp || s.FalsePositives != fp || s.FalseNegatives != fn {
		t.Fatalf("TP/FP/FN = %d/%d/%d, want %d/%d/%d", s.TruePositives, s.FalsePositives, s.FalseNegatives, tp, fp, fn)
	}
	if len(s.Matched) != tp || len(s.Spurious) != fp || len(s.Missed) != fn {
		t.Fatalf("lists = %d/%d/%d, want %d/%d/%d", len(s.Matched), len(s.Spurious), len(s.Missed), tp, fp, fn)
	}
}

func TestScoreExactMatch(t *testing.T) {
	s := Score(truthOf(false, vuln("sql-injection", "app.py", 23)), []Reported{rep("SPK-1", "sql-injection", "app.py", 23)})
	counts(t, s, 1, 0, 0)
	m := s.Matched[0]
	if m.FindingID != "SPK-1" || m.Line != 23 || m.ReportedLine != 23 || m.Class != "sql-injection" || m.File != "app.py" {
		t.Fatalf("match = %+v", m)
	}
	if s.Fixture != "fx" || s.Language != "go" || s.Difficulty != "easy" || s.Clean {
		t.Fatalf("fixture fields not copied: %+v", s)
	}
}

func TestScoreLineTolerance(t *testing.T) {
	truth := truthOf(false, vuln("xss", "a.ts", 10))
	for _, line := range []int{7, 13} {
		counts(t, Score(truth, []Reported{rep("A", "xss", "a.ts", line)}), 1, 0, 0)
	}
	for _, line := range []int{6, 14} {
		counts(t, Score(truth, []Reported{rep("A", "xss", "a.ts", line)}), 0, 1, 1)
	}
}

func TestScoreWrongClassAndFile(t *testing.T) {
	truth := truthOf(false, vuln("xss", "src/a.ts", 10))
	counts(t, Score(truth, []Reported{rep("A", "ssrf", "src/a.ts", 10)}), 0, 1, 1)
	counts(t, Score(truth, []Reported{rep("A", "xss", "src/b.ts", 10)}), 0, 1, 1)
	// The file comparison is case-sensitive.
	counts(t, Score(truth, []Reported{rep("A", "xss", "src/A.ts", 10)}), 0, 1, 1)
}

func TestScoreTwoFindingsOneTruth(t *testing.T) {
	truth := truthOf(false, vuln("xss", "a.ts", 10))
	s := Score(truth, []Reported{rep("B", "xss", "a.ts", 10), rep("A", "xss", "a.ts", 10)})
	counts(t, s, 1, 1, 0)
	// Equal distance: the lower finding id wins.
	if s.Matched[0].FindingID != "A" || s.Spurious[0].ID != "B" {
		t.Fatalf("matched %q, spurious %q", s.Matched[0].FindingID, s.Spurious[0].ID)
	}
}

func TestScoreTwoTruthsOneFinding(t *testing.T) {
	truth := truthOf(false, vuln("xss", "a.ts", 10), vuln("xss", "a.ts", 12))
	s := Score(truth, []Reported{rep("A", "xss", "a.ts", 12)})
	counts(t, s, 1, 0, 1)
	if s.Matched[0].Line != 12 || s.Missed[0].Line != 10 {
		t.Fatalf("matched line %d, missed line %d", s.Matched[0].Line, s.Missed[0].Line)
	}
}

func TestScoreNearestLinePreferred(t *testing.T) {
	truth := truthOf(false, vuln("xss", "a.ts", 10))
	s := Score(truth, []Reported{rep("A", "xss", "a.ts", 13), rep("Z", "xss", "a.ts", 11)})
	counts(t, s, 1, 1, 0)
	if s.Matched[0].FindingID != "Z" {
		t.Fatalf("matched %q, want the nearer finding Z", s.Matched[0].FindingID)
	}
}

func TestScoreDismissedIgnored(t *testing.T) {
	truth := truthOf(false, vuln("xss", "a.ts", 10))
	gone := rep("A", "xss", "a.ts", 10)
	gone.Status = finding.StatusDismissed
	other := rep("B", "ssrf", "a.ts", 40)
	other.Status = finding.StatusDismissed
	counts(t, Score(truth, []Reported{gone, other}), 0, 0, 1)
}

func TestScoreCleanFixture(t *testing.T) {
	s := Score(truthOf(true), []Reported{rep("A", "xss", "a.ts", 1), rep("B", "ssrf", "b.ts", 2)})
	counts(t, s, 0, 2, 0)
	if !s.Clean {
		t.Fatal("Clean not copied")
	}
	counts(t, Score(truthOf(true), nil), 0, 0, 0)
}

func TestScoreEmpty(t *testing.T) {
	s := Score(Truth{}, nil)
	counts(t, s, 0, 0, 0)
	if s.Matched == nil || s.Missed == nil || s.Spurious == nil {
		t.Fatal("lists must be empty, not nil, so the JSON is stable")
	}
}

func TestScoreVerifiedFixes(t *testing.T) {
	truth := truthOf(false, vuln("xss", "a.ts", 10), vuln("ssrf", "a.ts", 30))
	fixed := rep("A", "xss", "a.ts", 10)
	fixed.Fixed = true
	// A verified fix on a false positive is not a verified fix of anything real.
	spurious := rep("C", "weak-hash", "a.ts", 50)
	spurious.Fixed = true
	s := Score(truth, []Reported{fixed, rep("B", "ssrf", "a.ts", 30), spurious})
	counts(t, s, 2, 1, 0)
	if s.VerifiedFixes != 1 {
		t.Fatalf("VerifiedFixes = %d, want 1", s.VerifiedFixes)
	}
}

func TestFromFinding(t *testing.T) {
	f := finding.Finding{
		ID: "SPK-1", Class: "xss", Location: finding.Location{File: "a.ts", StartLine: 7},
		Confidence: finding.Confidence{Level: finding.ConfidenceHigh}, Status: finding.StatusFixed,
		Remediation: finding.Remediation{Verification: "verified: tests pass and the rescan is clean"},
	}
	r := FromFinding(f)
	want := Reported{ID: "SPK-1", Class: "xss", File: "a.ts", Line: 7, Confidence: "high", Status: "fixed", Fixed: true}
	if r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
	f.Remediation.Verification = "unverified"
	if FromFinding(f).Fixed {
		t.Fatal("an unverified fix must not count")
	}
	f.Remediation.Verification, f.Status = "verified", finding.StatusOpen
	if FromFinding(f).Fixed {
		t.Fatal("a finding that is still open must not count as fixed")
	}
}
