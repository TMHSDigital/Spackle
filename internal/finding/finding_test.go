package finding

import (
	"strings"
	"testing"
)

const critVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

func valid() Finding {
	sev, err := SeverityFromVector(critVector, "network reachable, no auth")
	if err != nil {
		panic(err)
	}
	loc := Location{File: "app/db.py", StartLine: 12, EndLine: 14}
	return Finding{
		ID: MakeID("sql-injection", loc), Title: "SQL injection in user lookup",
		Surface: SurfaceCode, Class: "sql-injection", CWE: []string{"CWE-89"},
		Location: loc, Severity: sev,
		Flaw:        Flaw{Description: "The query is built by string formatting."},
		Proof:       Proof{Status: ProofNotRun, Reason: "no container runtime"},
		Remediation: Remediation{Summary: "Use a parameterized query."},
		Confidence:  Confidence{Level: ConfidenceHigh, Reason: "traced from request to sink"},
		Status:      StatusOpen,
	}
}

func TestScore(t *testing.T) {
	score, label, err := Score(critVector)
	if err != nil || score != 9.3 || label != "critical" {
		t.Fatalf("score=%v label=%q err=%v, want 9.3 critical", score, label, err)
	}
}

func TestScoreRejectsBadVectors(t *testing.T) {
	for _, v := range []string{
		"", "nonsense", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:N",
	} {
		if _, _, err := Score(v); err == nil {
			t.Errorf("Score(%q) accepted an invalid vector", v)
		}
	}
}

func TestEveryDefaultVectorScores(t *testing.T) {
	for _, class := range Classes() {
		v, _ := DefaultVector(class)
		score, label, err := Score(v)
		if err != nil {
			t.Errorf("class %s: %v", class, err)
			continue
		}
		if score <= 0 || label == "none" {
			t.Errorf("class %s scores %.1f %s; a default vector must be above none", class, score, label)
		}
	}
}

func TestValidateAcceptsCompleteFinding(t *testing.T) {
	f := valid()
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejections(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Finding)
		want   string
	}{
		"no location":          {func(f *Finding) { f.Location = Location{} }, "neither a file nor an endpoint"},
		"absolute path":        {func(f *Finding) { f.Location.File = "/etc/passwd" }, "relative to the target root"},
		"backslash path":       {func(f *Finding) { f.Location.File = `app\db.py` }, "relative to the target root"},
		"parent path":          {func(f *Finding) { f.Location.File = "../x.py" }, "relative to the target root"},
		"unknown confidence":   {func(f *Finding) { f.Confidence.Level = "certain" }, "confidence"},
		"no confidence reason": {func(f *Finding) { f.Confidence.Reason = " " }, "confidence has no reason"},
		"demonstrated without artifact": {func(f *Finding) {
			f.Proof = Proof{Status: ProofDemonstrated, Result: "pwned"}
		}, "lists no artifact"},
		"demonstrated without result": {func(f *Finding) {
			f.Proof = Proof{Status: ProofDemonstrated, Artifacts: []string{"poc/test.py"}}
		}, "no captured result"},
		"confidence above proof": {func(f *Finding) { f.Confidence.Level = ConfidenceDemonstrated }, "confidence is demonstrated but proof"},
		"model-supplied score":   {func(f *Finding) { f.Severity.Score = 10 }, "does not match the vector"},
		"bad vector":             {func(f *Finding) { f.Severity.Vector = "CVSS:4.0/AV:Q" }, "severity vector"},
		"no vector, not flagged": {func(f *Finding) { f.Severity = Severity{Label: "high"} }, "not marked unscored"},
		"bad cwe":                {func(f *Finding) { f.CWE = []string{"89"} }, "CWE-<number>"},
		"bad surface":            {func(f *Finding) { f.Surface = "cloud" }, "surface"},
		"dismissed, no reason":   {func(f *Finding) { f.Status = StatusDismissed }, "no reason is recorded"},
		"no remediation":         {func(f *Finding) { f.Remediation.Summary = "" }, "remediation summary"},
		"line range reversed":    {func(f *Finding) { f.Location.EndLine = 3 }, "line range"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := valid()
			tc.mutate(&f)
			err := f.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	f := Finding{}
	err := f.Validate()
	if err == nil || strings.Count(err.Error(), "\n") < 5 {
		t.Fatalf("an empty finding should produce many problems, got: %v", err)
	}
}

func TestMakeIDIsStableAndDistinct(t *testing.T) {
	a := MakeID("sql-injection", Location{File: "a.py", StartLine: 3})
	b := MakeID("SQL-Injection", Location{File: "a.py", StartLine: 3})
	c := MakeID("sql-injection", Location{File: "a.py", StartLine: 4})
	if a != b || a == c || !strings.HasPrefix(a, "SPK-") || len(a) != 12 {
		t.Fatalf("a=%s b=%s c=%s", a, b, c)
	}
}

func TestLocationString(t *testing.T) {
	cases := map[string]Location{
		"app/db.py:12-14":           {File: "app/db.py", StartLine: 12, EndLine: 14},
		"app/db.py:12":              {File: "app/db.py", StartLine: 12, EndLine: 12},
		"GET /search (parameter q)": {Method: "GET", Endpoint: "/search", Parameter: "q"},
		"main.go:5, POST /login":    {File: "main.go", StartLine: 5, Method: "POST", Endpoint: "/login"},
	}
	for want, loc := range cases {
		if got := loc.String(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestRankOrder(t *testing.T) {
	mk := func(id, label string, score float64, conf, status string) Finding {
		return Finding{ID: id, Severity: Severity{Label: label, Score: score}, Confidence: Confidence{Level: conf}, Status: status}
	}
	in := []Finding{
		mk("E", "critical", 9.5, ConfidenceHigh, StatusDismissed),
		mk("D", "low", 2.0, ConfidenceHigh, StatusOpen),
		mk("C", "high", 8.0, ConfidencePlausible, StatusOpen),
		mk("B", "high", 8.0, ConfidenceDemonstrated, StatusOpen),
		mk("A", "critical", 9.3, ConfidenceHigh, StatusOpen),
		mk("F", "critical", 9.9, ConfidenceHigh, StatusFixed),
	}
	var got []string
	for _, f := range Rank(in) {
		got = append(got, f.ID)
	}
	if strings.Join(got, "") != "ABCDFE" {
		t.Fatalf("rank order = %v, want A B C D F E", got)
	}
	if in[0].ID != "E" {
		t.Fatal("Rank must not reorder its input")
	}
}

func TestDedupKeepsStrongerAndMergesOrigins(t *testing.T) {
	weak := valid()
	weak.Confidence = Confidence{Level: ConfidencePlausible, Reason: "lead"}
	weak.Origin = []string{"builtin"}
	strong := valid()
	strong.Origin = []string{"semgrep"}
	out := Dedup([]Finding{weak, strong})
	if len(out) != 1 || out[0].Confidence.Level != ConfidenceHigh || strings.Join(out[0].Origin, ",") != "builtin,semgrep" {
		t.Fatalf("%+v", out)
	}
}
