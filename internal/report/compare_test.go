package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/finding"
)

func cmpFinding(id, status, severity string) finding.Finding {
	return finding.Finding{ID: id, Title: id, Status: status, Severity: finding.Severity{Label: severity}}
}

func TestCompare(t *testing.T) {
	older := Run{ID: "old", Findings: []finding.Finding{
		cmpFinding("SPK-00000001", finding.StatusOpen, "high"),
		cmpFinding("SPK-00000002", finding.StatusOpen, "high"),
		cmpFinding("SPK-00000003", finding.StatusOpen, "high"),
		cmpFinding("SPK-00000004", finding.StatusDismissed, "low"),
		cmpFinding("SPK-00000005", finding.StatusOpen, "low"),
	}}
	newer := Run{ID: "new", Findings: []finding.Finding{
		cmpFinding("SPK-00000001", finding.StatusFixed, "high"),     // status change
		cmpFinding("SPK-00000002", finding.StatusFixed, "medium"),   // both change
		cmpFinding("SPK-00000003", finding.StatusDismissed, "high"), // dismissed now: gone
		cmpFinding("SPK-00000004", finding.StatusDismissed, "low"),  // dismissed in both: nowhere
		cmpFinding("SPK-00000005", finding.StatusOpen, "low"),       // unchanged
		cmpFinding("SPK-00000006", finding.StatusOpen, "medium"),    // new
	}}
	c := Compare(older, newer)
	changes := map[string]string{}
	for _, r := range c.StillPresent {
		changes[r.ID] = r.Change
	}
	want := map[string]string{
		"SPK-00000001": "status open to fixed",
		"SPK-00000002": "status open to fixed, severity high to medium",
		"SPK-00000005": "",
	}
	if len(changes) != len(want) {
		t.Fatalf("still present = %+v", c.StillPresent)
	}
	for id, w := range want {
		if got, ok := changes[id]; !ok || got != w {
			t.Errorf("%s: change = %q (present %v), want %q", id, got, ok, w)
		}
	}
	if len(c.New) != 1 || c.New[0].ID != "SPK-00000006" {
		t.Errorf("new = %+v", c.New)
	}
	if len(c.Gone) != 1 || c.Gone[0].ID != "SPK-00000003" {
		t.Errorf("gone = %+v, want the finding dismissed in the newer run", c.Gone)
	}

	// Two empty runs give empty lists, not null, in JSON.
	b, err := json.Marshal(Compare(Run{}, Run{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"older":"","newer":"","new":[],"gone":[],"still_present":[]}` {
		t.Errorf("empty comparison = %s", got)
	}
}

// SARIF carries the content fingerprint next to the id when a finding has
// one, and only the id otherwise.
func TestSARIFCarriesTheContentFingerprint(t *testing.T) {
	run := fixtureRun()
	run.Findings[0].Fingerprint = "0123456789abcdef"
	var b strings.Builder
	if err := Render("sarif", run, &b); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(b.String()), &log); err != nil {
		t.Fatal(err)
	}
	with, without := 0, 0
	for _, r := range log.Runs[0].Results {
		switch r.PartialFingerprints["spackle/content/v1"] {
		case "0123456789abcdef":
			with++
		case "":
			without++
		}
		if r.PartialFingerprints["spackle/v1"] == "" {
			t.Errorf("a result has no id fingerprint: %v", r.PartialFingerprints)
		}
	}
	if with != 1 || without != len(log.Runs[0].Results)-1 {
		t.Errorf("results with the content fingerprint = %d, without = %d", with, without)
	}
}

// A finding whose code moved to another line has a new id but the same
// fingerprint, so it is still present, with the old location in the
// change. A finding with a fingerprint nobody else has stays new, and
// findings without one are matched by id alone.
func TestCompareMatchesAMovedFindingByFingerprint(t *testing.T) {
	at := func(id, fp string, line int) finding.Finding {
		f := cmpFinding(id, finding.StatusOpen, "high")
		f.Fingerprint, f.Location = fp, finding.Location{File: "app/db.py", StartLine: line}
		return f
	}
	older := Run{ID: "old", Findings: []finding.Finding{
		at("SPK-0000000A", "fp-moved", 10),
		at("SPK-0000000B", "fp-same", 20),
		at("SPK-0000000C", "", 30),
		at("SPK-0000000D", "fp-gone", 40),
	}}
	newer := Run{ID: "new", Findings: []finding.Finding{
		at("SPK-000000AA", "fp-moved", 12), // moved down two lines
		at("SPK-0000000B", "fp-same", 20),  // unchanged
		at("SPK-000000CC", "", 32),         // moved, but no fingerprint
		at("SPK-000000EE", "fp-new", 50),   // new
	}}
	c := Compare(older, newer)
	present := map[string]string{}
	for _, r := range c.StillPresent {
		present[r.ID] = r.Change
	}
	if len(present) != 2 || present["SPK-000000AA"] != "moved from app/db.py:10" || present["SPK-0000000B"] != "" {
		t.Errorf("still present = %+v", c.StillPresent)
	}
	var newIDs, goneIDs []string
	for _, r := range c.New {
		newIDs = append(newIDs, r.ID)
	}
	for _, r := range c.Gone {
		goneIDs = append(goneIDs, r.ID)
	}
	if strings.Join(newIDs, ",") != "SPK-000000CC,SPK-000000EE" {
		t.Errorf("new = %v", newIDs)
	}
	if strings.Join(goneIDs, ",") != "SPK-0000000C,SPK-0000000D" {
		t.Errorf("gone = %v", goneIDs)
	}
}
