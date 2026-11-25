package report

import (
	"encoding/json"
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
