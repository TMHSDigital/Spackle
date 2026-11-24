package report

import (
	"strings"

	"github.com/TMHSDigital/spackle/internal/finding"
)

// ComparedFinding is one finding in a comparison of two runs.
type ComparedFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Location string `json:"location"`
	Status   string `json:"status"`
	// Change says what differs from the older run, for a finding in both.
	Change string `json:"change,omitempty"`
}

// Comparison joins two runs on finding id.
type Comparison struct {
	Older        string            `json:"older"`
	Newer        string            `json:"newer"`
	New          []ComparedFinding `json:"new"`
	Gone         []ComparedFinding `json:"gone"`
	StillPresent []ComparedFinding `json:"still_present"`
}

// Compare reports which findings are only in the newer run, only in the
// older run, or in both. Dismissed findings are left out on both sides. A
// finding id is made from the class, the place and, for a rule finding, the
// rule, so code that moved to another line shows as one gone and one new.
// spackle runs compare and the MCP compare_runs tool both use it.
func Compare(older, newer Run) Comparison {
	row := func(f finding.Finding) ComparedFinding {
		return ComparedFinding{ID: f.ID, Title: f.Title, Severity: f.Severity.Label, Location: f.Location.String(), Status: f.Status}
	}
	before := map[string]finding.Finding{}
	for _, f := range older.Active() {
		before[f.ID] = f
	}
	c := Comparison{Older: older.ID, Newer: newer.ID, New: []ComparedFinding{}, Gone: []ComparedFinding{}, StillPresent: []ComparedFinding{}}
	seen := map[string]bool{}
	for _, f := range newer.Active() {
		seen[f.ID] = true
		old, ok := before[f.ID]
		if !ok {
			c.New = append(c.New, row(f))
			continue
		}
		r := row(f)
		var changes []string
		if old.Status != f.Status {
			changes = append(changes, "status "+old.Status+" to "+f.Status)
		}
		if old.Severity.Label != f.Severity.Label {
			changes = append(changes, "severity "+old.Severity.Label+" to "+f.Severity.Label)
		}
		r.Change = strings.Join(changes, ", ")
		c.StillPresent = append(c.StillPresent, r)
	}
	for _, f := range older.Active() {
		if !seen[f.ID] {
			c.Gone = append(c.Gone, row(f))
		}
	}
	return c
}
