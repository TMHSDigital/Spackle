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

// Comparison joins two runs on finding id and content fingerprint.
type Comparison struct {
	Older        string            `json:"older"`
	Newer        string            `json:"newer"`
	New          []ComparedFinding `json:"new"`
	Gone         []ComparedFinding `json:"gone"`
	StillPresent []ComparedFinding `json:"still_present"`
}

// Compare reports which findings are only in the newer run, only in the
// older run, or in both. Dismissed findings are left out on both sides.
// Findings are matched by id first. The id includes the line, so the
// findings left over are then matched by their content fingerprint, which
// does not: a finding whose code only moved to another line is still
// present, with the change "moved from <old location>". Runs stored before
// fingerprints existed are matched by id alone. spackle runs compare and
// the MCP compare_runs tool both use it.
func Compare(older, newer Run) Comparison {
	row := func(f finding.Finding) ComparedFinding {
		return ComparedFinding{ID: f.ID, Title: f.Title, Severity: f.Severity.Label, Location: f.Location.String(), Status: f.Status}
	}
	olds, news := older.Active(), newer.Active()
	pair := make([]int, len(news)) // index into olds, or -1
	used := make([]bool, len(olds))
	byID := map[string]int{}
	for i, f := range olds {
		if _, dup := byID[f.ID]; !dup {
			byID[f.ID] = i
		}
	}
	for i, f := range news {
		pair[i] = -1
		if j, ok := byID[f.ID]; ok && !used[j] {
			pair[i], used[j] = j, true
		}
	}
	byPrint := map[string][]int{}
	for j, f := range olds {
		if !used[j] && f.Fingerprint != "" {
			byPrint[f.Fingerprint] = append(byPrint[f.Fingerprint], j)
		}
	}
	for i, f := range news {
		if pair[i] >= 0 || f.Fingerprint == "" {
			continue
		}
		if js := byPrint[f.Fingerprint]; len(js) > 0 {
			pair[i], used[js[0]] = js[0], true
			byPrint[f.Fingerprint] = js[1:]
		}
	}

	c := Comparison{Older: older.ID, Newer: newer.ID, New: []ComparedFinding{}, Gone: []ComparedFinding{}, StillPresent: []ComparedFinding{}}
	for i, f := range news {
		if pair[i] < 0 {
			c.New = append(c.New, row(f))
			continue
		}
		old := olds[pair[i]]
		r := row(f)
		var changes []string
		if old.ID != f.ID {
			changes = append(changes, "moved from "+old.Location.String())
		}
		if old.Status != f.Status {
			changes = append(changes, "status "+old.Status+" to "+f.Status)
		}
		if old.Severity.Label != f.Severity.Label {
			changes = append(changes, "severity "+old.Severity.Label+" to "+f.Severity.Label)
		}
		r.Change = strings.Join(changes, ", ")
		c.StillPresent = append(c.StillPresent, r)
	}
	for j, f := range olds {
		if !used[j] {
			c.Gone = append(c.Gone, row(f))
		}
	}
	return c
}
