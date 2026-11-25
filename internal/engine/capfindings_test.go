package engine

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
)

func TestCapFindings(t *testing.T) {
	// Five ranked findings, F1 the highest.
	var fs []finding.Finding
	for i := 1; i <= 5; i++ {
		fs = append(fs, finding.Finding{ID: fmt.Sprintf("F%d", i), Title: "t", Location: finding.Location{File: "a.py", StartLine: i}})
	}
	ids := func(fs []finding.Finding) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.ID)
		}
		return out
	}
	rec := func(ids ...string) map[string]bool {
		m := map[string]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	for _, c := range []struct {
		name     string
		recorded map[string]bool
		limit    int
		kept     []string
		dropped  int
		over     int
	}{
		{"no limit", nil, 0, []string{"F1", "F2", "F3", "F4", "F5"}, 0, 0},
		{"within the limit", nil, 5, []string{"F1", "F2", "F3", "F4", "F5"}, 0, 0},
		{"the highest ranked fill the room", nil, 2, []string{"F1", "F2"}, 3, 0},
		{"recorded ones are kept whatever their rank", rec("F5"), 2, []string{"F1", "F5"}, 3, 0},
		{"recorded ones fill the limit exactly", rec("F4", "F5"), 2, []string{"F4", "F5"}, 3, 0},
		{"recorded ones alone exceed the limit", rec("F2", "F3", "F4"), 2, []string{"F2", "F3", "F4"}, 2, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			kept, dropped, over := capFindings(fs, c.recorded, c.limit)
			// Equal-ranked findings keep their order, so the ids are
			// compared as a set.
			got := map[string]bool{}
			for _, id := range ids(kept) {
				got[id] = true
			}
			if !reflect.DeepEqual(got, rec(c.kept...)) || len(kept) != len(c.kept) || len(dropped) != c.dropped || over != c.over {
				t.Fatalf("kept %v, dropped %d, over %d; want %v, %d, %d", ids(kept), len(dropped), over, c.kept, c.dropped, c.over)
			}
		})
	}
}

// When findings that persist already wrote exceed the cap on their own,
// they are all kept and a note says the report holds more than the cap.
func TestRecordFindingsNotesARecordedSetOverTheCap(t *testing.T) {
	dir := t.TempDir()
	led, err := ledger.Create(dir, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	cfg := config.Default()
	cfg.Budget.MaxFindings = 1
	r := &runner{cfg: cfg, led: led, runDir: dir}

	a := FromLead(sqlLead(), "not investigated")
	b := a
	b.ID = "SPK-BBBBBBBB"
	for _, f := range []finding.Finding{a, b} {
		if err := r.persist(0, f); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.recordFindings(0, []finding.Finding{a, b}, nil); err != nil {
		t.Fatal(err)
	}
	var notes []string
	for _, e := range ledgerEvents(t, dir) {
		var n string
		if e.Type == ledger.TypeNote && e.Decode(&n) == nil {
			notes = append(notes, n)
		}
	}
	if !containsNote(notes, "2 findings were already recorded when the max findings cap of 1 applied, so the report holds 1 more than the cap.") {
		t.Fatalf("notes = %q", notes)
	}
}
