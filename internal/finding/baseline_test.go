package finding

import (
	"strings"
	"testing"
	"time"
)

func TestNewBaselineTakesOnlyUnresolvedFindings(t *testing.T) {
	open := valid()
	open.Fingerprint = "00000000000000aa"
	patched := valid()
	patched.ID, patched.Status = "SPK-00000002", StatusPatchAvailable
	fixed := valid()
	fixed.ID, fixed.Status = "SPK-00000003", StatusFixed
	dismissed := valid()
	dismissed.ID, dismissed.Status, dismissed.DismissReason = "SPK-00000004", StatusDismissed, "refuted"

	b := NewBaseline([]Finding{open, patched, fixed, dismissed}, "legacy code")
	if b.Version != BaselineVersion || len(b.Entries) != 2 {
		t.Fatalf("baseline = %+v", b)
	}
	e := b.Entries[0]
	if e.ID != open.ID || e.Fingerprint != "00000000000000aa" || e.Class != "sql-injection" || e.Location != "app/db.py:12-14" || e.Reason != "legacy code" {
		t.Errorf("entry = %+v", e)
	}
	if b.Entries[1].ID != "SPK-00000002" {
		t.Errorf("second entry = %+v", b.Entries[1])
	}
}

func TestParseBaselineRejectsBadFiles(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":      `{`,
		"wrong version": `{"version": 2, "entries": []}`,
		"unknown field": `{"version": 1, "entries": [], "extra": true}`,
		"empty entry":   `{"version": 1, "entries": [{"title": "x"}]}`,
		"bad expiry":    `{"version": 1, "entries": [{"id": "SPK-00000001", "expires": "next week"}]}`,
	} {
		if _, err := ParseBaseline([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseBaseline([]byte(`{"version": 1, "entries": [{"id": "SPK-00000001", "expires": "2027-01-31"}]}`)); err != nil {
		t.Errorf("a valid baseline was refused: %v", err)
	}
}

// An entry matches by fingerprint when both sides have one, and by id
// otherwise. Only open findings and findings with a patch are accepted,
// an expired entry accepts nothing, and the entries left over are listed.
func TestBaselineMatcher(t *testing.T) {
	b := Baseline{Version: 1, Entries: []BaselineEntry{
		{ID: "SPK-OLDLINE1", Fingerprint: "fp-moved", Reason: "known"}, // the finding moved: new id, same fingerprint
		{ID: "SPK-00000002"},                          // matched by id, no reason given
		{ID: "SPK-00000003", Fingerprint: "fp-stale"}, // matches nothing
		{ID: "SPK-00000004", Expires: "2026-11-27"},   // expired today
		{ID: "SPK-00000005", Fingerprint: "fp-other"}, // same id, other fingerprint: no match
	}}
	m := NewBaselineMatcher(b, time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC))
	mk := func(id, fp, status string) *Finding {
		f := valid()
		f.ID, f.Fingerprint, f.Status = id, fp, status
		return &f
	}
	moved := mk("SPK-NEWLINE1", "fp-moved", StatusOpen)
	byID := mk("SPK-00000002", "", StatusPatchAvailable)
	expired := mk("SPK-00000004", "", StatusOpen)
	otherFP := mk("SPK-00000005", "fp-changed", StatusOpen)
	fixed := mk("SPK-00000002", "", StatusFixed)

	if !m.Apply(moved) || moved.Status != StatusAccepted || moved.AcceptReason != "known" {
		t.Errorf("moved finding: %s %q", moved.Status, moved.AcceptReason)
	}
	if !m.Apply(byID) || byID.Status != StatusAccepted || !strings.Contains(byID.AcceptReason, "baseline") {
		t.Errorf("finding matched by id: %s %q", byID.Status, byID.AcceptReason)
	}
	for name, f := range map[string]*Finding{"expired": expired, "other fingerprint": otherFP, "fixed": fixed} {
		if m.Apply(f) || f.Status == StatusAccepted {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := moved.Validate(); err != nil {
		t.Errorf("an accepted finding does not validate: %v", err)
	}
	stale, exp := m.Unused()
	if len(stale) != 2 || stale[0].ID != "SPK-00000003" || stale[1].ID != "SPK-00000005" {
		t.Errorf("stale = %+v", stale)
	}
	if len(exp) != 1 || exp[0].ID != "SPK-00000004" {
		t.Errorf("expired = %+v", exp)
	}
	var none *BaselineMatcher
	if none.Apply(mk("SPK-00000009", "", StatusOpen)) {
		t.Error("a nil matcher accepted a finding")
	}
}
