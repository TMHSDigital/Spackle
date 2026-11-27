package finding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// BaselineVersion is the format version a baseline file is written with.
const BaselineVersion = 1

// maxBaselineSize bounds the baseline file a scan reads.
const maxBaselineSize = 16 << 20

// Baseline is the file of accepted findings: a finding that matches an
// entry gets the status accepted, stays in every report, and does not fail
// the run.
type Baseline struct {
	Version int             `json:"version"`
	Entries []BaselineEntry `json:"entries"`
}

// BaselineEntry accepts one finding. It matches a finding with the same
// fingerprint, or, when either side has none, the same id. Title, class
// and location are there for the person reading the file.
type BaselineEntry struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Class       string `json:"class"`
	Title       string `json:"title"`
	Location    string `json:"location"`
	// Reason says why the finding is accepted.
	Reason string `json:"reason,omitempty"`
	// Expires is a date (YYYY-MM-DD). From that day on the entry no longer
	// accepts anything.
	Expires string `json:"expires,omitempty"`
}

// String names the entry the way notes cite it.
func (e BaselineEntry) String() string {
	return fmt.Sprintf("%s %s (%s)", e.ID, e.Title, e.Location)
}

// expired reports whether the entry no longer applies on day now.
func (e BaselineEntry) expired(now time.Time) bool {
	if e.Expires == "" {
		return false
	}
	d, err := time.Parse(time.DateOnly, e.Expires)
	return err == nil && !now.Before(d)
}

// Matches reports whether the entry accepts f, whether or not it expired.
func (e BaselineEntry) Matches(f Finding) bool {
	if e.Fingerprint != "" && f.Fingerprint != "" {
		return e.Fingerprint == f.Fingerprint
	}
	return e.ID != "" && e.ID == f.ID
}

// NewBaseline makes a baseline that accepts every unresolved finding of
// fs (open or with a patch available), with reason on each entry.
func NewBaseline(fs []Finding, reason string) Baseline {
	b := Baseline{Version: BaselineVersion, Entries: []BaselineEntry{}}
	for _, f := range fs {
		if f.Status != StatusOpen && f.Status != StatusPatchAvailable {
			continue
		}
		b.Entries = append(b.Entries, BaselineEntry{
			ID: f.ID, Fingerprint: f.Fingerprint, Class: f.Class, Title: f.Title,
			Location: f.Location.String(), Reason: reason,
		})
	}
	return b
}

// LoadBaseline reads and checks a baseline file.
func LoadBaseline(path string) (Baseline, error) {
	f, err := os.Open(path) //nolint:gosec // the operator named the baseline file
	if err != nil {
		return Baseline{}, fmt.Errorf("baseline: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxBaselineSize+1))
	if err != nil {
		return Baseline{}, fmt.Errorf("baseline %s: %w", path, err)
	}
	if len(raw) > maxBaselineSize {
		return Baseline{}, fmt.Errorf("baseline %s is larger than %d MiB", path, maxBaselineSize>>20)
	}
	return ParseBaseline(raw)
}

// ParseBaseline decodes a baseline and checks every entry.
func ParseBaseline(raw []byte) (Baseline, error) {
	var b Baseline
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Baseline{}, fmt.Errorf("baseline is not valid: %w", err)
	}
	if b.Version != BaselineVersion {
		return Baseline{}, fmt.Errorf("baseline version %d is not supported (want %d)", b.Version, BaselineVersion)
	}
	var errs []error
	for i, e := range b.Entries {
		if strings.TrimSpace(e.ID) == "" && strings.TrimSpace(e.Fingerprint) == "" {
			errs = append(errs, fmt.Errorf("entry %d has neither an id nor a fingerprint", i+1))
		}
		if e.Expires != "" {
			if _, err := time.Parse(time.DateOnly, e.Expires); err != nil {
				errs = append(errs, fmt.Errorf("entry %d: expires %q is not a date of the form YYYY-MM-DD", i+1, e.Expires))
			}
		}
	}
	if len(errs) > 0 {
		return Baseline{}, fmt.Errorf("baseline is not valid: %w", errors.Join(errs...))
	}
	return b, nil
}

// BaselineMatcher applies a baseline to the findings of one run and
// remembers which entries were used.
type BaselineMatcher struct {
	b    Baseline
	now  time.Time
	used []bool
}

// NewBaselineMatcher prepares b for a run on day now.
func NewBaselineMatcher(b Baseline, now time.Time) *BaselineMatcher {
	return &BaselineMatcher{b: b, now: now, used: make([]bool, len(b.Entries))}
}

// Apply sets f to accepted when an entry that has not expired matches it.
// Only an open finding or one with a patch available can be accepted. It
// reports whether f was accepted.
func (m *BaselineMatcher) Apply(f *Finding) bool {
	if m == nil || (f.Status != StatusOpen && f.Status != StatusPatchAvailable) {
		return false
	}
	for i, e := range m.b.Entries {
		if e.expired(m.now) || !e.Matches(*f) {
			continue
		}
		m.used[i] = true
		f.Status, f.AcceptReason = StatusAccepted, e.Reason
		if f.AcceptReason == "" {
			f.AcceptReason = "accepted in the baseline file"
		}
		return true
	}
	return false
}

// Unused returns the entries that matched no finding and have not expired
// (stale: the finding is gone or changed), and those that have expired.
func (m *BaselineMatcher) Unused() (stale, expired []BaselineEntry) {
	if m == nil {
		return nil, nil
	}
	for i, e := range m.b.Entries {
		switch {
		case e.expired(m.now):
			expired = append(expired, e)
		case !m.used[i]:
			stale = append(stale, e)
		}
	}
	return stale, expired
}
