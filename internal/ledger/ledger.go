// Package ledger implements the append-only evidence ledger that every run
// writes and every report is rendered from.
//
// The ledger is a JSON Lines file. Each line is one Event. Events are only
// ever appended: nothing in Spackle rewrites or truncates a ledger.
package ledger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileName is the ledger file inside a run directory.
const FileName = "ledger.jsonl"

// Event types. Data shapes are defined by the packages that emit them.
const (
	TypeRunStart     = "run.start"
	TypeMap          = "map"
	TypeLead         = "lead"
	TypeSeeder       = "seeder"
	TypeModelCall    = "model.call"
	TypeToolCall     = "tool.call"
	TypeSandboxRun   = "sandbox.run"
	TypeHTTPExchange = "http.exchange"
	TypeFinding      = "finding.upsert"
	TypeVerdict      = "verdict"
	TypeReject       = "draft.reject"
	TypeBudgetSkip   = "budget.skip"
	TypeNote         = "note"
	TypeRunEnd       = "run.end"
)

// Event is one ledger line.
type Event struct {
	Seq    int64           `json:"seq"`
	TS     time.Time       `json:"ts"`
	Parent int64           `json:"parent,omitempty"`
	Type   string          `json:"type"`
	Data   json.RawMessage `json:"data"`
}

// Decode unmarshals the event data into v.
func (e Event) Decode(v any) error {
	if err := json.Unmarshal(e.Data, v); err != nil {
		return fmt.Errorf("ledger event %d (%s): %w", e.Seq, e.Type, err)
	}
	return nil
}

// Writer appends events to a ledger. It is safe for concurrent use.
type Writer struct {
	mu    sync.Mutex
	f     *os.File
	seq   int64
	clock func() time.Time
}

// Create starts a new ledger in dir, which must not already contain one.
// clock supplies event timestamps; nil means time.Now.
func Create(dir string, clock func() time.Time) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create run directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, FileName)
	// O_EXCL: a ledger is never overwritten. O_APPEND: every write lands at
	// the end even if something else holds the file open.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600) //nolint:gosec // path is built from the run directory
	if err != nil {
		return nil, fmt.Errorf("create ledger %s: %w", path, err)
	}
	return &Writer{f: f, clock: orNow(clock)}, nil
}

// Open reopens an existing ledger for appending, continuing its sequence.
// It is used by commands that add to a finished run, such as verify.
func Open(dir string, clock func() time.Time) (*Writer, error) {
	events, err := Read(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, FileName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // path is built from the run directory
	if err != nil {
		return nil, fmt.Errorf("open ledger %s: %w", path, err)
	}
	w := &Writer{f: f, clock: orNow(clock)}
	if n := len(events); n > 0 {
		w.seq = events[n-1].Seq
	}
	return w, nil
}

func orNow(clock func() time.Time) func() time.Time {
	if clock == nil {
		return time.Now
	}
	return clock
}

// Append writes one event and returns its sequence number. parent is the
// sequence number of the event that caused this one, or 0 for none.
func (w *Writer) Append(parent int64, typ string, data any) (int64, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return 0, fmt.Errorf("encode %s event: %w", typ, err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, errors.New("ledger is closed")
	}
	ev := Event{Seq: w.seq + 1, TS: w.clock().UTC(), Parent: parent, Type: typ, Data: raw}
	line, err := json.Marshal(ev)
	if err != nil {
		return 0, fmt.Errorf("encode %s event: %w", typ, err)
	}
	line = append(line, '\n')
	if _, err := w.f.Write(line); err != nil {
		return 0, fmt.Errorf("append to ledger: %w", err)
	}
	w.seq = ev.Seq
	return ev.Seq, nil
}

// Close flushes and closes the ledger.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	w.f = nil
	return err
}

// Read loads every event from the ledger in dir, in order. A malformed or
// out-of-sequence line is an error that names the line, because a damaged
// ledger must not render a report silently.
func Read(dir string) ([]Event, error) {
	path := filepath.Join(dir, FileName)
	raw, err := os.ReadFile(path) //nolint:gosec // path is built from the run directory
	if err != nil {
		return nil, fmt.Errorf("read ledger %s: %w", path, err)
	}
	var events []Event
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("ledger %s line %d is not valid JSON (%w): the file is truncated or was edited; re-run the scan to produce a clean ledger", path, lineNo, err)
		}
		if want := int64(len(events) + 1); ev.Seq != want {
			return nil, fmt.Errorf("ledger %s line %d has sequence %d, want %d: events are missing or reordered", path, lineNo, ev.Seq, want)
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read ledger %s: %w", path, err)
	}
	return events, nil
}
