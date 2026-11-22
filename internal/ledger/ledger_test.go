package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func TestAppendAndReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w, err := Create(dir, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	s1, err := w.Append(0, TypeRunStart, map[string]string{"target": "./app"})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := w.Append(s1, TypeLead, map[string]int{"line": 7})
	if err != nil {
		t.Fatal(err)
	}
	if s1 != 1 || s2 != 2 {
		t.Fatalf("seq = %d, %d; want 1, 2", s1, s2)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Parent != 1 || events[1].Type != TypeLead {
		t.Fatalf("events = %+v", events)
	}
	var data map[string]int
	if err := events[1].Decode(&data); err != nil || data["line"] != 7 {
		t.Fatalf("decode: %v %v", data, err)
	}
	if got := events[0].TS.Format(time.RFC3339); got != "2026-11-22T12:00:01Z" {
		t.Fatalf("timestamp = %s", got)
	}
}

func TestDeterministicBytesWithInjectedClock(t *testing.T) {
	write := func() []byte {
		dir := t.TempDir()
		w, err := Create(dir, fixedClock())
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if _, err := w.Append(0, TypeNote, map[string]any{"b": 2, "a": i}); err != nil {
				t.Fatal(err)
			}
		}
		_ = w.Close()
		b, err := os.ReadFile(filepath.Join(dir, FileName))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if a, b := write(), write(); string(a) != string(b) {
		t.Fatalf("ledger bytes differ between identical runs:\n%s\n%s", a, b)
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	w, err := Create(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if _, err := Create(dir, nil); err == nil {
		t.Fatal("Create over an existing ledger must fail")
	}
}

func TestOpenContinuesSequence(t *testing.T) {
	dir := t.TempDir()
	w, _ := Create(dir, nil)
	_, _ = w.Append(0, TypeNote, "one")
	_ = w.Close()
	w2, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	seq, err := w2.Append(0, TypeNote, "two")
	_ = w2.Close()
	if err != nil || seq != 2 {
		t.Fatalf("seq=%d err=%v", seq, err)
	}
}

func TestReadReportsTruncatedLine(t *testing.T) {
	dir := t.TempDir()
	w, _ := Create(dir, nil)
	_, _ = w.Append(0, TypeNote, "ok")
	_ = w.Close()
	path := filepath.Join(dir, FileName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"seq":2,"ts":"2026-11-22T12:00:00Z","type":"no`)
	_ = f.Close()

	_, err = Read(dir)
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "re-run") {
		t.Fatalf("want an error naming line 2 and a next step, got %v", err)
	}
}

func TestReadDetectsMissingEvent(t *testing.T) {
	dir := t.TempDir()
	body := `{"seq":1,"ts":"2026-11-22T12:00:00Z","type":"note","data":1}` + "\n" +
		`{"seq":3,"ts":"2026-11-22T12:00:01Z","type":"note","data":2}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), "sequence 3, want 2") {
		t.Fatalf("got %v", err)
	}
}

func TestReadToleratesCRLF(t *testing.T) {
	dir := t.TempDir()
	body := `{"seq":1,"ts":"2026-11-22T12:00:00Z","type":"note","data":1}` + "\r\n"
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if events, err := Read(dir); err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
}

func TestConcurrentAppendKeepsSequenceDense(t *testing.T) {
	dir := t.TempDir()
	w, _ := Create(dir, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.Append(0, TypeNote, i); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	_ = w.Close()
	events, err := Read(dir)
	if err != nil || len(events) != 50 {
		t.Fatalf("len=%d err=%v", len(events), err)
	}
}

func TestAppendAfterCloseFails(t *testing.T) {
	w, _ := Create(t.TempDir(), nil)
	_ = w.Close()
	if _, err := w.Append(0, TypeNote, 1); err == nil {
		t.Fatal("Append after Close must fail")
	}
}
