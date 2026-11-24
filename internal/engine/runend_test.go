package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/report"
)

// runEnds returns the run.end events of a stored run.
func runEnds(t *testing.T, runDir string) []ledger.RunEnd {
	t.Helper()
	events, err := ledger.Read(runDir)
	if err != nil {
		t.Fatal(err)
	}
	var ends []ledger.RunEnd
	for _, e := range events {
		if e.Type == ledger.TypeRunEnd {
			var end ledger.RunEnd
			if err := e.Decode(&end); err != nil {
				t.Fatal(err)
			}
			ends = append(ends, end)
		}
	}
	return ends
}

// openRun gives a runner with an open ledger that holds a run.start event,
// as every mode has once its run directory exists.
func openRun(t *testing.T) (*runner, int64) {
	t.Helper()
	runDir := filepath.Join(t.TempDir(), "runs", "20261122-120000-abcdef")
	led, err := ledger.Create(runDir, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	seq, err := led.Append(0, ledger.TypeRunStart, ledger.RunStart{RunID: "20261122-120000-abcdef", Command: "scan", Mode: "deterministic"})
	if err != nil {
		t.Fatal(err)
	}
	return &runner{led: led, runDir: runDir, runID: "20261122-120000-abcdef"}, seq
}

// Any error after the ledger is open ends the run with one run.end event,
// so the run loads as failed and not as incomplete (a process that died).
func TestAnErrorAfterTheLedgerIsOpenEndsTheRun(t *testing.T) {
	r, _ := openRun(t)
	run := func() (err error) {
		defer r.endOnError(&err)
		return errors.New("the disk is full")
	}
	if err := run(); err == nil {
		t.Fatal("the error was swallowed")
	}
	// A second report of the same failure, by an explicit fail or by an
	// outer deferred call, adds nothing.
	_ = r.fail(errors.New("again"))
	again := errors.New("and again")
	r.endOnError(&again)

	ends := runEnds(t, r.runDir)
	if len(ends) != 1 || ends[0].Outcome != "failed" || ends[0].Note != "the disk is full" {
		t.Fatalf("run.end events = %+v, want one failed event with the first error", ends)
	}
	if err := r.led.Close(); err != nil {
		t.Fatal(err)
	}
	loaded, err := report.Load(r.runDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Outcome != "failed" {
		t.Fatalf("outcome = %q, want failed", loaded.Outcome)
	}
}

// A run that ends normally has exactly its own run.end, also when an error
// turns up afterwards while the reports are written.
func TestARunThatEndedIsNotMarkedFailed(t *testing.T) {
	r, startSeq := openRun(t)
	var none error
	r.endOnError(&none)
	if ends := runEnds(t, r.runDir); len(ends) != 0 {
		t.Fatalf("a run without an error got a run.end: %+v", ends)
	}
	res, err := r.end(startSeq, "completed")
	if err != nil {
		t.Fatal(err)
	}
	late := errors.New("a report could not be written")
	r.endOnError(&late)
	if ends := runEnds(t, r.runDir); len(ends) != 1 || ends[0].Outcome != "completed" {
		t.Fatalf("run.end events = %+v, want the one completed event", ends)
	}
	if res.Run.Outcome != "completed" || res.RunID != r.runID {
		t.Fatalf("result = %s %s", res.RunID, res.Run.Outcome)
	}
}

// End to end: an authorized running target that does not answer fails the
// run after its ledger was opened. The stored run says so, once.
func TestAFailedLiveRunIsStoredAsFailed(t *testing.T) {
	app := httptest.NewServer(http.NotFoundHandler())
	url := app.URL
	app.Close() // authorized, and no longer there
	o := liveOpts(t, url)
	o.ScopeFile = scopeFile(t, url)
	o.Yes = true
	if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "could not be probed") {
		t.Fatalf("err = %v, want the probe failure", err)
	}
	runDir := filepath.Join(RunsDir(o.Config.StateDir), o.RunID)
	ends := runEnds(t, runDir)
	if len(ends) != 1 || ends[0].Outcome != "failed" || !strings.Contains(ends[0].Note, "could not be probed") {
		t.Fatalf("run.end events = %+v, want one failed event", ends)
	}
	loaded, err := report.Load(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Outcome != "failed" {
		t.Fatalf("outcome = %q, want failed", loaded.Outcome)
	}
}
