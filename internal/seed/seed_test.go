package seed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/walk"
)

// testSeeder is a file seeder for tests: it handles the files that wants
// accepts and reports one lead per line of text.
type testSeeder struct {
	name  string
	wants func(f walk.File) bool
}

func (s testSeeder) Name() string            { return s.name }
func (testSeeder) Available() (bool, string) { return true, "" }
func (s testSeeder) label() string           { return s.name }
func (s testSeeder) Run(ctx context.Context, _ string, files []walk.File) ([]Lead, error) {
	return runAlone(ctx, s, files)
}

func (s testSeeder) checks() func(walk.File) func(string) []Lead {
	return func(f walk.File) func(string) []Lead {
		if !s.wants(f) {
			return nil
		}
		return func(text string) []Lead {
			var leads []Lead
			for n := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
				leads = append(leads, Lead{RuleID: s.name, File: f.Rel, Line: n + 1})
			}
			return leads
		}
	}
}

// The shared pass gives each seeder the same leads in the same order
// however the workers are scheduled, and its own first read error in file
// order, without hiding the leads of the other files.
func TestRunFilesIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	files := make([]walk.File, 200)
	for i := range files {
		rel := fmt.Sprintf("f%03d.py", i)
		files[i] = walk.File{Rel: rel, Abs: filepath.Join(dir, rel)}
		if i == 7 || i == 151 {
			continue // listed but gone: the read fails
		}
		if err := os.WriteFile(files[i].Abs, []byte("a\nb\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	all := testSeeder{name: "all", wants: func(f walk.File) bool { return !strings.HasSuffix(f.Rel, "0.py") }}
	late := testSeeder{name: "late", wants: func(f walk.File) bool { return f.Rel >= "f100.py" }}
	none := testSeeder{name: "none", wants: func(walk.File) bool { return false }}
	for round := 0; round < 5; round++ {
		runs := runFiles(context.Background(), []fileSeeder{all, late, none}, files, nil)
		if err := runs[0].err; err == nil || !strings.Contains(err.Error(), "all could not read f007.py") {
			t.Fatalf("all: err = %v, want its first error in file order", err)
		}
		if err := runs[1].err; err == nil || !strings.Contains(err.Error(), "late could not read f151.py") {
			t.Fatalf("late: err = %v, want the first error among the files it handles", err)
		}
		if runs[2].err != nil || len(runs[2].leads) != 0 {
			t.Fatalf("none: leads = %d, err = %v", len(runs[2].leads), runs[2].err)
		}
		if n := len(runs[0].leads); n != (200-20-2)*2 {
			t.Fatalf("all: leads = %d", n)
		}
		if n := len(runs[1].leads); n != (100-1)*2 {
			t.Fatalf("late: leads = %d", n)
		}
		for _, r := range runs {
			for i := 1; i < len(r.leads); i++ {
				a, b := r.leads[i-1], r.leads[i]
				if a.File > b.File || (a.File == b.File && a.Line > b.Line) {
					t.Fatalf("leads are not in file order at %d: %s:%d then %s:%d", i, a.File, a.Line, b.File, b.Line)
				}
			}
		}
	}
	if runs := runFiles(context.Background(), []fileSeeder{all}, nil, nil); runs[0].err != nil || len(runs[0].leads) != 0 {
		t.Fatalf("no files: leads=%d err=%v", len(runs[0].leads), runs[0].err)
	}
}

// A file is read once for every seeder that handles it, a text an earlier
// stage kept is used instead of the disk, and a file that no seeder handles
// is not read at all.
func TestRunFilesReadsAFileOnce(t *testing.T) {
	dir := t.TempDir()
	onDisk := walk.File{Rel: "disk.py", Abs: filepath.Join(dir, "disk.py")}
	if err := os.WriteFile(onDisk.Abs, []byte("1\r\n2\r\n3\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Neither of these exists on disk, so a read of one would fail.
	kept := walk.File{Rel: "kept.py", Abs: filepath.Join(dir, "kept.py")}
	unwanted := walk.File{Rel: "unwanted.bin", Abs: filepath.Join(dir, "unwanted.bin")}
	texts := walk.NewTexts()
	texts.Put(kept.Abs, "x\ny\n")

	py := func(f walk.File) bool { return strings.HasSuffix(f.Rel, ".py") }
	a, b := testSeeder{name: "a", wants: py}, testSeeder{name: "b", wants: py}
	leads, statuses := RunAll(context.Background(), []Seeder{a, manyLeads{[]Lead{{RuleID: "other", File: "o.py", Line: 1}}}, b}, dir, []walk.File{onDisk, kept, unwanted}, texts)
	for _, st := range statuses {
		if st.Error != "" {
			t.Fatalf("%s: %s", st.Name, st.Error)
		}
	}
	if statuses[0].Leads != 5 || statuses[1].Leads != 1 || statuses[2].Leads != 5 || len(leads) != 11 {
		t.Fatalf("statuses = %+v, leads = %d", statuses, len(leads))
	}
	for _, l := range leads {
		if l.Source == "" || l.ID == "" {
			t.Fatalf("lead was not finalized: %+v", l)
		}
	}
	if _, ok := texts.Get(kept.Abs); ok {
		t.Error("the kept text was not released after it was used")
	}
}

// A context that is already done must always win: no file is handed to a
// worker and the cancellation is reported, also for a single file, where a
// worker is ready at the same moment.
func TestEachFileHandsOutNothingAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, n := range []int{1, 2, 64} {
		files := make([]walk.File, n)
		for round := 0; round < 200; round++ {
			var checked atomic.Int32
			_, covered := eachFile(ctx, files, func(walk.File) bool {
				checked.Add(1)
				return true
			})
			if covered {
				t.Fatalf("%d files, round %d: a cancelled run was reported as complete", n, round)
			}
			if got := checked.Load(); got != 0 {
				t.Fatalf("%d files, round %d: %d files were checked after the cancellation", n, round, got)
			}
		}
		everything := testSeeder{name: "everything", wants: func(walk.File) bool { return true }}
		if _, err := everything.Run(ctx, "", files); err == nil || !strings.Contains(err.Error(), "everything stopped early") || !errors.Is(err, context.Canceled) {
			t.Fatalf("%d files: err = %v, want the cancellation", n, err)
		}
	}
}

// A run that covered every file is complete, even when the context ends
// just after the last file was handed out.
func TestEachFileThatCoveredEverythingIsNotStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	files := make([]walk.File, 3)
	var checked atomic.Int32
	results, covered := eachFile(ctx, files, func(walk.File) bool {
		if checked.Add(1) == int32(len(files)) {
			cancel()
		}
		return true
	})
	if !covered || len(results) != len(files) {
		t.Fatalf("results = %v, covered = %v", results, covered)
	}
	for i, done := range results {
		if !done {
			t.Fatalf("file %d was not checked", i)
		}
	}
}

type manyLeads struct{ leads []Lead }

func (manyLeads) Name() string              { return "many" }
func (manyLeads) Available() (bool, string) { return true, "" }
func (m manyLeads) Run(context.Context, string, []walk.File) ([]Lead, error) {
	return m.leads, nil
}

// rendezvous is a scanner that waits, while it runs, for the other one to
// start too. Run one after another, the first would give up waiting.
type rendezvous struct {
	name        string
	mine, other chan struct{}
}

func (r rendezvous) Name() string            { return r.name }
func (rendezvous) Available() (bool, string) { return true, "" }
func (r rendezvous) Run(context.Context, string, []walk.File) ([]Lead, error) {
	close(r.mine)
	select {
	case <-r.other:
		return []Lead{{RuleID: r.name, Class: "debug-enabled", File: r.name + ".py", Line: 1, Title: "t", Detail: "d", Fix: "f"}}, nil
	case <-time.After(10 * time.Second):
		return nil, errors.New(r.name + " ran alone: the other scanner never started while it ran")
	}
}

// External scanners are independent subprocesses, so they run side by side;
// the statuses still come back in seeder order.
func TestRunAllRunsScannersConcurrently(t *testing.T) {
	a, b := make(chan struct{}), make(chan struct{})
	seeders := []Seeder{rendezvous{"first", a, b}, rendezvous{"second", b, a}}
	leads, statuses := RunAll(context.Background(), seeders, "", nil, nil)
	if len(statuses) != 2 || statuses[0].Name != "first" || statuses[1].Name != "second" {
		t.Fatalf("statuses = %+v, want them in seeder order", statuses)
	}
	for _, st := range statuses {
		if st.Error != "" {
			t.Fatalf("%s: %s", st.Name, st.Error)
		}
	}
	if len(leads) != 2 {
		t.Fatalf("leads = %d, want one per scanner", len(leads))
	}
}

// One rule that matches thousands of lines of a generated file must not
// bury the report, and the drop must be visible in the seeder's status.
func TestLeadCapsAreAppliedAndReported(t *testing.T) {
	var leads []Lead
	for line := 1; line <= 3000; line++ {
		leads = append(leads, Lead{RuleID: "noisy", Class: "debug-enabled", File: "gen/big.js", Line: line, Title: "t", Detail: "d", Fix: "f"})
	}
	leads = append(leads, Lead{RuleID: "real", Class: "sql-injection", File: "app.py", Line: 4, Title: "t", Detail: "d", Fix: "f"})
	got, statuses := RunAll(context.Background(), []Seeder{manyLeads{leads}}, "", nil, nil)
	if len(got) != MaxLeadsPerRuleFile+1 {
		t.Fatalf("leads = %d, want %d", len(got), MaxLeadsPerRuleFile+1)
	}
	st := statuses[0]
	if st.Leads != MaxLeadsPerRuleFile+1 || !strings.Contains(st.Note, "2950 leads were not listed") || !strings.Contains(st.Note, "rule noisy in gen/big.js, 3000 matches") {
		t.Fatalf("status = %+v", st)
	}

	// The per-run cap: many files, each under the per-file cap.
	leads = nil
	for f := 0; f < 300; f++ {
		for line := 1; line <= 20; line++ {
			leads = append(leads, Lead{RuleID: "r", Class: "debug-enabled", File: fmt.Sprintf("f%d.py", f), Line: line, Title: "t", Detail: "d", Fix: "f"})
		}
	}
	got, statuses = RunAll(context.Background(), []Seeder{manyLeads{leads}}, "", nil, nil)
	if len(got) != MaxLeadsPerSeeder || !strings.Contains(statuses[0].Note, "1000 leads were not listed: a seeder reports at most") {
		t.Fatalf("leads = %d status = %+v", len(got), statuses[0])
	}
}

func TestLimitedBufferStopsAtItsLimit(t *testing.T) {
	b := &limitedBuffer{limit: 10}
	for _, chunk := range []string{"12345", "678", "9abcdef", "more"} {
		if n, err := b.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = %d, %v; a write must always succeed", chunk, n, err)
		}
	}
	if b.String() != "123456789a" || !b.truncated {
		t.Fatalf("buffer = %q truncated = %v", b.String(), b.truncated)
	}

	// os/exec fills a non-file Stdout with io.Copy, which uses ReadFrom when
	// the writer has one and so would skip the limit in Write.
	c := &limitedBuffer{limit: 10}
	if _, err := io.Copy(c, strings.NewReader("123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if c.String() != "123456789a" || !c.truncated {
		t.Fatalf("after io.Copy: buffer = %q truncated = %v", c.String(), c.truncated)
	}
}

// redactedLine visits only the matches on the line, and still redacts every
// one of them.
func TestRedactedLineWithManyMatches(t *testing.T) {
	key := func(i int) string { return fmt.Sprintf("AKIA%016d", i) }
	var b strings.Builder
	for i := 0; i < 2000; i++ {
		b.WriteString("a = \"" + key(i) + "\"; b = \"" + key(i+5000) + "\"\n")
	}
	text := b.String()
	leads := secretLeads("gen.py", text)
	if len(leads) != 4000 {
		t.Fatalf("leads = %d, want 4000", len(leads))
	}
	for _, l := range []Lead{leads[0], leads[1999], leads[3999]} {
		if strings.Contains(l.Snippet, "AKIA") || strings.Count(l.Snippet, "[REDACTED:") != 2 {
			t.Fatalf("line %d snippet = %q", l.Line, l.Snippet)
		}
	}
}

type notingSeeder struct{ manyLeads }

func (notingSeeder) Note() string { return "3 results were skipped: no Spackle class fits them." }

// What a seeder says about results it dropped must reach its status, which
// is what the report shows.
func TestRunAllKeepsTheSeedersNote(t *testing.T) {
	lead := Lead{RuleID: "r", Class: "sql-injection", File: "app.py", Line: 4, Title: "t", Detail: "d", Fix: "f"}
	_, statuses := RunAll(context.Background(), []Seeder{notingSeeder{manyLeads{[]Lead{lead}}}, manyLeads{[]Lead{lead}}}, "", nil, nil)
	if statuses[0].Note != "3 results were skipped: no Spackle class fits them." {
		t.Fatalf("note = %q", statuses[0].Note)
	}
	if statuses[1].Note != "" {
		t.Fatalf("a seeder with nothing to say got the note %q", statuses[1].Note)
	}
}

// In a diff scan the built-in rules read only the changed files, and the
// leads a scanner finds elsewhere are dropped before its cap, so they
// cannot crowd out a lead in a changed file.
func TestRunAllInKeepsOnlyTheChangedFiles(t *testing.T) {
	var many []Lead
	for f := 0; f < 300; f++ {
		for line := 1; line <= 20; line++ {
			many = append(many, Lead{RuleID: "r", Class: "debug-enabled", File: fmt.Sprintf("old%03d.py", f), Line: line, Title: "t", Detail: "d", Fix: "f"})
		}
	}
	if len(many) <= MaxLeadsPerSeeder {
		t.Fatalf("the test needs more than %d leads in unchanged files", MaxLeadsPerSeeder)
	}
	// Sorted last, so the cap would drop it if it applied first.
	changedLead := Lead{RuleID: "r", Class: "sql-injection", File: "zz_changed.py", Line: 3, Title: "t", Detail: "d", Fix: "f"}
	noFile := Lead{RuleID: "r", Class: "debug-enabled", Title: "t", Detail: "d", Fix: "f"}

	dir := t.TempDir()
	changed := walk.File{Rel: "zz_changed.py", Abs: filepath.Join(dir, "zz_changed.py")}
	if err := os.WriteFile(changed.Abs, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Not on disk: reading it would fail the built-in pass.
	unchanged := walk.File{Rel: "old000.py", Abs: filepath.Join(dir, "old000.py")}
	builtin := testSeeder{name: "builtin", wants: func(walk.File) bool { return true }}

	only := map[string]bool{"zz_changed.py": true}
	leads, statuses, leftOut := RunAllIn(context.Background(), []Seeder{manyLeads{append(append(many, changedLead), noFile)}, builtin}, dir, []walk.File{changed, unchanged}, nil, only)
	for _, st := range statuses {
		if st.Error != "" {
			t.Fatalf("%s: %s (a built-in rule read an unchanged file)", st.Name, st.Error)
		}
	}
	if leftOut != len(many)+1 || len(leads) != 2 {
		t.Fatalf("leftOut = %d, leads = %+v", leftOut, leads)
	}
	for _, l := range leads {
		if l.File != "zz_changed.py" {
			t.Fatalf("lead outside the changed files: %+v", l)
		}
	}
	if strings.Contains(statuses[0].Note, "not listed") {
		t.Fatalf("the cap applied to leads that were dropped anyway: %q", statuses[0].Note)
	}
}

// inFlight is an external scanner that counts how many run at once.
type inFlight struct {
	name      string
	available bool
	fail      bool
	now, max  *int32
}

func (s inFlight) Name() string { return s.name }
func (s inFlight) Available() (bool, string) {
	if !s.available {
		return false, "not installed"
	}
	return true, ""
}
func (s inFlight) Run(context.Context, string, []walk.File) ([]Lead, error) {
	if !s.available {
		panic(s.name + " ran although it is not available")
	}
	n := atomic.AddInt32(s.now, 1)
	for {
		m := atomic.LoadInt32(s.max)
		if n <= m || atomic.CompareAndSwapInt32(s.max, m, n) {
			break
		}
	}
	time.Sleep(50 * time.Millisecond)
	atomic.AddInt32(s.now, -1)
	if s.fail {
		return nil, errors.New(s.name + " broke")
	}
	return []Lead{{RuleID: s.name, Class: "debug-enabled", File: s.name + ".py", Line: 1, Title: "t", Detail: "d", Fix: "f"}}, nil
}

// At most maxConcurrentScanners external scanners run at once; a failure
// stays in its own status, an unavailable scanner never starts, and the
// statuses keep seeder order.
func TestRunAllCapsConcurrentScanners(t *testing.T) {
	var now, peak int32
	var seeders []Seeder
	for i := 0; i < 6; i++ {
		seeders = append(seeders, inFlight{name: fmt.Sprintf("s%d", i), available: i != 4, fail: i == 2, now: &now, max: &peak})
	}
	leads, statuses := RunAll(context.Background(), seeders, "", nil, nil)
	if peak != maxConcurrentScanners {
		t.Fatalf("at most %d scanners ran at once, want %d", peak, maxConcurrentScanners)
	}
	for i, st := range statuses {
		if st.Name != fmt.Sprintf("s%d", i) {
			t.Fatalf("statuses out of seeder order: %+v", statuses)
		}
		switch i {
		case 2:
			if !strings.Contains(st.Error, "s2 broke") || st.Leads != 0 {
				t.Errorf("failing scanner: %+v", st)
			}
		case 4:
			if st.Available || st.Leads != 0 {
				t.Errorf("unavailable scanner: %+v", st)
			}
		default:
			if st.Error != "" || st.Leads != 1 {
				t.Errorf("scanner %d: %+v", i, st)
			}
		}
	}
	if len(leads) != 4 {
		t.Fatalf("leads = %d, want 4", len(leads))
	}
}
