package seed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/walk"
)

// eachFile gives the same leads in the same order however the workers are
// scheduled, and reports the first error in file order.
func TestEachFileIsDeterministic(t *testing.T) {
	files := make([]walk.File, 200)
	for i := range files {
		files[i] = walk.File{Rel: fmt.Sprintf("f%03d.py", i)}
	}
	check := func(f walk.File) ([]Lead, error) {
		if f.Rel == "f007.py" || f.Rel == "f151.py" {
			return nil, errors.New("cannot read " + f.Rel)
		}
		if strings.HasSuffix(f.Rel, "0.py") {
			return nil, nil
		}
		return []Lead{{File: f.Rel, Line: 1}, {File: f.Rel, Line: 2}}, nil
	}
	for round := 0; round < 5; round++ {
		leads, err := eachFile(context.Background(), "test", files, check)
		if err == nil || err.Error() != "cannot read f007.py" {
			t.Fatalf("err = %v, want the first error in file order", err)
		}
		if len(leads) != (200-20-2)*2 {
			t.Fatalf("leads = %d", len(leads))
		}
		for i := 1; i < len(leads); i++ {
			a, b := leads[i-1], leads[i]
			if a.File > b.File || (a.File == b.File && a.Line > b.Line) {
				t.Fatalf("leads are not in file order at %d: %s:%d then %s:%d", i, a.File, a.Line, b.File, b.Line)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := eachFile(ctx, "test", files, check); err == nil || !strings.Contains(err.Error(), "stopped early") {
		t.Fatalf("a cancelled run returned %v", err)
	}
	if leads, err := eachFile(context.Background(), "test", nil, check); err != nil || len(leads) != 0 {
		t.Fatalf("no files: leads=%d err=%v", len(leads), err)
	}
}

type manyLeads struct{ leads []Lead }

func (manyLeads) Name() string              { return "many" }
func (manyLeads) Available() (bool, string) { return true, "" }
func (m manyLeads) Run(context.Context, string, []walk.File) ([]Lead, error) {
	return m.leads, nil
}

// One rule that matches thousands of lines of a generated file must not
// bury the report, and the drop must be visible in the seeder's status.
func TestLeadCapsAreAppliedAndReported(t *testing.T) {
	var leads []Lead
	for line := 1; line <= 3000; line++ {
		leads = append(leads, Lead{RuleID: "noisy", Class: "debug-enabled", File: "gen/big.js", Line: line, Title: "t", Detail: "d", Fix: "f"})
	}
	leads = append(leads, Lead{RuleID: "real", Class: "sql-injection", File: "app.py", Line: 4, Title: "t", Detail: "d", Fix: "f"})
	got, statuses := RunAll(context.Background(), []Seeder{manyLeads{leads}}, "", nil)
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
	got, statuses = RunAll(context.Background(), []Seeder{manyLeads{leads}}, "", nil)
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
