// Package seed produces leads: deterministic, model-free observations that
// start an investigation. A lead is not a verdict. Seeders are either
// built-in rule sets or adapters around an installed scanner.
package seed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/TMHSDigital/spackle/internal/walk"
)

// Lead is one observation from a seeder.
type Lead struct {
	ID      string   `json:"id"`              // stable; see (*Lead).Finalize
	Source  string   `json:"source"`          // seeder name: builtin-code, builtin-secrets, semgrep, ...
	RuleID  string   `json:"rule_id"`         // rule within the seeder
	Title   string   `json:"title"`           // short, specific, no trailing period
	Class   string   `json:"class"`           // a class known to finding.DefaultVector
	Surface string   `json:"surface"`         // finding.SurfaceCode, SurfaceInfra or SurfaceDAST
	CWE     []string `json:"cwe,omitempty"`   // "CWE-89"
	OWASP   []string `json:"owasp,omitempty"` // "A03:2021 Injection"
	// Severity is the seeder's hint: critical, high, medium or low.
	Severity string `json:"severity"`

	File    string `json:"file,omitempty"` // forward-slash, relative to the target root
	Line    int    `json:"line,omitempty"` // 1-based
	EndLine int    `json:"end_line,omitempty"`

	Method   string `json:"method,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Param    string `json:"param,omitempty"`

	// Snippet is the matched source or traffic, already redacted. It must
	// never contain a secret value.
	Snippet string `json:"snippet,omitempty"`
	Detail  string `json:"detail"` // what is wrong, in one or two sentences
	Fix     string `json:"fix"`    // the concrete remediation, in one or two sentences
	// Evidence names stored artifacts (for DAST, the exchange ids).
	Evidence []string `json:"evidence,omitempty"`
}

// Finalize sets the stable ID from the lead's identity. Seeders call it on
// every lead before returning.
func (l *Lead) Finalize() {
	key := strings.Join([]string{l.Source, l.RuleID, l.File, fmt.Sprint(l.Line), l.Method, l.Endpoint, l.Param}, "\x00")
	sum := sha256.Sum256([]byte(key))
	l.ID = "L-" + hex.EncodeToString(sum[:5])
}

// Seeder produces leads for a target on disk.
type Seeder interface {
	// Name is the stable seeder name used in Lead.Source and in doctor output.
	Name() string
	// Available reports whether the seeder can run here, with a note that
	// says how to get it when it cannot (for example an install hint).
	Available() (ok bool, note string)
	// Run examines the target. files is the safe file listing of root;
	// seeders must read target files only through it or through
	// walk.Resolve, never by walking the tree themselves.
	Run(ctx context.Context, root string, files []walk.File) ([]Lead, error)
}

// Status records how one seeder fared in a run.
type Status struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Note      string `json:"note,omitempty"`
	Leads     int    `json:"leads"`
	Error     string `json:"error,omitempty"`
}

// RunAll runs every available seeder and returns the merged, sorted leads.
// One failing seeder does not stop the others: its error is recorded in its
// Status and the run continues.
func RunAll(ctx context.Context, seeders []Seeder, root string, files []walk.File) ([]Lead, []Status) {
	var leads []Lead
	var statuses []Status
	for _, s := range seeders {
		st := Status{Name: s.Name()}
		st.Available, st.Note = s.Available()
		if st.Available {
			got, err := s.Run(ctx, root, files)
			if err != nil {
				st.Error = err.Error()
			}
			// A seeder may have more to say about its run than its leads,
			// for example how many scanner results it could not classify.
			// Without this the drop would be silent.
			if n, ok := s.(Noter); ok && n.Note() != "" {
				st.Note = strings.TrimSpace(st.Note + " " + n.Note())
			}
			got, capNote := capLeads(got)
			if capNote != "" {
				st.Note = strings.TrimSpace(st.Note + " " + capNote)
			}
			for i := range got {
				got[i].Source = s.Name()
				got[i].Finalize()
			}
			st.Leads = len(got)
			leads = append(leads, got...)
		}
		statuses = append(statuses, st)
	}
	return Sort(Unique(leads)), statuses
}

// Lead caps. A generated or vendored file can match one rule thousands of
// times. Past a point more leads of the same rule in the same file add
// nothing a reader can use, and each one costs a ledger line and a finding.
const (
	// MaxLeadsPerRuleFile is how many leads one rule may report in one file.
	MaxLeadsPerRuleFile = 50
	// MaxLeadsPerSeeder is how many leads one seeder may report in one run.
	MaxLeadsPerSeeder = 5000
)

// capLeads applies the lead caps to one seeder's output, keeping the first
// leads in the seeder's own order. The note says what was dropped, so the
// cap is visible in the seeder's status and never silent.
func capLeads(leads []Lead) ([]Lead, string) {
	type key struct{ rule, file string }
	perKey := map[key]int{}
	overFile, overRun := 0, 0
	worst, worstN := key{}, 0
	kept := leads[:0:0]
	for _, l := range leads {
		k := key{l.RuleID, l.File}
		perKey[k]++
		if l.File != "" && perKey[k] > MaxLeadsPerRuleFile {
			overFile++
			if perKey[k] > worstN {
				worst, worstN = k, perKey[k]
			}
			continue
		}
		if len(kept) >= MaxLeadsPerSeeder {
			overRun++
			continue
		}
		kept = append(kept, l)
	}
	var notes []string
	if overFile > 0 {
		notes = append(notes, fmt.Sprintf("%d leads were not listed: a rule reports at most %d leads per file (most: rule %s in %s, %d matches).", overFile, MaxLeadsPerRuleFile, worst.rule, worst.file, worstN))
	}
	if overRun > 0 {
		notes = append(notes, fmt.Sprintf("%d leads were not listed: a seeder reports at most %d leads per run.", overRun, MaxLeadsPerSeeder))
	}
	return kept, strings.Join(notes, " ")
}

// Unique drops leads with a repeated ID, keeping the first.
func Unique(leads []Lead) []Lead {
	seen := map[string]bool{}
	out := leads[:0:0]
	for _, l := range leads {
		if seen[l.ID] {
			continue
		}
		seen[l.ID] = true
		out = append(out, l)
	}
	return out
}

// Sort orders leads by file, line, source and rule so output is stable.
func Sort(leads []Lead) []Lead {
	sort.SliceStable(leads, func(i, j int) bool {
		a, b := leads[i], leads[j]
		switch {
		case a.File != b.File:
			return a.File < b.File
		case a.Line != b.Line:
			return a.Line < b.Line
		case a.Endpoint != b.Endpoint:
			return a.Endpoint < b.Endpoint
		case a.Source != b.Source:
			return a.Source < b.Source
		default:
			return a.RuleID < b.RuleID
		}
	})
	return leads
}

// eachFile runs check over files in a worker pool sized to the machine and
// returns the leads in file order, so the result does not depend on
// scheduling. check returns nil leads for a file it does not handle. The
// first error in file order is returned with the leads of the other files:
// one unreadable file must not hide the rest. what names the seeder in the
// message for a cancelled run.
func eachFile(ctx context.Context, what string, files []walk.File, check func(f walk.File) ([]Lead, error)) ([]Lead, error) {
	type result struct {
		leads []Lead
		err   error
	}
	results := make([]result, len(files))
	next := make(chan int)
	var wg sync.WaitGroup
	workers := min(runtime.GOMAXPROCS(0), len(files))
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i].leads, results[i].err = check(files[i])
			}
		}()
	}
	var stopped error
feed:
	for i := range files {
		select {
		case next <- i:
		case <-ctx.Done():
			stopped = fmt.Errorf("%s stopped early: %w; rerun the scan to cover the remaining files", what, ctx.Err())
			break feed
		}
	}
	close(next)
	wg.Wait()

	var leads []Lead
	var firstErr error
	for _, r := range results {
		leads = append(leads, r.leads...)
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
	}
	if stopped != nil {
		return leads, stopped
	}
	return leads, firstErr
}
