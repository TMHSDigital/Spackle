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
// Status and the run continues. texts may hold file texts that an earlier
// stage already read; nil means every file is read here.
func RunAll(ctx context.Context, seeders []Seeder, root string, files []walk.File, texts *walk.Texts) ([]Lead, []Status) {
	leads, statuses, _ := RunAllIn(ctx, seeders, root, files, texts, nil)
	return leads, statuses
}

// RunAllIn is RunAll for a diff scan: only, when not nil, holds the files
// (relative paths) whose leads are wanted. The built-in seeders read only
// those files, and the leads of the other seeders in any other file are
// dropped before a seeder's lead cap applies, so leads elsewhere cannot
// crowd out a lead in a wanted file. A lead with no file is dropped too.
// leftOut is how many leads were dropped that way.
func RunAllIn(ctx context.Context, seeders []Seeder, root string, files []walk.File, texts *walk.Texts, only map[string]bool) (leads []Lead, statuses []Status, leftOut int) {
	sharedFiles := files
	if only != nil {
		sharedFiles = nil
		for _, f := range files {
			if only[f.Rel] {
				sharedFiles = append(sharedFiles, f)
			}
		}
	}
	// The built-in seeders that work file by file share one pass, so a
	// file is read once for all of them.
	var shared []fileSeeder
	var sharedAt []int
	for i, s := range seeders {
		if fs, ok := s.(fileSeeder); ok {
			if avail, _ := s.Available(); avail {
				shared, sharedAt = append(shared, fs), append(sharedAt, i)
			}
		}
	}
	// Every other available seeder (the external scanners) is an
	// independent subprocess: they run side by side, and alongside the
	// shared pass, with at most maxConcurrentScanners at once. Results are
	// stored by seeder position, so the output order does not depend on
	// which finishes first.
	runs := make([]fileRun, len(seeders))
	avail := make([]bool, len(seeders))
	notes := make([]string, len(seeders))
	inShared := map[int]bool{}
	for _, i := range sharedAt {
		inShared[i] = true
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, maxConcurrentScanners)
	for i, s := range seeders {
		avail[i], notes[i] = s.Available()
		if !avail[i] || inShared[i] {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			runs[i].leads, runs[i].err = s.Run(ctx, root, files)
		}()
	}
	if len(shared) > 0 {
		for j, r := range runFiles(ctx, shared, sharedFiles, texts) {
			runs[sharedAt[j]] = r
		}
	}
	wg.Wait()

	for i, s := range seeders {
		st := Status{Name: s.Name(), Available: avail[i], Note: notes[i]}
		if st.Available {
			got, err := runs[i].leads, runs[i].err
			if err != nil {
				st.Error = err.Error()
			}
			// A seeder may have more to say about its run than its leads,
			// for example how many scanner results it could not classify.
			// Without this the drop would be silent.
			if n, ok := s.(Noter); ok && n.Note() != "" {
				st.Note = strings.TrimSpace(st.Note + " " + n.Note())
			}
			if only != nil {
				kept := got[:0:0]
				for _, l := range got {
					if only[l.File] {
						kept = append(kept, l)
					}
				}
				leftOut += len(got) - len(kept)
				got = kept
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
	return Sort(Unique(leads)), statuses, leftOut
}

// maxConcurrentScanners is how many external scanners run at once. Each is
// a heavy subprocess of its own, so they are not all started together.
const maxConcurrentScanners = 3

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

// fileSeeder is a built-in seeder that examines one file at a time. RunAll
// runs all of them in one pass over the files, so a file is read once
// however many seeders want it.
type fileSeeder interface {
	Seeder
	// label names the seeder in messages, for example "built-in code rules".
	label() string
	// checks returns the function that picks the check for one file: nil
	// for a file the seeder does not handle, otherwise the function that
	// turns the text of that file into leads.
	checks() func(f walk.File) func(text string) []Lead
}

// fileRun is what one file seeder produced in a shared pass.
type fileRun struct {
	leads []Lead
	err   error
}

// runAlone runs one file seeder by itself, for its Run method.
func runAlone(ctx context.Context, s fileSeeder, files []walk.File) ([]Lead, error) {
	r := runFiles(ctx, []fileSeeder{s}, files, nil)[0]
	return r.leads, r.err
}

// runFiles runs the seeders over files in one pass and returns one result
// per seeder, in the order given. A file is read once, and only when a
// seeder handles it; a text an earlier stage already read is taken from
// texts. Each seeder gets its leads in file order and its first read error
// in file order, with the leads of the other files: one unreadable file
// must not hide the rest. A cancelled run returns the leads found so far
// and an error that says it stopped early.
func runFiles(ctx context.Context, seeders []fileSeeder, files []walk.File, texts *walk.Texts) []fileRun {
	pick := make([]func(walk.File) func(string) []Lead, len(seeders))
	for i, s := range seeders {
		pick[i] = s.checks()
	}
	type result struct {
		leads [][]Lead // per seeder; nil when no seeder handled the file
		err   error    // the read error, for the seeders in wants
		wants []bool
	}
	results, covered := eachFile(ctx, files, func(f walk.File) result {
		checks := make([]func(string) []Lead, len(seeders))
		wants := make([]bool, len(seeders))
		handled := false
		for i := range seeders {
			checks[i] = pick[i](f)
			wants[i] = checks[i] != nil
			handled = handled || wants[i]
		}
		if !handled {
			return result{}
		}
		text, ok := texts.Take(f.Abs)
		if !ok {
			var err error
			if text, err = walk.ReadText(f.Abs); err != nil {
				return result{err: err, wants: wants}
			}
		}
		leads := make([][]Lead, len(seeders))
		for i, check := range checks {
			if check != nil {
				leads[i] = check(text)
			}
		}
		return result{leads: leads}
	})

	runs := make([]fileRun, len(seeders))
	for n, r := range results {
		for i, s := range seeders {
			if r.leads != nil {
				runs[i].leads = append(runs[i].leads, r.leads[i]...)
			}
			if r.err != nil && r.wants[i] && runs[i].err == nil {
				runs[i].err = fmt.Errorf("%s could not read %s: %w; check the file's permissions and rerun", s.label(), files[n].Rel, r.err)
			}
		}
	}
	if !covered {
		for i, s := range seeders {
			runs[i].err = fmt.Errorf("%s stopped early: %w; rerun the scan to cover the remaining files", s.label(), ctx.Err())
		}
	}
	return runs
}

// eachFile runs check over files in a worker pool sized to the machine and
// returns the results in file order, so the outcome does not depend on
// scheduling. covered is false when the run was cancelled before every file
// was handed to a worker; a file that was not keeps the zero result.
func eachFile[T any](ctx context.Context, files []walk.File, check func(f walk.File) T) (results []T, covered bool) {
	results = make([]T, len(files))
	next := make(chan int)
	var wg sync.WaitGroup
	workers := min(runtime.GOMAXPROCS(0), len(files))
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i] = check(files[i])
			}
		}()
	}
	handed := 0
feed:
	for i := range files {
		// A select with both cases ready picks one at random, so a context
		// that is already done is checked first: no file is handed out
		// after the run was cancelled.
		if ctx.Err() != nil {
			break
		}
		select {
		case next <- i:
			handed++
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	// Every file that was handed out has been checked, so the run stopped
	// early exactly when some file was never handed out.
	return results, handed == len(files)
}
