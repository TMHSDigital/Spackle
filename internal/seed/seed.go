// Package seed produces leads: deterministic, model-free observations that
// start an investigation. A lead is not a verdict. Seeders are either
// built-in rule sets or adapters around an installed scanner.
package seed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

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
