// Package finding defines the Spackle finding: the schema every stage
// produces and every report renders, with validation, CVSS 4.0 scoring,
// deduplication and ranking.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Confidence levels, from strongest to weakest.
const (
	ConfidenceDemonstrated = "demonstrated" // a proof of concept ran and succeeded
	ConfidenceHigh         = "high"         // traced end to end, not run
	ConfidencePlausible    = "plausible"    // a lead that was not confirmed
)

// Proof statuses.
const (
	ProofDemonstrated = "demonstrated" // PoC ran in the sandbox and triggered the flaw
	ProofReasoned     = "reasoned"     // exploit path argued from code or traffic, not run
	ProofNotRun       = "not-run"      // no sandbox, or the operator declined live testing
	ProofFailed       = "failed"       // PoC ran and did not trigger the flaw
)

// Statuses.
const (
	StatusOpen      = "open"
	StatusDismissed = "dismissed" // refuted by the reviewer; reason kept
	// StatusPatchAvailable means a patch was written and checked against
	// the proof, but it is not applied: the scanned code still has the flaw.
	StatusPatchAvailable = "patch-available"
	// StatusFixed means the stored proof no longer succeeds against the
	// code itself, which is what "spackle verify" establishes.
	StatusFixed = "fixed"
)

// Surfaces.
const (
	SurfaceCode  = "code"
	SurfaceDAST  = "running-target"
	SurfaceInfra = "infrastructure"
	SurfaceDebug = "debug"
)

// Finding is one reported flaw. Field order here is the order JSON output
// uses, and the order a report presents the sections in.
type Finding struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Surface string   `json:"surface"`
	Class   string   `json:"class"`
	CWE     []string `json:"cwe,omitempty"`
	OWASP   []string `json:"owasp,omitempty"`

	Location Location `json:"location"`
	Severity Severity `json:"severity"`

	Flaw         Flaw         `json:"flaw"`
	Exploitation Exploitation `json:"exploitation"`
	Proof        Proof        `json:"proof"`
	BlastRadius  BlastRadius  `json:"blast_radius"`
	Remediation  Remediation  `json:"remediation"`
	Confidence   Confidence   `json:"confidence"`

	Origin []string `json:"origin,omitempty"`
	Status string   `json:"status"`
	// DismissReason is set when Status is dismissed.
	DismissReason string `json:"dismiss_reason,omitempty"`
}

// Location says exactly where the flaw is: a file and line range, or an
// endpoint and parameter. At least one form must be present.
type Location struct {
	File      string `json:"file,omitempty"` // forward-slash path relative to the target root
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Symbol    string `json:"symbol,omitempty"`

	Method    string `json:"method,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Parameter string `json:"parameter,omitempty"`
}

// String renders the location the way a report cites it.
func (l Location) String() string {
	var parts []string
	if l.File != "" {
		s := l.File
		if l.StartLine > 0 {
			s += fmt.Sprintf(":%d", l.StartLine)
			if l.EndLine > l.StartLine {
				s += fmt.Sprintf("-%d", l.EndLine)
			}
		}
		parts = append(parts, s)
	}
	if l.Endpoint != "" {
		s := l.Endpoint
		if l.Method != "" {
			s = l.Method + " " + s
		}
		if l.Parameter != "" {
			s += " (parameter " + l.Parameter + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// Severity holds a CVSS 4.0 assessment. Score and Label are always computed
// by Spackle from Vector; a model never supplies them.
type Severity struct {
	Vector    string  `json:"cvss_vector,omitempty"`
	Score     float64 `json:"cvss_score"`
	Label     string  `json:"label"` // critical|high|medium|low|none
	Reasoning string  `json:"reasoning,omitempty"`
	// Unscored is true when no valid vector was available and Label is an
	// estimate carried over from a scanner or rule.
	Unscored bool `json:"unscored,omitempty"`
}

// Flaw describes what is wrong and how data reaches the sink.
type Flaw struct {
	Description string     `json:"description"`
	Flow        []FlowStep `json:"flow,omitempty"`
}

// FlowStep is one hop from source to sink, quoting the real code or traffic.
type FlowStep struct {
	Role  string `json:"role"` // source|propagation|sanitizer|sink
	File  string `json:"file,omitempty"`
	Line  int    `json:"line,omitempty"`
	Quote string `json:"quote,omitempty"`
	Note  string `json:"note,omitempty"`
}

// Exploitation is the attacker's-eye scenario.
type Exploitation struct {
	Preconditions []string `json:"preconditions,omitempty"`
	Steps         []string `json:"steps,omitempty"`
	ChainsInto    []string `json:"chains_into,omitempty"`
}

// Proof records the demonstration, or why there is none.
type Proof struct {
	Status    string   `json:"status"`
	Kind      string   `json:"kind,omitempty"` // test|script|http-sequence
	Summary   string   `json:"summary,omitempty"`
	Artifacts []string `json:"artifacts,omitempty"` // paths relative to the run directory
	Command   string   `json:"command,omitempty"`
	Result    string   `json:"result,omitempty"` // captured output or response excerpt
	Isolation string   `json:"isolation,omitempty"`
	Reason    string   `json:"reason,omitempty"` // why it was not run, when it was not
}

// BlastRadius says what an attacker gains.
type BlastRadius struct {
	Gains     []string `json:"gains,omitempty"`
	Exposed   []string `json:"exposed,omitempty"`
	KillChain string   `json:"kill_chain,omitempty"`
	Related   []string `json:"related,omitempty"` // ids of findings this combines with
}

// Remediation is the fix.
type Remediation struct {
	Summary        string   `json:"summary"`
	Patch          string   `json:"patch,omitempty"` // unified diff
	Why            string   `json:"why,omitempty"`
	DefenseInDepth []string `json:"defense_in_depth,omitempty"`
	Verification   string   `json:"verification,omitempty"` // verified|unverified|rejected
	Branch         string   `json:"branch,omitempty"`
}

// Confidence is the honest label with its reason.
type Confidence struct {
	Level  string `json:"level"`
	Reason string `json:"reason"`
}

// MakeID derives a stable finding id from what the finding is and where it
// is, so the same flaw gets the same id on every run of the same target.
func MakeID(class string, loc Location) string {
	return MakeRuleID(class, loc, "")
}

// MakeRuleID is MakeID for a finding that comes straight from a rule hit.
// The rule is part of the id, so two different rules of one class that fire
// at the same place stay two findings, while the same rule reported by two
// seeders still gets one id. An empty rule gives the same id as MakeID.
func MakeRuleID(class string, loc Location, rule string) string {
	parts := []string{
		strings.ToLower(class), loc.File, fmt.Sprint(loc.StartLine),
		strings.ToUpper(loc.Method), loc.Endpoint, loc.Parameter,
	}
	if rule != "" {
		parts = append(parts, rule)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "SPK-" + strings.ToUpper(hex.EncodeToString(sum[:4]))
}

// hasParentSegment reports whether a forward-slash path has a ".." segment.
// A name that merely contains two dots ("[...slug]", "v1..v2.md") does not.
func hasParentSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// Validate checks that a finding is complete enough to report. It returns
// every problem at once so a rejected draft can be explained in one message.
func (f *Finding) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if strings.TrimSpace(f.ID) == "" {
		add("id is empty")
	}
	if strings.TrimSpace(f.Title) == "" {
		add("title is empty")
	}
	if strings.TrimSpace(f.Class) == "" {
		add("class is empty")
	}
	switch f.Surface {
	case SurfaceCode, SurfaceDAST, SurfaceInfra, SurfaceDebug:
	default:
		add("surface %q is not one of code, running-target, infrastructure, debug", f.Surface)
	}
	if f.Location.File == "" && f.Location.Endpoint == "" {
		add("location has neither a file nor an endpoint")
	}
	if f.Location.File != "" {
		if strings.Contains(f.Location.File, `\`) || strings.HasPrefix(f.Location.File, "/") || hasParentSegment(f.Location.File) {
			add("location file %q must be a forward-slash path relative to the target root", f.Location.File)
		}
		if f.Location.StartLine < 0 || (f.Location.EndLine != 0 && f.Location.EndLine < f.Location.StartLine) {
			add("location line range %d-%d is invalid", f.Location.StartLine, f.Location.EndLine)
		}
	}
	for _, c := range f.CWE {
		if !validCWE(c) {
			add("cwe %q is not of the form CWE-<number>", c)
		}
	}
	switch f.Severity.Label {
	case "critical", "high", "medium", "low", "none":
	default:
		add("severity label %q is not one of critical, high, medium, low, none", f.Severity.Label)
	}
	if f.Severity.Vector != "" {
		score, label, err := Score(f.Severity.Vector)
		switch {
		case err != nil:
			add("severity vector: %v", err)
		case score != f.Severity.Score || label != f.Severity.Label:
			add("severity %.1f %s does not match the vector, which scores %.1f %s", f.Severity.Score, f.Severity.Label, score, label)
		}
	} else if !f.Severity.Unscored {
		add("severity has no CVSS vector and is not marked unscored")
	}
	if strings.TrimSpace(f.Flaw.Description) == "" {
		add("flaw description is empty")
	}
	switch f.Proof.Status {
	case ProofDemonstrated:
		if len(f.Proof.Artifacts) == 0 {
			add("proof is marked demonstrated but lists no artifact")
		}
		if strings.TrimSpace(f.Proof.Result) == "" {
			add("proof is marked demonstrated but has no captured result")
		}
	case ProofReasoned, ProofNotRun, ProofFailed:
	default:
		add("proof status %q is not one of demonstrated, reasoned, not-run, failed", f.Proof.Status)
	}
	switch f.Confidence.Level {
	case ConfidenceDemonstrated:
		if f.Proof.Status != ProofDemonstrated {
			add("confidence is demonstrated but proof status is %q", f.Proof.Status)
		}
	case ConfidenceHigh, ConfidencePlausible:
	default:
		add("confidence %q is not one of demonstrated, high, plausible", f.Confidence.Level)
	}
	if strings.TrimSpace(f.Confidence.Reason) == "" {
		add("confidence has no reason")
	}
	if strings.TrimSpace(f.Remediation.Summary) == "" {
		add("remediation summary is empty")
	}
	switch f.Status {
	case StatusOpen, StatusPatchAvailable, StatusFixed:
	case StatusDismissed:
		if strings.TrimSpace(f.DismissReason) == "" {
			add("status is dismissed but no reason is recorded")
		}
	default:
		add("status %q is not one of open, dismissed, fixed", f.Status)
	}
	return errors.Join(errs...)
}

func validCWE(s string) bool {
	rest, ok := strings.CutPrefix(s, "CWE-")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

var labelOrder = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
var confidenceOrder = map[string]int{ConfidenceDemonstrated: 2, ConfidenceHigh: 1, ConfidencePlausible: 0}

// LabelRank orders severity labels; higher is worse. Unknown labels rank
// below "none".
func LabelRank(label string) int {
	if r, ok := labelOrder[label]; ok {
		return r
	}
	return -1
}

// Rank returns the findings ordered for a report: open before fixed before
// dismissed, then by severity label, score, confidence, and finally id so
// the order is total and stable.
func Rank(fs []Finding) []Finding {
	out := make([]Finding, len(fs))
	copy(out, fs)
	statusOrder := map[string]int{StatusOpen: 0, StatusPatchAvailable: 1, StatusFixed: 2, StatusDismissed: 3}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if statusOrder[a.Status] != statusOrder[b.Status] {
			return statusOrder[a.Status] < statusOrder[b.Status]
		}
		if LabelRank(a.Severity.Label) != LabelRank(b.Severity.Label) {
			return LabelRank(a.Severity.Label) > LabelRank(b.Severity.Label)
		}
		if a.Severity.Score != b.Severity.Score {
			return a.Severity.Score > b.Severity.Score
		}
		if confidenceOrder[a.Confidence.Level] != confidenceOrder[b.Confidence.Level] {
			return confidenceOrder[a.Confidence.Level] > confidenceOrder[b.Confidence.Level]
		}
		return a.ID < b.ID
	})
	return out
}

// Dedup merges findings that share an id, keeping the stronger one and the
// union of their origins. Input order decides ties.
func Dedup(fs []Finding) []Finding {
	index := map[string]int{}
	var out []Finding
	for _, f := range fs {
		i, seen := index[f.ID]
		if !seen {
			index[f.ID] = len(out)
			out = append(out, f)
			continue
		}
		keep, drop := out[i], f
		if stronger(f, keep) {
			keep, drop = f, keep
		}
		keep.Origin = UnionOrigins(keep.Origin, drop.Origin)
		out[i] = keep
	}
	return out
}

func stronger(a, b Finding) bool {
	if confidenceOrder[a.Confidence.Level] != confidenceOrder[b.Confidence.Level] {
		return confidenceOrder[a.Confidence.Level] > confidenceOrder[b.Confidence.Level]
	}
	return a.Severity.Score > b.Severity.Score
}

// UnionOrigins returns the sorted union of two origin lists.
func UnionOrigins(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
