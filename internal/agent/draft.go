package agent

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// Draft is a finding as a model proposes it. Nothing in a draft is trusted:
// BuildFinding checks every claim it can against the target before the
// draft becomes a finding.
type Draft struct {
	Title             string      `json:"title"`
	Class             string      `json:"class"`
	CWE               []string    `json:"cwe"`
	File              string      `json:"file"`
	StartLine         int         `json:"start_line"`
	EndLine           int         `json:"end_line"`
	Symbol            string      `json:"symbol"`
	Vector            string      `json:"cvss_vector"`
	SeverityReasoning string      `json:"severity_reasoning"`
	Description       string      `json:"description"`
	Flow              []DraftStep `json:"flow"`
	Preconditions     []string    `json:"preconditions"`
	AttackSteps       []string    `json:"attack_steps"`
	ChainsInto        []string    `json:"chains_into"`
	Gains             []string    `json:"gains"`
	Exposed           []string    `json:"exposed"`
	FixSummary        string      `json:"fix_summary"`
	FixWhy            string      `json:"fix_why"`
	DefenseInDepth    []string    `json:"defense_in_depth"`
	Confidence        string      `json:"confidence"`
	ConfidenceReason  string      `json:"confidence_reason"`
}

// DraftStep is one flow step in a draft.
type DraftStep struct {
	Role  string `json:"role"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Quote string `json:"quote"`
	Note  string `json:"note"`
}

// BuildFinding validates a draft against the target and converts it. It
// returns an error describing every problem, so a rejected draft can be
// sent back to the model once with specific corrections.
//
// What is checked: the class is known; the file exists inside the target;
// the line range is inside the file; every quoted line really appears in the
// file it cites (line numbers are corrected when the quote is found
// elsewhere in the same file); and the CVSS vector is valid. The score and
// label are computed here, never taken from the model.
func BuildFinding(root string, d Draft, origin []string) (finding.Finding, error) {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	d.Class = strings.TrimSpace(strings.ToLower(d.Class))
	if _, ok := finding.DefaultVector(d.Class); !ok {
		add("class %q is not one of the known classes", d.Class)
	}
	d.File = normRel(d.File)
	lines, ferr := readLines(root, d.File)
	if ferr != nil {
		add("file %q: %v", d.File, ferr)
	} else {
		if d.StartLine < 1 || d.StartLine > len(lines) {
			add("start_line %d is outside %s, which has %d lines", d.StartLine, d.File, len(lines))
		}
		if d.EndLine < d.StartLine {
			d.EndLine = d.StartLine
		}
		if d.EndLine > len(lines) {
			d.EndLine = len(lines)
		}
	}

	var flow []finding.FlowStep
	cache := map[string][]string{d.File: lines}
	for i, s := range d.Flow {
		s.File = normRel(s.File)
		if s.File == "" {
			s.File = d.File
		}
		fl, ok := cache[s.File]
		if !ok {
			var err error
			if fl, err = readLines(root, s.File); err != nil {
				add("flow step %d: file %q: %v", i+1, s.File, err)
				continue
			}
			cache[s.File] = fl
		}
		if fl == nil {
			continue // the main file failed to read; already reported
		}
		quote := strings.TrimSpace(s.Quote)
		if quote == "" {
			add("flow step %d has no quote", i+1)
			continue
		}
		line, found := locateQuote(fl, quote, s.Line)
		if !found {
			add("flow step %d: the quote %q does not appear in %s. Quote the line exactly as it is in the file", i+1, clip(quote, 120), s.File)
			continue
		}
		role := strings.ToLower(strings.TrimSpace(s.Role))
		switch role {
		case "source", "propagation", "sanitizer", "sink":
		default:
			role = "propagation"
		}
		flow = append(flow, finding.FlowStep{Role: role, File: s.File, Line: line, Quote: clip(quote, 400), Note: clip(s.Note, 400)})
	}
	if len(d.Flow) == 0 {
		add("flow is empty: include at least the sink, quoted from the file")
	}

	sev, serr := finding.SeverityFromVector(d.Vector, clip(d.SeverityReasoning, 800))
	if serr != nil {
		// Weaker models often produce a CVSS 3 shaped vector. That alone
		// should not discard a finding whose evidence checks out, so fall
		// back to the class default and say so. The score is still computed
		// from a real vector, never taken from the model.
		if def, ok := finding.DefaultVector(d.Class); ok {
			sev, serr = finding.SeverityFromVector(def, "The model supplied an invalid CVSS 4.0 vector, so the default vector for this class is used. Treat the score as an estimate.")
		}
		if serr != nil {
			add("%v", serr)
		}
	}
	level := strings.ToLower(strings.TrimSpace(d.Confidence))
	if level != finding.ConfidenceHigh && level != finding.ConfidencePlausible {
		// A model may not award itself "demonstrated": only a sandbox run can.
		level = finding.ConfidencePlausible
	}
	if strings.TrimSpace(d.Title) == "" || strings.TrimSpace(d.Description) == "" || strings.TrimSpace(d.FixSummary) == "" {
		add("title, description and fix_summary are all required")
	}
	if strings.TrimSpace(d.ConfidenceReason) == "" {
		add("confidence_reason is required: say what you verified and what you did not")
	}
	if len(errs) > 0 {
		return finding.Finding{}, errors.Join(errs...)
	}

	loc := finding.Location{File: d.File, StartLine: d.StartLine, EndLine: d.EndLine, Symbol: clip(d.Symbol, 120)}
	info := finding.Info(d.Class)
	f := finding.Finding{
		ID: finding.MakeID(d.Class, loc), Title: clip(strings.TrimSpace(d.Title), 200),
		Surface: surfaceFor(d.Class), Class: d.Class,
		CWE: cleanCWE(d.CWE), OWASP: info.OWASP, Location: loc, Severity: sev,
		Flaw: finding.Flaw{Description: clip(strings.TrimSpace(d.Description), 2000), Flow: flow},
		Exploitation: finding.Exploitation{
			Preconditions: clipAll(d.Preconditions, 8, 400),
			Steps:         clipAll(d.AttackSteps, 12, 600),
			ChainsInto:    clipAll(d.ChainsInto, 6, 400),
		},
		Proof: finding.Proof{
			Status: finding.ProofReasoned,
			Reason: "Traced by reading the code. No proof of concept has been run.",
		},
		BlastRadius: finding.BlastRadius{Gains: clipAll(d.Gains, 8, 400), Exposed: clipAll(d.Exposed, 8, 400)},
		Remediation: finding.Remediation{
			Summary: clip(strings.TrimSpace(d.FixSummary), 1200), Why: clip(d.FixWhy, 1200),
			DefenseInDepth: clipAll(d.DefenseInDepth, 6, 400), Verification: "unverified",
		},
		Confidence: finding.Confidence{Level: level, Reason: clip(strings.TrimSpace(d.ConfidenceReason), 800)},
		Origin:     origin,
		Status:     finding.StatusOpen,
	}
	if err := f.Validate(); err != nil {
		return finding.Finding{}, err
	}
	return f, nil
}

func normRel(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	return strings.TrimPrefix(p, "./")
}

func readLines(root, rel string) ([]string, error) {
	abs, err := walk.Resolve(root, rel)
	if err != nil {
		return nil, err
	}
	text, err := walk.ReadText(abs)
	if err != nil {
		return nil, errors.New("cannot be read as text")
	}
	return strings.Split(strings.TrimRight(text, "\n"), "\n"), nil
}

// squash collapses whitespace so a quote matches regardless of indentation
// or of how the model normalized tabs and spaces.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// locateQuote finds a quote in a file and returns its 1-based line. It
// prefers a match at or near the line the model gave and otherwise accepts
// the first match anywhere in the file. Multi-line quotes are matched
// against the joined lines.
func locateQuote(lines []string, quote string, hint int) (int, bool) {
	want := squash(quote)
	if want == "" {
		return 0, false
	}
	span := strings.Count(strings.TrimSpace(quote), "\n") + 1
	match := func(i int) bool { // i is a 0-based start line
		if i < 0 || i >= len(lines) {
			return false
		}
		end := i + span
		if end > len(lines) {
			end = len(lines)
		}
		return strings.Contains(squash(strings.Join(lines[i:end], " ")), want)
	}
	if hint >= 1 {
		for delta := 0; delta <= 3; delta++ {
			if match(hint - 1 + delta) {
				return hint + delta, true
			}
			if delta > 0 && match(hint-1-delta) {
				return hint - delta, true
			}
		}
	}
	for i := range lines {
		if match(i) {
			return i + 1, true
		}
	}
	return 0, false
}

func surfaceFor(class string) string {
	switch class {
	case "container-privilege", "container-hardening", "supply-chain", "ci-injection", "ci-permissions",
		"network-exposure", "public-storage", "unencrypted-storage":
		return finding.SurfaceInfra
	}
	return finding.SurfaceCode
}

func cleanCWE(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		rest, ok := strings.CutPrefix(c, "CWE-")
		if !ok || rest == "" || strings.Trim(rest, "0123456789") != "" {
			continue
		}
		out = append(out, c)
	}
	return capSlice(out, 5)
}

func clipAll(in []string, maxItems, maxLen int) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, clip(s, maxLen))
		}
	}
	return capSlice(out, maxItems)
}
