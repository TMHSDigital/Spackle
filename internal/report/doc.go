package report

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
)

// The text renderers (terminal, markdown, html) share one intermediate form,
// the doc, so the three reports cannot drift apart in content or order. A doc
// holds only strings that are ready to print: every string that came from the
// target or the ledger has already been passed through the renderer's clean
// function.

// noFindingsText is shown whenever a run has no active finding.
const noFindingsText = "Spackle reported no findings in this run. Keep in mind that no findings is not proof of no flaws: " +
	"it means only that this run, with the coverage and limits listed below, did not find one."

const notRecorded = "not recorded"

// Block kinds.
const (
	blockKV    = "kv"    // Label: Text
	blockPara  = "para"  // optional Label, then prose
	blockList  = "list"  // Label, then bullet Items
	blockSteps = "steps" // Label, then numbered Items
	blockCode  = "code"  // optional Label, then verbatim Text; Lang is "diff" or empty
)

type block struct {
	Kind  string
	Label string
	Text  string
	Items []string
	Lang  string
	// Mono marks a value that is an identifier, path or command.
	Mono bool
}

type section struct {
	Title  string
	Blocks []block
}

type kv struct {
	Label string
	Value string
	Mono  bool
}

type findingView struct {
	ID         string
	Title      string
	Location   string
	Class      string // severity class: critical|high|medium|low|none
	Label      string // severity label as recorded
	Score      string // "9.3" or "unscored (estimate)"
	Tag        string // "CRITICAL 9.3"
	Confidence string
	Status     string
	Reason     string // dismiss reason
	Sections   []section
}

type seederRow struct {
	Name   string
	Status string
	Leads  string
	Note   string
}

type doc struct {
	RunID       string
	Outcome     string
	Summary     []kv
	Counts      string
	NoFindings  string // set when there is no active finding
	Active      []findingView
	Dismissed   []findingView
	Skipped     []string
	Map         []kv
	Seeders     []seederRow
	Usage       []kv
	SummaryLine string
	PatchLine   string
}

// builder turns a Run into a doc, cleaning every untrusted string.
type builder struct {
	clean func(string) string
}

func (b builder) list(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, b.clean(s))
	}
	return out
}

func (b builder) orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return notRecorded
	}
	return b.clean(s)
}

func buildDoc(run Run, clean func(string) string) doc {
	b := builder{clean: clean}
	d := doc{
		RunID:       b.orNone(run.ID),
		Outcome:     b.orNone(run.Outcome),
		Summary:     b.runSummary(run),
		Counts:      countsText(run.Count()),
		Skipped:     b.skipped(run),
		Map:         b.mapSummary(run),
		Usage:       usageSummary(run.Usage),
		SummaryLine: summaryLine(run),
		PatchLine:   patchLine(run),
	}
	for _, f := range run.Active() {
		d.Active = append(d.Active, b.finding(f))
	}
	for _, f := range run.Dismissed() {
		d.Dismissed = append(d.Dismissed, b.finding(f))
	}
	if len(d.Active) == 0 {
		d.NoFindings = noFindingsText
	}
	for _, s := range run.Seeders {
		status := "missing"
		if s.Available {
			status = "available"
		}
		note := strings.TrimSpace(s.Note)
		if s.Version != "" {
			note = strings.TrimSpace("Version " + s.Version + ". " + note)
		}
		if e := strings.TrimSpace(s.Error); e != "" {
			if note != "" {
				note += " "
			}
			note += "Error: " + e
		}
		d.Seeders = append(d.Seeders, seederRow{
			Name:   b.orNone(s.Name),
			Status: status,
			Leads:  fmt.Sprint(s.Leads),
			Note:   b.clean(note),
		})
	}
	return d
}

func (b builder) runSummary(run Run) []kv {
	out := []kv{
		{"Run id", b.orNone(run.ID), true},
		{"Command", b.orNone(run.Command), false},
		{"Target", b.orNone(run.Target), true},
		{"Target kind", b.orNone(run.TargetKind), false},
		{"Commit", b.orNone(run.Commit), true},
		{"Mode", b.orNone(run.Mode), false},
	}
	if run.Mode == "agentic" || run.Provider != "" || run.Model != "" {
		out = append(out,
			kv{"Provider", b.orNone(run.Provider), false},
			kv{"Model", b.orNone(run.Model), false})
	}
	out = append(out, kv{"Offline", yesNo(run.Offline), false})
	if run.TargetKind == "url" || run.Scope != "" || run.ScopeSource != "" {
		out = append(out,
			kv{"Authorized scope", b.orNone(run.Scope), true},
			kv{"Scope given by", b.orNone(run.ScopeSource), false})
	}
	return append(out,
		kv{"Sandbox isolation", b.orNone(run.Isolation), false},
		kv{"Started", fmtTime(run.StartedAt), false},
		kv{"Ended", fmtTime(run.EndedAt), false},
		kv{"Outcome", b.orNone(run.Outcome), false},
		kv{"Spackle version", b.orNone(run.Version), false})
}

func (b builder) mapSummary(run Run) []kv {
	m := run.Map
	out := []kv{
		{"Files mapped", fmt.Sprint(m.Files), false},
		{"Files not read", fmt.Sprint(m.Skipped), false},
		{"Languages", b.joined(m.Languages), false},
		{"Frameworks", b.joined(m.Frameworks), false},
		{"Entry points", fmt.Sprint(m.EntryPoints), false},
		{"Infrastructure files", fmt.Sprint(m.InfraFiles), false},
	}
	if m.Endpoints > 0 {
		out = append(out, kv{"Endpoints", fmt.Sprint(m.Endpoints), false})
	}
	if m.TestCommand != "" {
		out = append(out, kv{"Test command", b.clean(m.TestCommand), true})
	}
	return append(out, kv{"Leads from seeders", fmt.Sprint(run.Usage.Leads), false})
}

func (b builder) joined(in []string) string {
	if len(in) == 0 {
		return "none detected"
	}
	return b.clean(strings.Join(in, ", "))
}

func (b builder) skipped(run Run) []string {
	var out []string
	for _, s := range run.Skipped {
		line := "Cap reached: " + strings.TrimSpace(s.Cap) + "."
		if len(s.Skipped) > 0 {
			line += " Not examined: " + strings.Join(s.Skipped, "; ") + "."
		} else {
			line += " What was left unexamined was not recorded."
		}
		out = append(out, b.clean(line))
	}
	for _, r := range run.Rejected {
		out = append(out, b.clean(rejectLine(r)))
	}
	for _, n := range run.Notes {
		out = append(out, b.clean("Note: "+strings.TrimSpace(n)))
	}
	return out
}

// rejectLine says what a draft.reject event means for the reader: part of
// the plan produced no result, so the report does not cover it.
func rejectLine(r ledger.Reject) string {
	what := "Investigation not completed"
	switch r.Stage {
	case "seed", "dast":
		what = "Lead dropped at validation"
	case "engine":
		what = "Finding dropped at validation"
	}
	intent := strings.TrimSpace(r.Intent)
	if intent == "" {
		intent = "unnamed"
	}
	reason := strings.TrimSuffix(strings.TrimSpace(r.Reason), ".")
	if reason == "" {
		reason = "no reason was recorded"
	}
	return what + ": " + intent + " (" + reason + ")."
}

func usageSummary(u Usage) []kv {
	tokens := fmt.Sprintf("%d input, %d output", u.InputTokens, u.OutputTokens)
	if u.Estimated {
		tokens += " (estimated)"
	}
	cost := "unknown for this model"
	if u.CostKnown {
		cost = fmt.Sprintf("$%.4f", u.CostUSD)
	}
	out := []kv{
		{"Model calls", fmt.Sprint(u.ModelCalls), false},
		{"Tokens", tokens, false},
		{"Cost", cost, false},
	}
	// One line per stage, so the split of a budget across the stages and
	// their models can be read off the report.
	for _, name := range u.Stages() {
		s := u.ByStage[name]
		cost := "cost unknown"
		if s.CostKnown {
			cost = fmt.Sprintf("$%.4f", s.CostUSD)
		}
		calls := "calls"
		if s.Calls == 1 {
			calls = "call"
		}
		line := fmt.Sprintf("%d %s, %d input and %d output tokens, %s", s.Calls, calls, s.InputTokens, s.OutputTokens, cost)
		if len(s.Models) > 0 {
			line += " (" + strings.Join(s.Models, ", ") + ")"
		}
		out = append(out, kv{"Stage " + name, line, false})
	}
	return append(out, kv{"Sandbox runs", fmt.Sprint(u.SandboxRuns), false})
}

func countsText(c Counts) string {
	accepted := ""
	if c.Accepted > 0 {
		accepted = fmt.Sprintf(", %d accepted by the baseline", c.Accepted)
	}
	return fmt.Sprintf("%d open, %d with a patch available, %d fixed%s, %d dismissed. By severity, all but dismissed: %d critical, %d high, %d medium, %d low, %d none. "+
		"Demonstrated by a proof of concept: %d.",
		c.Open, c.PatchAvailable, c.Fixed, accepted, c.Dismissed, c.Critical, c.High, c.Medium, c.Low, c.None, c.Demonstrated)
}

// summaryLine is the one-line total that ends the terminal report. The
// finding count is the number of active findings: every one that is not
// dismissed.
func summaryLine(run Run) string {
	c := run.Count()
	n := c.Open + c.PatchAvailable + c.Fixed + c.Accepted
	noun := "findings"
	if n == 1 {
		noun = "finding"
	}
	accepted := ""
	if c.Accepted > 0 {
		accepted = fmt.Sprintf(", %d accepted", c.Accepted)
	}
	return fmt.Sprintf("Summary: %d %s (%d critical, %d high, %d medium, %d low), %d demonstrated, %d fixed%s, %d dismissed",
		n, noun, c.Critical, c.High, c.Medium, c.Low, c.Demonstrated, c.Fixed, accepted, c.Dismissed)
}

// patchLine is shown above the summary line when patches were written and
// not applied. It is separate so the summary line keeps its width.
func patchLine(run Run) string {
	n := run.Count().PatchAvailable
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("Patches available and not applied: %d. The scanned code still has these flaws.", n)
}

func (b builder) finding(f finding.Finding) findingView {
	v := findingView{
		ID:         b.orNone(f.ID),
		Title:      b.orNone(f.Title),
		Location:   b.orNone(f.Location.String()),
		Class:      severityClass(f.Severity.Label),
		Label:      b.orNone(f.Severity.Label),
		Score:      scoreText(f.Severity),
		Confidence: b.orNone(f.Confidence.Level),
		Status:     b.orNone(f.Status),
		Reason:     b.orNone(f.DismissReason),
	}
	v.Tag = strings.ToUpper(v.Label) + " " + v.Score
	v.Sections = []section{
		{"Identity", b.identity(f)},
		{"Severity", b.severity(f.Severity)},
		{"The flaw", b.flaw(f.Flaw)},
		{"Exploitation scenario", b.exploitation(f.Exploitation)},
		{"Proof of concept", b.proof(f.Proof)},
		{"Blast radius", b.blast(f.BlastRadius)},
		{"Remediation", b.remediation(f.Remediation)},
		{"Confidence", b.confidence(f.Confidence)},
		{"Origin", b.origin(f.Origin)},
	}
	return v
}

func (b builder) kv(label, value string, mono bool) block {
	return block{Kind: blockKV, Label: label, Text: b.clean(value), Mono: mono}
}

func (b builder) para(label, text string) block {
	return block{Kind: blockPara, Label: label, Text: b.clean(text)}
}

func (b builder) identity(f finding.Finding) []block {
	out := []block{
		b.kv("Id", f.ID, true),
		b.kv("Title", f.Title, false),
		{Kind: blockKV, Label: "Location", Text: b.orNone(f.Location.String()), Mono: true},
	}
	if f.Location.Symbol != "" {
		out = append(out, b.kv("Symbol", f.Location.Symbol, true))
	}
	out = append(out, b.kv("Class", f.Class, false), b.kv("Surface", f.Surface, false))
	if len(f.CWE) > 0 {
		out = append(out, b.kv("CWE", strings.Join(f.CWE, ", "), false))
	}
	if len(f.OWASP) > 0 {
		out = append(out, b.kv("OWASP", strings.Join(f.OWASP, ", "), false))
	}
	out = append(out, b.kv("Status", f.Status, false))
	if f.DismissReason != "" {
		out = append(out, b.kv("Dismiss reason", f.DismissReason, false))
	}
	if f.AcceptReason != "" {
		out = append(out, b.kv("Accepted because", f.AcceptReason, false))
	}
	return out
}

func (b builder) severity(s finding.Severity) []block {
	out := []block{
		{Kind: blockKV, Label: "Label", Text: b.orNone(s.Label)},
	}
	if s.Unscored {
		out = append(out, block{Kind: blockKV, Label: "Score", Text: scoreText(s) + ": no valid CVSS vector was available, so the label is carried over from a scanner or rule"})
	} else {
		out = append(out, block{Kind: blockKV, Label: "Score", Text: scoreText(s) + " (CVSS 4.0)"})
	}
	if s.Vector != "" {
		out = append(out, b.kv("Vector", s.Vector, true))
	}
	if s.Reasoning != "" {
		out = append(out, b.para("Reasoning", s.Reasoning))
	}
	return out
}

func (b builder) flaw(fl finding.Flaw) []block {
	out := []block{{Kind: blockPara, Text: b.orNone(fl.Description)}}
	for i, st := range fl.Flow {
		where := st.File
		if where != "" && st.Line > 0 {
			where += fmt.Sprintf(":%d", st.Line)
		}
		role := strings.TrimSpace(st.Role)
		if role == "" {
			role = "step"
		}
		label := b.clean(fmt.Sprintf("Flow step %d, %s", i+1, role))
		if where == "" {
			// A step observed in traffic or configuration has no file to cite.
			out = append(out, block{Kind: blockKV, Label: label, Text: "no file location recorded"})
		} else {
			out = append(out, b.kv(label, where, true))
		}
		if st.Note != "" {
			out = append(out, b.kv("Note", st.Note, false))
		}
		if st.Quote != "" {
			out = append(out, block{Kind: blockCode, Text: b.clean(st.Quote)})
		}
	}
	return out
}

func (b builder) exploitation(e finding.Exploitation) []block {
	var out []block
	if len(e.Preconditions) > 0 {
		out = append(out, block{Kind: blockList, Label: "Preconditions", Items: b.list(e.Preconditions)})
	}
	if len(e.Steps) > 0 {
		out = append(out, block{Kind: blockSteps, Label: "Steps", Items: b.list(e.Steps)})
	}
	if len(e.ChainsInto) > 0 {
		out = append(out, block{Kind: blockList, Label: "Chains into", Items: b.list(e.ChainsInto)})
	}
	return orEmptyNote(out, "No exploitation scenario was recorded.")
}

func (b builder) proof(p finding.Proof) []block {
	out := []block{
		{Kind: blockKV, Label: "Status", Text: b.orNone(p.Status) + " (" + proofMeaning(p.Status) + ")"},
	}
	switch {
	case p.Reason != "":
		out = append(out, b.kv("Reason", p.Reason, false))
	case p.Status != finding.ProofDemonstrated:
		out = append(out, block{Kind: blockKV, Label: "Reason", Text: "none recorded"})
	}
	if p.Kind != "" {
		out = append(out, b.kv("Kind", p.Kind, false))
	}
	if p.Summary != "" {
		out = append(out, b.para("Summary", p.Summary))
	}
	if p.Command != "" {
		out = append(out, block{Kind: blockCode, Label: "Command", Text: b.clean(p.Command)})
	}
	if p.Result != "" {
		out = append(out, block{Kind: blockCode, Label: "Captured result", Text: b.clean(p.Result)})
	}
	if p.Isolation != "" {
		out = append(out, b.kv("Isolation", p.Isolation, false))
	}
	if len(p.Artifacts) > 0 {
		out = append(out, block{Kind: blockList, Label: "Artifacts", Items: b.list(p.Artifacts), Mono: true})
	}
	return out
}

func (b builder) blast(r finding.BlastRadius) []block {
	var out []block
	if len(r.Gains) > 0 {
		out = append(out, block{Kind: blockList, Label: "What the attacker gains", Items: b.list(r.Gains)})
	}
	if len(r.Exposed) > 0 {
		out = append(out, block{Kind: blockList, Label: "Exposed", Items: b.list(r.Exposed)})
	}
	if r.KillChain != "" {
		out = append(out, b.para("Kill chain", r.KillChain))
	}
	if len(r.Related) > 0 {
		out = append(out, b.kv("Related findings", strings.Join(r.Related, ", "), true))
	}
	return orEmptyNote(out, "No blast radius was recorded.")
}

func (b builder) remediation(r finding.Remediation) []block {
	out := []block{{Kind: blockPara, Text: b.orNone(r.Summary)}}
	if r.Patch != "" {
		out = append(out, block{Kind: blockCode, Label: "Patch", Text: b.clean(r.Patch), Lang: "diff"})
	}
	if r.Why != "" {
		out = append(out, b.para("Why this fixes it", r.Why))
	}
	if len(r.DefenseInDepth) > 0 {
		out = append(out, block{Kind: blockList, Label: "Defense in depth", Items: b.list(r.DefenseInDepth)})
	}
	if r.Verification != "" {
		out = append(out, b.kv("Verification", r.Verification, false))
	}
	if r.Branch != "" {
		out = append(out, b.kv("Branch", r.Branch, true))
	}
	return out
}

func (b builder) confidence(c finding.Confidence) []block {
	reason := "none recorded"
	if strings.TrimSpace(c.Reason) != "" {
		reason = b.clean(c.Reason)
	}
	return []block{
		{Kind: blockKV, Label: "Level", Text: b.orNone(c.Level) + " (" + confidenceMeaning(c.Level) + ")"},
		{Kind: blockKV, Label: "Reason", Text: reason},
	}
}

func (b builder) origin(o []string) []block {
	if len(o) == 0 {
		return []block{{Kind: blockPara, Text: "No origin was recorded."}}
	}
	return []block{b.kv("Found by", strings.Join(o, ", "), false)}
}

func orEmptyNote(blocks []block, note string) []block {
	if len(blocks) == 0 {
		return []block{{Kind: blockPara, Text: note}}
	}
	return blocks
}

func proofMeaning(status string) string {
	switch status {
	case finding.ProofDemonstrated:
		return "the flaw's effect was observed: a proof of concept ran in the sandbox, or a recorded exchange shows it"
	case finding.ProofReasoned:
		return "the exploit path was argued from code or traffic and was not run"
	case finding.ProofNotRun:
		return "no proof of concept was run"
	case finding.ProofFailed:
		return "a proof of concept ran and did not trigger the flaw"
	}
	return "unrecognized proof status"
}

func confidenceMeaning(level string) string {
	switch level {
	case finding.ConfidenceDemonstrated:
		return "the flaw's effect was observed, by a sandboxed proof or a recorded exchange"
	case finding.ConfidenceHigh:
		return "traced end to end, not run"
	case finding.ConfidencePlausible:
		return "a lead that was not confirmed"
	}
	return "unrecognized confidence level"
}

// severityClass maps a recorded label onto the fixed set the renderers style.
func severityClass(label string) string {
	switch label {
	case "critical", "high", "medium", "low":
		return label
	}
	return "none"
}

func scoreText(s finding.Severity) string {
	if s.Unscored {
		return "unscored (estimate)"
	}
	return fmt.Sprintf("%.1f", s.Score)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return notRecorded
	}
	return t.UTC().Format(time.RFC3339)
}

// normalizeNewlines turns CRLF and lone CR into LF so every report has LF
// line endings whatever the target's files use.
func normalizeNewlines(s string) string {
	if !strings.Contains(s, "\r") {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// cleanControl is CleanText, under the name the renderers use.
var cleanControl = CleanText

// CleanText makes text from the target safe to print on a terminal or to
// store in a plain-text file. Line endings become LF; every other C0 or C1
// control character (ESC included), DEL, invisible Unicode format characters
// such as bidirectional overrides, and invalid UTF-8 are replaced with a
// visible backslash escape. Newline and tab are kept. A hostile repository
// therefore cannot move the cursor, recolor or retitle the operator's
// terminal, or reorder what the operator reads. Commands outside the
// reports that print run content, such as the run list, use it too.
func CleanText(s string) string {
	s = normalizeNewlines(s)
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x7f || (c < 0x20 && c != '\n' && c != '\t') {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}
