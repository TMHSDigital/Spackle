package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// termWidth is the widest line the terminal report emits.
const termWidth = 100

// ANSI SGR parameters used when color is on.
const (
	sgrCritical = "91"       // bright red
	sgrHigh     = "38;5;208" // 256-color orange
	sgrMedium   = "33"       // yellow
	sgrLow      = "34"       // blue
	sgrDim      = "90"       // grey, for labels
	sgrBold     = "1"
)

// Terminal writes the plain-text report. With color false the output has no
// escape bytes at all. Text that came from the target is cleaned first, so
// the only escape sequences ever written are the fixed ones above.
func Terminal(run Run, w io.Writer, color bool) error {
	t := &term{color: color}
	d := buildDoc(run, cleanControl)

	t.line(t.paint(sgrBold, "Spackle report"))
	t.line("==============")
	t.line("")

	t.heading("Run summary")
	for _, p := range d.Summary {
		t.kv(2, p.Label, p.Value)
	}
	t.line("")
	t.kv(0, "Counts", d.Counts)
	t.line("")

	t.heading("Findings summary")
	if d.NoFindings != "" {
		t.prose(2, d.NoFindings)
	}
	for i, f := range d.Active {
		t.summaryRow(i+1, f)
	}
	t.line("")

	for _, f := range d.Active {
		t.finding(f)
	}
	if len(d.Active) > 0 {
		t.rule()
		t.line("")
	}

	t.heading("Dismissed by review")
	if len(d.Dismissed) == 0 {
		t.prose(2, "No findings were dismissed.")
	}
	for _, f := range d.Dismissed {
		t.hanging(2, "- ", f.ID+" ["+f.Tag+"] "+f.Title+" ("+f.Location+")")
		t.kv(4, "Reason", f.Reason)
	}
	t.line("")

	t.heading("What was skipped")
	if len(d.Skipped) == 0 {
		t.prose(2, "Nothing was skipped.")
	}
	for _, s := range d.Skipped {
		t.hanging(2, "- ", s)
	}
	t.line("")

	t.heading("Coverage")
	for _, p := range d.Map {
		t.kv(2, p.Label, p.Value)
	}
	t.line(t.paint(sgrDim, "  Seeders:"))
	if len(d.Seeders) == 0 {
		t.prose(4, "No seeder reported its status.")
	}
	for _, s := range d.Seeders {
		row := s.Name + ": " + s.Status + ", leads " + s.Leads
		if s.Note != "" {
			row += ". " + s.Note
		}
		t.hanging(4, "- ", row)
	}
	t.line("")

	t.heading("Usage")
	for _, p := range d.Usage {
		t.kv(2, p.Label, p.Value)
	}
	t.line("")
	t.line(d.SummaryLine)

	_, err := w.Write(t.buf.Bytes())
	return err
}

func renderTerminal(run Run, w io.Writer) error {
	return Terminal(run, w, false)
}

type term struct {
	buf   bytes.Buffer
	color bool
}

// paint wraps already-clean text in one SGR sequence when color is on.
func (t *term) paint(sgr, s string) string {
	if !t.color || s == "" {
		return s
	}
	return "\x1b[" + sgr + "m" + s + "\x1b[0m"
}

func (t *term) line(s string) {
	t.buf.WriteString(strings.TrimRight(s, " "))
	t.buf.WriteByte('\n')
}

func (t *term) rule() {
	t.line(t.paint(sgrDim, strings.Repeat("-", termWidth)))
}

func (t *term) heading(s string) {
	t.line(t.paint(sgrBold, s))
}

// prose writes wrapped text at the given indent.
func (t *term) prose(indent int, s string) {
	pad := strings.Repeat(" ", indent)
	for _, l := range wrapText(s, termWidth-indent) {
		t.line(pad + l)
	}
}

// hanging writes wrapped text whose first line starts with lead and whose
// later lines are indented to line up after it.
func (t *term) hanging(indent int, lead, s string) {
	pad := strings.Repeat(" ", indent)
	rest := strings.Repeat(" ", len(lead))
	lines := wrapText(s, termWidth-indent-len(lead))
	if len(lines) == 0 {
		lines = []string{""}
	}
	for i, l := range lines {
		if i == 0 {
			t.line(pad + lead + l)
		} else {
			t.line(pad + rest + l)
		}
	}
}

// kv writes "Label: value", wrapped, with the label dimmed.
func (t *term) kv(indent int, label, value string) {
	prefix := label + ":"
	pad := strings.Repeat(" ", indent)
	lines := wrapText(prefix+" "+value, termWidth-indent-2)
	for i, l := range lines {
		if i == 0 {
			if rest, ok := strings.CutPrefix(l, prefix); ok {
				l = t.paint(sgrDim, prefix) + rest
			}
			t.line(pad + l)
		} else {
			t.line(pad + "  " + l)
		}
	}
}

// code writes verbatim text. Long lines are broken hard so the report stays
// within termWidth; tabs become four spaces so the width is predictable.
func (t *term) code(indent int, s string) {
	pad := strings.Repeat(" ", indent)
	width := termWidth - indent
	s = strings.ReplaceAll(strings.TrimRight(s, "\n"), "\t", "    ")
	for _, l := range strings.Split(s, "\n") {
		for _, chunk := range hardBreak(l, width) {
			t.line(pad + chunk)
		}
	}
}

func (t *term) severityPaint(class, s string) string {
	switch class {
	case "critical":
		return t.paint(sgrCritical, s)
	case "high":
		return t.paint(sgrHigh, s)
	case "medium":
		return t.paint(sgrMedium, s)
	case "low":
		return t.paint(sgrLow, s)
	}
	return t.paint(sgrDim, s)
}

func (t *term) summaryRow(n int, f findingView) {
	lead := fmt.Sprintf("%d. ", n)
	head := f.ID + " " + t.severityPaint(f.Class, "["+f.Tag+"]") + " confidence " + f.Confidence
	if f.Status != "open" {
		head += ", status " + f.Status
	}
	// The head is short and built from fixed-shape fields; it is clipped
	// rather than wrapped so the escape sequences stay intact.
	plain := f.ID + " [" + f.Tag + "] confidence " + f.Confidence + ", status " + f.Status
	if utf8.RuneCountInString(plain) > termWidth-2-len(lead) {
		t.hanging(2, lead, plain)
	} else {
		t.line("  " + lead + head)
	}
	pad := 2 + len(lead)
	t.prose(pad, f.Title)
	t.prose(pad, f.Location)
}

func (t *term) finding(f findingView) {
	t.rule()
	head := f.ID
	if f.Status != "open" {
		head += " (" + f.Status + ")"
	}
	tag := "[" + f.Tag + "]"
	if utf8.RuneCountInString(tag+" "+head) > termWidth {
		t.prose(0, tag+" "+head)
	} else {
		t.line(t.severityPaint(f.Class, tag) + " " + head)
	}
	for _, l := range wrapText(f.Title, termWidth) {
		t.line(t.paint(sgrBold, l))
	}
	t.line("")
	for _, s := range f.Sections {
		t.heading(s.Title)
		for _, b := range s.Blocks {
			t.block(b)
		}
		t.line("")
	}
}

func (t *term) block(b block) {
	switch b.Kind {
	case blockKV:
		t.kv(2, b.Label, b.Text)
	case blockPara:
		if b.Label == "" {
			t.prose(2, b.Text)
			return
		}
		t.line("  " + t.paint(sgrDim, b.Label+":"))
		t.prose(4, b.Text)
	case blockList, blockSteps:
		t.line("  " + t.paint(sgrDim, b.Label+":"))
		for i, it := range b.Items {
			lead := "- "
			if b.Kind == blockSteps {
				lead = fmt.Sprintf("%d. ", i+1)
			}
			t.hanging(4, lead, it)
		}
	case blockCode:
		if b.Label != "" {
			t.line("  " + t.paint(sgrDim, b.Label+":"))
		}
		t.code(6, b.Text)
	}
}

// wrapText word-wraps s to width columns. Newlines in s start a new line;
// runs of other whitespace collapse to one space. A word longer than width is
// broken hard. Width is counted in runes.
func wrapText(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur, curLen := "", 0
		for _, word := range words {
			for _, piece := range hardBreak(word, width) {
				n := utf8.RuneCountInString(piece)
				switch {
				case curLen == 0:
					cur, curLen = piece, n
				case curLen+1+n <= width:
					cur += " " + piece
					curLen += 1 + n
				default:
					out = append(out, cur)
					cur, curLen = piece, n
				}
			}
		}
		out = append(out, cur)
	}
	// Trailing blank lines carry no information.
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// hardBreak splits s into pieces of at most width runes. An empty string
// yields one empty piece.
func hardBreak(s string, width int) []string {
	if utf8.RuneCountInString(s) <= width {
		return []string{s}
	}
	var out []string
	r := []rune(s)
	for len(r) > width {
		out = append(out, string(r[:width]))
		r = r[width:]
	}
	return append(out, string(r))
}
