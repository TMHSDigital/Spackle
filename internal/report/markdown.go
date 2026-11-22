package report

import (
	"io"
	"strings"
)

// renderMarkdown writes GitHub-flavored markdown. Text from the target is
// never written raw: prose is backslash-escaped, identifiers go into code
// spans whose delimiter is longer than any backtick run inside, and code goes
// into fenced blocks whose fence is longer than any backtick run inside.
func renderMarkdown(run Run, w io.Writer) error {
	d := buildDoc(run, cleanControl)
	var b strings.Builder

	b.WriteString("# Spackle report\n\n")

	b.WriteString("## Run summary\n\n")
	mdKVList(&b, d.Summary)
	b.WriteString("\n**Counts:** " + mdInline(d.Counts) + "\n\n")

	b.WriteString("## Findings summary\n\n")
	if d.NoFindings != "" {
		b.WriteString(mdPara(d.NoFindings) + "\n\n")
	} else {
		b.WriteString("| Id | Severity | Score | Confidence | Status | Title | Location |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
		for _, f := range d.Active {
			cells := []string{
				mdCodeCell(f.ID), mdInline(f.Label), mdInline(f.Score), mdInline(f.Confidence),
				mdInline(f.Status), mdInline(f.Title), mdCodeCell(f.Location),
			}
			b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
		}
		b.WriteString("\n## Findings\n\n")
		for _, f := range d.Active {
			mdFinding(&b, f)
		}
	}

	b.WriteString("## Dismissed by review\n\n")
	if len(d.Dismissed) == 0 {
		b.WriteString("No findings were dismissed.\n")
	}
	for _, f := range d.Dismissed {
		b.WriteString("- " + mdCode(f.ID) + " " + mdInline("["+f.Tag+"] "+f.Title) + " at " + mdCode(f.Location) +
			". **Reason:** " + mdInline(f.Reason) + "\n")
	}

	b.WriteString("\n## What was skipped\n\n")
	if len(d.Skipped) == 0 {
		b.WriteString("Nothing was skipped.\n")
	}
	for _, s := range d.Skipped {
		b.WriteString("- " + mdInline(s) + "\n")
	}

	b.WriteString("\n## Coverage\n\n")
	mdKVList(&b, d.Map)
	b.WriteString("\n")
	if len(d.Seeders) == 0 {
		b.WriteString("No seeder reported its status.\n")
	} else {
		b.WriteString("| Seeder | Status | Leads | Note |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		for _, s := range d.Seeders {
			b.WriteString("| " + mdInline(s.Name) + " | " + s.Status + " | " + s.Leads + " | " + mdInline(s.Note) + " |\n")
		}
	}

	b.WriteString("\n## Usage\n\n")
	mdKVList(&b, d.Usage)

	_, err := io.WriteString(w, b.String())
	return err
}

func mdKVList(b *strings.Builder, items []kv) {
	for _, p := range items {
		b.WriteString("- **" + p.Label + ":** " + mdValue(p.Value, p.Mono) + "\n")
	}
}

func mdValue(s string, mono bool) string {
	if mono && s != notRecorded {
		return mdCode(s)
	}
	return mdInline(s)
}

func mdFinding(b *strings.Builder, f findingView) {
	b.WriteString("### " + mdInline(f.ID+": "+f.Title) + "\n\n")
	b.WriteString("**Severity:** " + mdInline(f.Tag) + ". **Confidence:** " + mdInline(f.Confidence) +
		". **Status:** " + mdInline(f.Status) + ".\n\n")
	for _, s := range f.Sections {
		b.WriteString("#### " + s.Title + "\n\n")
		prev := ""
		for _, bl := range s.Blocks {
			// Consecutive key-value lines form one tight list.
			if prev != "" && (prev != blockKV || bl.Kind != blockKV) {
				b.WriteString("\n")
			}
			mdBlock(b, bl)
			prev = bl.Kind
		}
		b.WriteString("\n")
	}
}

func mdBlock(b *strings.Builder, bl block) {
	switch bl.Kind {
	case blockKV:
		b.WriteString("- **" + mdInline(bl.Label) + ":** " + mdValue(bl.Text, bl.Mono) + "\n")
	case blockPara:
		if bl.Label != "" {
			b.WriteString("**" + bl.Label + "**\n\n")
		}
		b.WriteString(mdPara(bl.Text) + "\n")
	case blockList, blockSteps:
		b.WriteString("**" + bl.Label + "**\n\n")
		for _, it := range bl.Items {
			lead := "- "
			if bl.Kind == blockSteps {
				// Markdown renumbers an ordered list from its first item.
				lead = "1. "
			}
			b.WriteString(lead + mdValue(it, bl.Mono) + "\n")
		}
	case blockCode:
		if bl.Label != "" {
			b.WriteString("**" + bl.Label + "**\n\n")
		}
		lang := bl.Lang
		if lang == "" {
			lang = "text"
		}
		b.WriteString(mdFence(bl.Text, lang))
	}
}

// mdInline escapes text for use inside a paragraph, list item, heading or
// table cell. Whitespace, newlines included, collapses to single spaces, and
// every character markdown or GitHub gives a meaning to is backslash-escaped,
// the table pipe included.
func mdInline(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '<', '>', '|', '#', '~', '!', '&', '$', '@':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mdPara escapes multi-line prose. Line breaks are kept; each line is
// escaped, and a line that would otherwise open a list, a rule or a setext
// heading has its leading marker escaped too.
func mdPara(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		l = mdInline(l)
		switch {
		case l == "":
		case l[0] == '-' || l[0] == '+' || l[0] == '=':
			l = `\` + l
		default:
			j := 0
			for j < len(l) && l[j] >= '0' && l[j] <= '9' {
				j++
			}
			if j > 0 && j < len(l) && (l[j] == '.' || l[j] == ')') {
				l = l[:j] + `\` + l[j:]
			}
		}
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}

// mdCode wraps s in a code span. The delimiter is one backtick longer than
// the longest backtick run in s, so s cannot close the span.
func mdCode(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	delim := strings.Repeat("`", longestRun(s, '`')+1)
	if strings.Contains(s, "`") {
		// Padding keeps a leading or trailing backtick apart from the delimiter.
		return delim + " " + s + " " + delim
	}
	return delim + s + delim
}

// mdCodeCell is mdCode for a table cell, where a pipe ends the cell even
// inside a code span unless it is escaped.
func mdCodeCell(s string) string {
	return strings.ReplaceAll(mdCode(s), "|", `\|`)
}

// mdFence wraps content in a fenced code block. The fence is at least three
// backticks and always longer than any backtick run in content, so content
// from the target cannot close the block and continue as markdown.
func mdFence(content, lang string) string {
	fence := strings.Repeat("`", max(3, longestRun(content, '`')+1))
	return fence + lang + "\n" + strings.TrimRight(content, "\n") + "\n" + fence + "\n"
}

// longestRun returns the length of the longest run of c in s.
func longestRun(s string, c byte) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			cur++
			best = max(best, cur)
		} else {
			cur = 0
		}
	}
	return best
}
