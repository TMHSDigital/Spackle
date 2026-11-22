// Command demosvg turns the real output of a spackle run into the terminal
// picture shown in the README. It never invents text: every line in the
// picture is a line of the transcript it is given, selected by fixed rules
// (the command, the progress lines, the first few entries of the findings
// summary, and the final summary line).
//
// Usage:
//
//	spackle scan ./examples/demo-app > out.txt 2> err.txt
//	go run ./tools/demosvg -stdout out.txt -stderr err.txt -cmd "spackle scan ./examples/demo-app" -out docs/assets/demo.svg
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Palette shared with the wordmark and the report HTML.
const (
	bg      = "#1B1714"
	bar     = "#26201B"
	border  = "#3A3029"
	fg      = "#F3EDE4"
	muted   = "#B5A999"
	dim     = "#7F7466"
	accent  = "#FF8A4C"
	violet  = "#C4A1FF"
	crit    = "#FF5D5D"
	medium  = "#F2C14E"
	low     = "#8FB8DE"
	okGreen = "#7BD389"
)

const (
	width      = 860
	lineHeight = 20
	padX       = 24
	top        = 36
	mono       = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"
	sans       = "ui-sans-serif, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
	maxCols    = 100
)

type span struct{ text, color string }
type line []span

var (
	entryRe = regexp.MustCompile(`^\s*(\d+)\. (SPK-[0-9A-F]+) \[([A-Z]+)([^\]]*)\] confidence (\w+)\s*$`)
	sevCol  = map[string]string{"CRITICAL": crit, "HIGH": accent, "MEDIUM": medium, "LOW": low, "NONE": dim}
)

func main() {
	stdout := flag.String("stdout", "", "file holding the run's standard output (the terminal report)")
	stderr := flag.String("stderr", "", "file holding the run's standard error (progress lines)")
	cmd := flag.String("cmd", "spackle scan ./examples/demo-app", "the command line that produced the output")
	title := flag.String("title", "spackle", "title bar text")
	out := flag.String("out", "docs/assets/demo.svg", "SVG file to write")
	maxEntries := flag.Int("max", 5, "how many findings to show")
	flag.Parse()
	if *stdout == "" {
		fmt.Fprintln(os.Stderr, "demosvg: -stdout is required: pass the file holding the real output of a spackle run")
		os.Exit(2)
	}
	report, err := os.ReadFile(*stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "demosvg:", err)
		os.Exit(1)
	}
	var progress []byte
	if *stderr != "" {
		if progress, err = os.ReadFile(*stderr); err != nil {
			fmt.Fprintln(os.Stderr, "demosvg:", err)
			os.Exit(1)
		}
	}
	lines, alt, err := build(*cmd, string(progress), string(report), *maxEntries)
	if err != nil {
		fmt.Fprintln(os.Stderr, "demosvg:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, []byte(render(*title, alt, lines)), 0o644); err != nil { //nolint:gosec // a public asset
		fmt.Fprintln(os.Stderr, "demosvg:", err)
		os.Exit(1)
	}
	fmt.Println(alt)
}

// build selects transcript lines by rule and colors them.
func build(cmd, progress, report string, maxEntries int) ([]line, string, error) {
	var out []line
	out = append(out, line{{"$ ", okGreen}, {cmd, fg}})
	for _, l := range splitLines(progress) {
		// Progress lines are shown as they were printed, except the run
		// directory line, which holds a machine-specific path.
		if l == "" || strings.HasPrefix(l, "Run ") {
			continue
		}
		out = append(out, line{{clip(l), dim}})
	}
	out = append(out, line{})

	rl := splitLines(report)
	start := -1
	for i, l := range rl {
		if strings.TrimSpace(l) == "Findings summary" {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, "", fmt.Errorf("the transcript has no \"Findings summary\" section; pass the terminal report of a run that found something")
	}
	shown, total := 0, 0
	var titles []string
	for i := start + 1; i < len(rl); i++ {
		m := entryRe.FindStringSubmatch(rl[i])
		if m == nil {
			if strings.TrimSpace(rl[i]) == "" && total > 0 && (i+1 >= len(rl) || !strings.HasPrefix(rl[i+1], "  ")) {
				break
			}
			continue
		}
		total++
		if shown >= maxEntries || i+2 >= len(rl) {
			continue
		}
		shown++
		tag := "[" + m[3] + m[4] + "]"
		out = append(out, line{{m[2] + " ", muted}, {tag, sevCol[m[3]]}, {"  " + m[5], confidenceColor(m[5])}})
		out = append(out, line{{"  " + clip(strings.TrimSpace(rl[i+1])), fg}})
		out = append(out, line{{"  " + clip(strings.TrimSpace(rl[i+2])), dim}})
		titles = append(titles, strings.TrimSpace(rl[i+1]))
	}
	if total > shown {
		out = append(out, line{{fmt.Sprintf("  ... and %d more", total-shown), dim}})
	}
	summary := ""
	for _, l := range rl {
		if strings.HasPrefix(l, "Summary: ") {
			summary = l
		}
	}
	if summary == "" {
		return nil, "", fmt.Errorf("the transcript has no \"Summary:\" line")
	}
	out = append(out, line{}, line{{clip(summary), fg}})
	alt := fmt.Sprintf("spackle in a terminal: %s. The first findings are %s. %s", cmd, strings.Join(titles, "; "), summary)
	return out, alt, nil
}

func confidenceColor(level string) string {
	switch level {
	case "demonstrated":
		return okGreen
	case "high":
		return violet
	}
	return muted
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(strings.TrimRight(s, "\r\n"), "\r\n", "\n"), "\n")
}

func clip(s string) string {
	if len(s) > maxCols {
		return s[:maxCols-3] + "..."
	}
	return s
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func render(title, alt string, lines []line) string {
	height := top + 24 + len(lines)*lineHeight + 16
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s">`+"\n", width, height, width, height, esc(alt))
	fmt.Fprintf(&b, `<rect width="%d" height="%d" rx="12" fill="%s"/>`+"\n", width, height, bg)
	fmt.Fprintf(&b, `<path d="M0 12a12 12 0 0 1 12-12h%da12 12 0 0 1 12 12v24H0z" fill="%s"/>`+"\n", width-24, bar)
	fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%d" height="%d" rx="11.5" fill="none" stroke="%s"/>`+"\n", width-1, height-1, border)
	for i, c := range []string{crit, medium, okGreen} {
		fmt.Fprintf(&b, `<circle cx="%d" cy="18" r="5.5" fill="%s"/>`, 24+i*18, c)
	}
	fmt.Fprintf(&b, "\n"+`<text x="%d" y="22" text-anchor="middle" fill="%s" font-family="%s" font-size="12" font-weight="600">%s</text>`+"\n", width/2, dim, sans, esc(title))
	fmt.Fprintf(&b, `<g font-family="%s" font-size="13">`+"\n", mono)
	for i, l := range lines {
		if len(l) == 0 {
			continue
		}
		fmt.Fprintf(&b, `<text x="%d" y="%d" xml:space="preserve">`, padX, top+24+i*lineHeight)
		for _, s := range l {
			fmt.Fprintf(&b, `<tspan fill="%s">%s</tspan>`, s.color, esc(s.text))
		}
		b.WriteString("</text>\n")
	}
	b.WriteString("</g>\n</svg>\n")
	return b.String()
}
