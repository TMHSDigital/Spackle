package seed

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// Rule is one line-oriented source pattern. The engine is deliberately
// simple: a lead is a starting point for an investigation, so a rule only
// has to be precise enough that most of its hits deserve a look.
type Rule struct {
	ID    string
	Langs []string // walk.File.Lang values the rule applies to
	// Pattern must match the line.
	Pattern *regexp.Regexp
	// Exclude, when set, suppresses the rule if it matches the same line.
	// It expresses the safe variant of the pattern (a literal argument, a
	// safe loader) which RE2 cannot express as a negative lookahead.
	Exclude *regexp.Regexp
	// Require, when set, must also match the same line.
	Require *regexp.Regexp
	// Near, when set, must match some line within NearLines of the hit.
	// It is for settings that are only dangerous together.
	Near      *regexp.Regexp
	NearLines int

	Title    string
	Class    string
	CWE      string
	OWASP    string
	Severity string
	Detail   string
	Fix      string
}

type codeSeeder struct{ rules []Rule }

func (codeSeeder) Name() string { return "builtin-code" }

func (codeSeeder) Available() (bool, string) { return true, "" }

// isTestPath reports whether rel looks like test code. Test code is not
// attack surface, and it is full of deliberately unsafe fixtures.
func isTestPath(rel string) bool {
	p := "/" + strings.ToLower(rel)
	base := p[strings.LastIndex(p, "/")+1:]
	switch {
	case strings.Contains(p, "/tests/"), strings.Contains(p, "/__tests__/"):
		return true
	case strings.HasSuffix(base, "_test.go"), strings.HasSuffix(base, "_test.py"):
		return true
	case strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"):
		return true
	}
	for _, mid := range []string{".test.", ".spec."} {
		for _, ext := range []string{"ts", "tsx", "js", "jsx", "mjs", "cjs"} {
			if strings.HasSuffix(base, mid+ext) {
				return true
			}
		}
	}
	return false
}

// isCommentLine reports whether a trimmed line is only a comment in Go,
// Python, JavaScript or TypeScript.
func isCommentLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*")
}

func (s codeSeeder) Run(ctx context.Context, _ string, files []walk.File) ([]Lead, error) {
	byLang := map[string][]*Rule{}
	for i := range s.rules {
		for _, l := range s.rules[i].Langs {
			byLang[l] = append(byLang[l], &s.rules[i])
		}
	}
	var leads []Lead
	var firstErr error
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return leads, fmt.Errorf("built-in code rules stopped early: %w; rerun the scan to cover the remaining files", err)
		}
		rules := byLang[f.Lang]
		if len(rules) == 0 || isTestPath(f.Rel) {
			continue
		}
		text, err := walk.ReadText(f.Abs)
		if err != nil {
			// One unreadable file must not hide the leads from the rest.
			if firstErr == nil {
				firstErr = fmt.Errorf("built-in code rules could not read %s: %w; check the file's permissions and rerun", f.Rel, err)
			}
			continue
		}
		leads = append(leads, matchRules(rules, f.Rel, text)...)
	}
	return leads, firstErr
}

func matchRules(rules []*Rule, rel, text string) []Lead {
	var leads []Lead
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isCommentLine(trimmed) {
			continue
		}
		for _, r := range rules {
			if !r.Pattern.MatchString(line) {
				continue
			}
			if r.Exclude != nil && r.Exclude.MatchString(line) {
				continue
			}
			if r.Require != nil && !r.Require.MatchString(line) {
				continue
			}
			if r.Near != nil && !nearMatch(r.Near, lines, i, r.NearLines) {
				continue
			}
			l := Lead{
				RuleID:   r.ID,
				Title:    r.Title,
				Class:    r.Class,
				Surface:  finding.SurfaceCode,
				CWE:      []string{r.CWE},
				Severity: r.Severity,
				File:     rel,
				Line:     i + 1,
				Snippet:  snippet(line),
				Detail:   r.Detail,
				Fix:      r.Fix,
			}
			if r.OWASP != "" {
				l.OWASP = []string{r.OWASP}
			}
			leads = append(leads, l)
		}
	}
	return leads
}

func nearMatch(re *regexp.Regexp, lines []string, i, window int) bool {
	lo, hi := max(i-window, 0), min(i+window, len(lines)-1)
	for j := lo; j <= hi; j++ {
		if t := strings.TrimSpace(lines[j]); !isCommentLine(t) && re.MatchString(lines[j]) {
			return true
		}
	}
	return false
}
