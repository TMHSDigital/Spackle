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

// commentStyle says how a language writes comments.
type commentStyle struct {
	hash    bool // "#" starts a comment that runs to the end of the line
	slashes bool // "//" does, and "/* ... */" is a block comment
}

func commentStyleOf(lang string) commentStyle {
	switch lang {
	case "python", "ruby", "shell", "yaml", "toml", "dockerfile", "terraform":
		return commentStyle{hash: true}
	case "php":
		return commentStyle{hash: true, slashes: true}
	case "html", "xml":
		return commentStyle{}
	}
	return commentStyle{slashes: true}
}

// stripComments returns the code part of each line: the line with comments
// removed, in the comment syntax of the language. Rules are matched against
// it, so a word in a comment can neither hide a lead nor produce one, and a
// statement that starts with "*" (Go, Python) or "#" (a JavaScript private
// member) is still code. Comment markers inside string literals are kept.
// It is a line scanner, not a parser: when in doubt it keeps the text.
func stripComments(lines []string, st commentStyle) []string {
	out := make([]string, len(lines))
	inBlock := false
	for n, line := range lines {
		var b strings.Builder
		var quote byte
		for i := 0; i < len(line); i++ {
			c := line[i]
			next := byte(0)
			if i+1 < len(line) {
				next = line[i+1]
			}
			switch {
			case inBlock:
				if c == '*' && next == '/' {
					inBlock = false
					i++
				}
				continue
			case quote != 0:
				b.WriteByte(c)
				if c == '\\' && next != 0 {
					b.WriteByte(next)
					i++
				} else if c == quote {
					quote = 0
				}
				continue
			case c == '"' || c == '\'' || c == '`':
				quote = c
			case st.hash && c == '#':
				i = len(line)
				continue
			case st.slashes && c == '/' && next == '/':
				i = len(line)
				continue
			case st.slashes && c == '/' && next == '*' && !inRegexLiteral(line, i):
				inBlock = true
				i++
				continue
			}
			b.WriteByte(c)
		}
		out[n] = b.String()
	}
	return out
}

// inRegexLiteral guesses whether the "/*" at i sits inside a regular
// expression literal such as /\/*$/ or /[/*]/, where it is not a comment.
// Reading it as one would hide every following line up to the next "*/".
func inRegexLiteral(line string, i int) bool {
	return i > 0 && (line[i-1] == '\\' || line[i-1] == '[')
}

func (s codeSeeder) Run(ctx context.Context, _ string, files []walk.File) ([]Lead, error) {
	byLang := map[string][]*Rule{}
	for i := range s.rules {
		for _, l := range s.rules[i].Langs {
			byLang[l] = append(byLang[l], &s.rules[i])
		}
	}
	return eachFile(ctx, "built-in code rules", files, func(f walk.File) ([]Lead, error) {
		rules := byLang[f.Lang]
		if len(rules) == 0 || isTestPath(f.Rel) {
			return nil, nil
		}
		text, err := walk.ReadText(f.Abs)
		if err != nil {
			// One unreadable file must not hide the leads from the rest.
			return nil, fmt.Errorf("built-in code rules could not read %s: %w; check the file's permissions and rerun", f.Rel, err)
		}
		return matchRules(rules, f.Lang, f.Rel, text), nil
	})
}

func matchRules(rules []*Rule, lang, rel, text string) []Lead {
	var leads []Lead
	lines := strings.Split(text, "\n")
	code := stripComments(lines, commentStyleOf(lang))
	for i, line := range lines {
		c := strings.TrimRight(code[i], " \t")
		if strings.TrimSpace(c) == "" {
			continue // blank, or nothing but a comment
		}
		for _, r := range rules {
			if !r.Pattern.MatchString(c) {
				continue
			}
			if r.Exclude != nil && r.Exclude.MatchString(c) {
				continue
			}
			if r.Require != nil && !r.Require.MatchString(c) {
				continue
			}
			if r.Near != nil && !nearMatch(r.Near, code, i, r.NearLines) {
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
			// The OWASP categories come from the class table, so a finding
			// carries the same labels whether a rule or a model produced
			// it. The rule's own label is used only for a class that has
			// none there.
			if owasp := finding.Info(r.Class).OWASP; len(owasp) > 0 {
				l.OWASP = append([]string(nil), owasp...)
			} else if r.OWASP != "" {
				l.OWASP = []string{r.OWASP}
			}
			leads = append(leads, l)
		}
	}
	return leads
}

// nearMatch looks for re in the code part of the lines around i.
func nearMatch(re *regexp.Regexp, code []string, i, window int) bool {
	lo, hi := max(i-window, 0), min(i+window, len(code)-1)
	for j := lo; j <= hi; j++ {
		if re.MatchString(code[j]) {
			return true
		}
	}
	return false
}
