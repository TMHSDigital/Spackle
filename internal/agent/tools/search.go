package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/walk"
)

const (
	defaultGrepResults = 60
	maxGrepResults     = 200
	maxGrepContext     = 3
	// maxLineLen keeps minified bundles and data blobs out of results: one
	// such line can be megabytes and says nothing a model can use.
	maxLineLen        = 2000
	maxPatternLen     = 1000
	maxSymbolResults  = 50
	maxRefResults     = 100
	maxIdentifierSize = 100
)

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type grepArgs struct {
	Pattern    string `json:"pattern"`
	Path       string `json:"path"`
	Glob       string `json:"glob"`
	MaxResults int    `json:"max_results"`
	Context    int    `json:"context"`
}

func (r *Registry) grepTool() builtin {
	return builtin{
		def: llm.ToolDef{
			Name:        "grep",
			Description: "Search the target's text files with an RE2 regular expression (no lookaround, no backreferences), one line at a time. Output is file:line: text, sorted by file then line.",
			Schema: schema(`"pattern":{"type":"string","description":"RE2 regular expression matched against each line."},`+
				`"path":{"type":"string","description":"Directory or file to search, relative to the target root. Default: the whole target."},`+
				`"glob":{"type":"string","description":"File name filter such as *.py, or a path filter such as **/handlers/*.go."},`+
				`"max_results":{"type":"integer","minimum":1,"maximum":200,"description":"Matching lines to return. Default 60, at most 200."},`+
				`"context":{"type":"integer","minimum":0,"maximum":3,"description":"Lines of context around each match, 0 to 3. Default 0."}`, "pattern"),
		},
		fn: r.grep,
	}
}

func (r *Registry) grep(ctx context.Context, raw json.RawMessage) (label, text string, err error) {
	var a grepArgs
	if err := decode(raw, &a); err != nil {
		return "", "", err
	}
	switch {
	case a.Pattern == "":
		return "", "", errors.New("pattern is required; pass an RE2 regular expression")
	case len(a.Pattern) > maxPatternLen:
		return "", "", fmt.Errorf("pattern is %d bytes, over the %d byte limit; use a shorter pattern", len(a.Pattern), maxPatternLen)
	}
	re, err := regexp.Compile(a.Pattern)
	if err != nil {
		return "", "", fmt.Errorf("pattern does not compile (%s); use RE2 syntax and escape literal ( ) [ ] { } . * + ? | with a backslash", clip(err.Error(), 160))
	}
	if a.Glob != "" {
		if _, err := path.Match(strings.TrimPrefix(a.Glob, "**/"), ""); err != nil {
			return "", "", fmt.Errorf("glob %s is malformed; use a pattern such as *.py or **/handlers/*.go", quote(a.Glob))
		}
	}
	limit := a.MaxResults
	if limit <= 0 {
		limit = defaultGrepResults
	}
	limit = min(limit, maxGrepResults)
	around := min(max(a.Context, 0), maxGrepContext)

	files, err := r.scope(a.Path)
	if err != nil {
		return "", "", err
	}

	var b strings.Builder
	matches, searched, longLines := 0, 0, 0
	more := false
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return "", "", errors.New("the search was cancelled before it finished; narrow it with path or glob and try again")
		}
		if a.Glob != "" && !globMatch(a.Glob, f.Rel) {
			continue
		}
		content, err := r.text(f.Abs)
		if err != nil {
			continue // unreadable since listing; nothing useful to report per file
		}
		searched++
		lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
		var hits []int
		for i, line := range lines {
			if len(line) > maxLineLen {
				longLines++
				continue
			}
			if !re.MatchString(line) {
				continue
			}
			if matches == limit {
				more = true
				break
			}
			matches++
			hits = append(hits, i)
		}
		writeHits(&b, f.Rel, lines, hits, around)
		if more {
			break
		}
	}

	label = "grep \"" + clip(a.Pattern, 100) + "\""
	if matches == 0 {
		fmt.Fprintf(&b, "[no matches in %d files]\n", searched)
	}
	if more {
		fmt.Fprintf(&b, "[stopped at %d matches; more exist: narrow the pattern, path or glob]\n", limit)
	}
	if longLines > 0 {
		fmt.Fprintf(&b, "[%d lines longer than %d bytes were not searched]\n", longLines, maxLineLen)
	}
	return label, b.String(), nil
}

// writeHits prints the matching lines of one file, with context. Matching
// lines use "file:line: text"; context lines use "file-line- text", and
// "--" separates groups that are not adjacent, as grep does.
func writeHits(b *strings.Builder, rel string, lines []string, hits []int, around int) {
	isHit := make(map[int]bool, len(hits))
	for _, h := range hits {
		isHit[h] = true
	}
	if around > 0 && len(hits) > 0 && b.Len() > 0 {
		b.WriteString("--\n") // a new file is never adjacent to the previous group
	}
	last := -1
	for _, h := range hits {
		for i := max(h-around, 0, last+1); i <= min(h+around, len(lines)-1); i++ {
			if last >= 0 && i > last+1 {
				b.WriteString("--\n")
			}
			line := lines[i]
			switch {
			case isHit[i]:
				fmt.Fprintf(b, "%s:%d: %s\n", rel, i+1, line)
			case len(line) > maxLineLen:
				fmt.Fprintf(b, "%s-%d- [line longer than %d bytes not shown]\n", rel, i+1, maxLineLen)
			default:
				fmt.Fprintf(b, "%s-%d- %s\n", rel, i+1, line)
			}
			last = i
		}
	}
}

// scope returns the listed files under a model-supplied path (all of them
// when the path is empty or the root).
func (r *Registry) scope(p string) ([]walk.File, error) {
	files, err := r.files()
	if err != nil {
		return nil, err
	}
	if p == "" {
		return files, nil
	}
	abs, rel, err := r.resolve(p)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return files, nil
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read (%s); check the path with list_dir", rel, reason(err))
	}
	var out []walk.File
	for _, f := range files {
		if f.Rel == rel || (fi.IsDir() && strings.HasPrefix(f.Rel, rel+"/")) {
			out = append(out, f)
		}
	}
	if len(out) == 0 && !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a searchable text file (it is binary, too large, or in a skipped directory); search another path", rel)
	}
	return out, nil
}

// globMatch reports whether a forward-slash relative path matches glob. A
// glob without a slash is matched against the base name. A glob with a
// slash is matched against the whole path, and a leading "**/" lets it
// match at any depth.
func globMatch(glob, rel string) bool {
	rest, anyDepth := strings.CutPrefix(glob, "**/")
	for strings.HasPrefix(rest, "**/") {
		rest = strings.TrimPrefix(rest, "**/")
	}
	if !strings.Contains(rest, "/") {
		ok, _ := path.Match(rest, path.Base(rel))
		return ok
	}
	if ok, _ := path.Match(rest, rel); ok {
		return true
	}
	if !anyDepth {
		return false
	}
	for i := 0; i < len(rel); i++ {
		if rel[i] != '/' {
			continue
		}
		if ok, _ := path.Match(rest, rel[i+1:]); ok {
			return true
		}
	}
	return false
}

type nameArgs struct {
	Name string `json:"name"`
}

// checkName validates an identifier argument.
func checkName(raw json.RawMessage) (string, error) {
	var a nameArgs
	if err := decode(raw, &a); err != nil {
		return "", err
	}
	switch {
	case a.Name == "":
		return "", errors.New("name is required; pass one identifier such as get_user")
	case len(a.Name) > maxIdentifierSize || !identifier.MatchString(a.Name):
		return "", fmt.Errorf("name %s is not a plain identifier; pass one name matching ^[A-Za-z_][A-Za-z0-9_]*$ (no dots, spaces or regex), or use grep for patterns", quote(a.Name))
	}
	return a.Name, nil
}

// definitionPatterns returns, per walk language, the regexes that recognize
// a definition of name. name is a validated identifier, so it needs no
// quoting inside a pattern.
func definitionPatterns(name string) map[string][]*regexp.Regexp {
	compile := func(exprs ...string) []*regexp.Regexp {
		out := make([]*regexp.Regexp, 0, len(exprs))
		for _, e := range exprs {
			out = append(out, regexp.MustCompile(strings.ReplaceAll(e, "NAME", name)))
		}
		return out
	}
	script := compile(
		`\bfunction\s*\*?\s*NAME\b`,
		`\bclass\s+NAME\b`,
		`\b(?:const|let|var)\s+NAME\s*(?::[^=]+)?=`,
		`^\s*(?:(?:public|private|protected|static|async|readonly|override|get|set)\s+)*\*?\s*NAME\s*(?:<[^>]*>)?\([^)]*\)\s*(?::[^{]+)?\{`,
		`^\s*export\s+(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(?:function\*?|class|const|let|var|interface|type|enum|namespace)\s+NAME\b`,
		`^\s*(?:declare\s+)?(?:interface|type|enum|namespace)\s+NAME\b`,
	)
	return map[string][]*regexp.Regexp{
		"go": compile(
			`^func\s+NAME\s*[(\[]`,
			`^func\s*\([^)]*\)\s*NAME\s*[(\[]`,
			`^\s*type\s+NAME\b`,
			`^(?:var|const)\s+NAME\b`,
		),
		"python": compile(
			`^\s*(?:async\s+)?def\s+NAME\s*\(`,
			`^\s*class\s+NAME\b`,
			`^NAME\s*(?::[^=]+)?=(?:[^=]|$)`,
		),
		"javascript": script,
		"typescript": script,
	}
}

type hit struct {
	rel  string
	line int
	text string
}

// scan runs keep over every line of every listed file that mentions name.
func (r *Registry) scan(ctx context.Context, name string, keep func(f walk.File, line string) bool) ([]hit, error) {
	files, err := r.files()
	if err != nil {
		return nil, err
	}
	var hits []hit
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, errors.New("the search was cancelled before it finished; try again")
		}
		content, err := r.text(f.Abs)
		if err != nil || !strings.Contains(content, name) {
			continue
		}
		for i, line := range strings.Split(content, "\n") {
			if len(line) > maxLineLen || !strings.Contains(line, name) {
				continue
			}
			if keep(f, line) {
				hits = append(hits, hit{rel: f.Rel, line: i + 1, text: line})
			}
		}
	}
	return hits, nil
}

func (r *Registry) definitions(ctx context.Context, name string) ([]hit, error) {
	pats := definitionPatterns(name)
	return r.scan(ctx, name, func(f walk.File, line string) bool {
		for _, re := range pats[f.Lang] {
			if re.MatchString(line) {
				return true
			}
		}
		return false
	})
}

func writeCapped(b *strings.Builder, hits []hit, limit int, what string) {
	for i, h := range hits {
		if i == limit {
			fmt.Fprintf(b, "[%d more %s not shown; use grep with a path to narrow the search]\n", len(hits)-limit, what)
			return
		}
		fmt.Fprintf(b, "%s:%d: %s\n", h.rel, h.line, h.text)
	}
}

func (r *Registry) findSymbolTool() builtin {
	return builtin{
		def: llm.ToolDef{
			Name:        "find_symbol",
			Description: "Find where a function, method, class, type or top-level variable is defined, by exact name, in Go, Python, JavaScript and TypeScript files. Output is file:line: text, at most 50 results.",
			Schema:      schema(`"name":{"type":"string","description":"Exact identifier, for example get_user. Not a pattern."}`, "name"),
		},
		fn: func(ctx context.Context, raw json.RawMessage) (string, string, error) {
			name, err := checkName(raw)
			if err != nil {
				return "", "", err
			}
			defs, err := r.definitions(ctx, name)
			if err != nil {
				return "", "", err
			}
			var b strings.Builder
			if len(defs) == 0 {
				fmt.Fprintf(&b, "[no definition of %s found in Go, Python, JavaScript or TypeScript files; try grep]\n", name)
			}
			writeCapped(&b, defs, maxSymbolResults, "definitions")
			return "find_symbol " + name, b.String(), nil
		},
	}
}

func (r *Registry) findReferencesTool() builtin {
	return builtin{
		def: llm.ToolDef{
			Name:        "find_references",
			Description: "Find every line that uses an identifier as a whole word, in any text file, leaving out the lines where it is defined (see find_symbol). Output is file:line: text, at most 100 results plus a count of the rest.",
			Schema:      schema(`"name":{"type":"string","description":"Exact identifier, for example get_user. Not a pattern."}`, "name"),
		},
		fn: func(ctx context.Context, raw json.RawMessage) (string, string, error) {
			name, err := checkName(raw)
			if err != nil {
				return "", "", err
			}
			defs, err := r.definitions(ctx, name)
			if err != nil {
				return "", "", err
			}
			type site struct {
				rel  string
				line int
			}
			isDef := make(map[site]bool, len(defs))
			for _, d := range defs {
				isDef[site{d.rel, d.line}] = true
			}
			word := regexp.MustCompile(`\b` + name + `\b`)
			all, err := r.scan(ctx, name, func(_ walk.File, line string) bool { return word.MatchString(line) })
			if err != nil {
				return "", "", err
			}
			refs := all[:0]
			for _, h := range all {
				if !isDef[site{h.rel, h.line}] {
					refs = append(refs, h)
				}
			}
			var b strings.Builder
			if len(refs) == 0 {
				fmt.Fprintf(&b, "[no references to %s found outside its definitions]\n", name)
			}
			writeCapped(&b, refs, maxRefResults, "references")
			return "find_references " + name, b.String(), nil
		},
	}
}
