// Package redact finds secrets in text and replaces them with markers. It
// is used by seeders, which report where a secret is but never its value,
// and by the provider wrapper, which redacts everything sent to a model.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Match is one secret found in a text. It deliberately has no field for the
// value: the hash is enough to tell two secrets apart and to recognize the
// same secret in two places without ever storing it.
type Match struct {
	Rule  string // rule name, see Rules
	Start int    // byte offset of the secret in the scanned text
	End   int    // byte offset just past the secret
	Line  int    // 1-based line of Start
	Hash  string // first 8 hex digits of sha256(value)
}

// rule is one detector. Group selects the capture group that holds the
// secret (0 is the whole match), so a rule can use surrounding context to
// be precise while redacting only the value. A rule with several
// alternative groups lists them all and the first one that took part wins.
type rule struct {
	name   string
	re     *regexp.Regexp
	groups []int
	// keep, when set, is a final check on the candidate value. It exists
	// because RE2 has no lookaround and some rules need to reject
	// placeholders and low-entropy strings.
	keep func(value string) bool
}

const genericNames = `password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[_-]?token|access[_-]?key|client[_-]?secret`

// rules are ordered by priority: when two rules claim exactly the same
// bytes, the earlier rule names the match. Specific token formats therefore
// come before the generic assignment rule, and anthropic-key comes before
// openai-key because every Anthropic key also fits the OpenAI pattern.
var rules = []rule{
	{
		name: "private-key-block",
		re:   regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
	},
	{
		name: "aws-access-key-id",
		re:   regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	},
	{
		name:   "aws-secret-access-key",
		re:     regexp.MustCompile(`(?i)aws[a-z0-9_.-]*secret[a-z0-9_.-]*["']?\s*(?::=|=>|=|:)\s*["']?([a-z0-9/+]{40})(?:[^a-z0-9/+=]|$)`),
		groups: []int{1},
	},
	{
		name: "github-token",
		re:   regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b`),
	},
	{
		name: "gitlab-token",
		re:   regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`),
	},
	{
		name: "slack-token",
		re:   regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`),
	},
	{
		name: "slack-webhook",
		re:   regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9_/+-]{20,}`),
	},
	{
		name: "stripe-key",
		re:   regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{24,}`),
	},
	{
		name: "google-api-key",
		re:   regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`),
	},
	{
		name: "anthropic-key",
		re:   regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`),
	},
	{
		name: "openai-key",
		re:   regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
	},
	{
		name: "jwt",
		re:   regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`),
	},
	{
		name:   "basic-auth-url",
		re:     regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@"'<>]+:([^\s@/"'<>]+)@[A-Za-z0-9\[]`),
		groups: []int{1},
		keep:   func(v string) bool { return !isPlaceholder(v) },
	},
	{
		name:   "generic-secret",
		re:     regexp.MustCompile(`(?i)(?:` + genericNames + `)[a-z0-9_-]*["']?\s*(?::=|=>|=|:)\s*(?:"([^"\n]{8,})"|'([^'\n]{8,})')`),
		groups: []int{1, 2},
		keep:   func(v string) bool { return !isPlaceholder(v) && entropy(v) >= 3.0 },
	},
}

// marker matches the text Apply writes. Anything overlapping a marker is
// never reported, which is what makes Apply idempotent.
var marker = regexp.MustCompile(`\[REDACTED:[a-z0-9-]+:[0-9a-f]{8}\]`)

// Rules returns the rule names, sorted.
func Rules() []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.name)
	}
	sort.Strings(out)
	return out
}

type candidate struct {
	Match
	prio int
}

// Scan returns the secrets in text, sorted by Start and non-overlapping.
// When candidates overlap, the one that starts earliest wins, then the
// longest, then the more specific rule.
func Scan(text string) []Match {
	if text == "" {
		return nil
	}
	markers := marker.FindAllStringIndex(text, -1)
	var cands []candidate
	for prio, r := range rules {
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := -1, -1
			if len(r.groups) == 0 {
				start, end = loc[0], loc[1]
			}
			for _, g := range r.groups {
				if loc[2*g] >= 0 {
					start, end = loc[2*g], loc[2*g+1]
					break
				}
			}
			if start < 0 || start == end || overlapsAny(markers, start, end) {
				continue
			}
			value := text[start:end]
			if r.keep != nil && !r.keep(value) {
				continue
			}
			sum := sha256.Sum256([]byte(value))
			cands = append(cands, candidate{
				Match: Match{Rule: r.name, Start: start, End: end, Hash: hex.EncodeToString(sum[:])[:8]},
				prio:  prio,
			})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		switch {
		case a.Start != b.Start:
			return a.Start < b.Start
		case a.End != b.End:
			return a.End > b.End
		default:
			return a.prio < b.prio
		}
	})
	var out []Match
	last, line, pos := 0, 1, 0
	for _, c := range cands {
		if c.Start < last {
			continue
		}
		line += strings.Count(text[pos:c.Start], "\n")
		pos = c.Start
		c.Line = line
		out = append(out, c.Match)
		last = c.End
	}
	return out
}

// Marker returns the replacement text for a secret found by rule whose
// value hashes to hash. Seeders that redact a value they located by
// structure (a YAML node, an ENV instruction) use it so every redaction in
// Spackle looks the same and is skipped by a later Apply.
func Marker(rule, hash string) string {
	return "[REDACTED:" + rule + ":" + hash + "]"
}

// Hash returns the 8 hex digit fingerprint used in markers and matches.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

// Apply replaces each secret in text with "[REDACTED:<rule>:<hash>]" and
// returns the new text with the matches, whose offsets refer to the input.
func Apply(text string) (string, []Match) {
	ms := Scan(text)
	if len(ms) == 0 {
		return text, nil
	}
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, m := range ms {
		b.WriteString(text[pos:m.Start])
		b.WriteString(Marker(m.Rule, m.Hash))
		pos = m.End
	}
	b.WriteString(text[pos:])
	return b.String(), ms
}

func overlapsAny(spans [][]int, start, end int) bool {
	for _, s := range spans {
		if start < s[1] && s[0] < end {
			return true
		}
	}
	return false
}

var placeholderWords = []string{
	"changeme", "change_me", "change-me", "example", "placeholder", "xxxx", "****",
	"os.environ", "getenv", "process.env", "${", "{{", "redacted",
}

// isPlaceholder reports whether v is obviously not a real secret: a
// documentation stand-in, a template expression, or a reference to the
// environment. Reporting those would train operators to ignore the rule.
func isPlaceholder(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	if low == "" {
		return true
	}
	for _, w := range placeholderWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	if strings.HasPrefix(low, "your-") || strings.HasPrefix(low, "your_") || strings.HasPrefix(low, "your ") {
		return true
	}
	if strings.HasPrefix(low, "<") && strings.HasSuffix(low, ">") {
		return true
	}
	if strings.HasPrefix(low, "$") || strings.HasPrefix(low, "%") && strings.HasSuffix(low, "%") {
		return true
	}
	return strings.Count(low, low[:1]) == len(low)
}

// IsPlaceholder is isPlaceholder for seeders that find secret-looking
// values by structure and need the same notion of "obviously not real".
func IsPlaceholder(v string) bool { return isPlaceholder(v) }

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
