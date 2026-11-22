package seed

import (
	"regexp"
	"strings"

	"github.com/TMHSDigital/spackle/internal/redact"
)

// Builtin returns the seeders that need nothing installed.
func Builtin() []Seeder {
	return []Seeder{codeSeeder{rules: codeRules}, secretsSeeder{}, infraSeeder{}}
}

// All returns the built-in seeders followed by the scanner adapters.
func All() []Seeder {
	return append(Builtin(), External()...)
}

// maxSnippet bounds Lead.Snippet so one minified line cannot bloat a report
// or a model prompt.
const maxSnippet = 200

// snippet prepares a source line for Lead.Snippet: trimmed, redacted, then
// truncated. Redaction runs before truncation so a cut can never expose the
// tail of a secret that a shorter text would no longer match.
func snippet(line string) string {
	out, _ := redact.Apply(strings.TrimSpace(line))
	return truncate(out, maxSnippet)
}

func truncate(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit])
}

// lineAt returns the 1-based line of lines, or "" when out of range.
func lineAt(lines []string, n int) string {
	if n < 1 || n > len(lines) {
		return ""
	}
	return lines[n-1]
}

// secretName matches configuration names that usually hold a credential.
var secretName = regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)`)

// secretNameSuffixes mark names that point at a secret rather than hold
// one, such as DB_PASSWORD_FILE.
var secretNameSuffixes = []string{"_file", "_path", "_dir", "_url", "_name", "_id", "_ttl", "_expiry", "_length"}

// looksLikeSecretPair reports whether name and value look like a credential
// written directly into configuration.
func looksLikeSecretPair(name, value string) bool {
	if !secretName.MatchString(name) {
		return false
	}
	low := strings.ToLower(name)
	for _, suf := range secretNameSuffixes {
		if strings.HasSuffix(low, suf) {
			return false
		}
	}
	value = strings.TrimSpace(value)
	if len(value) < 4 || redact.IsPlaceholder(value) {
		return false
	}
	switch strings.ToLower(value) {
	case "true", "false", "null", "none", "nil":
		return false
	}
	return true
}

// redactedValue is the marker that stands in for value in a snippet.
func redactedValue(rule, value string) string {
	return redact.Marker(rule, redact.Hash(value))
}
