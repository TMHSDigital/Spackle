package seed

import (
	"context"
	"fmt"
	"strings"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/walk"
)

type secretsSeeder struct{}

func (secretsSeeder) Name() string { return "builtin-secrets" }

func (secretsSeeder) Available() (bool, string) { return true, "" }

// lockfiles hold long hashes and integrity strings that look like secrets
// and never are.
var lockfiles = map[string]bool{
	"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true,
	"pnpm-lock.yaml": true, "go.sum": true, "cargo.lock": true, "poetry.lock": true,
	"pipfile.lock": true, "composer.lock": true, "gemfile.lock": true, "uv.lock": true,
	"bun.lock": true, "flake.lock": true,
}

func skipForSecrets(rel string) bool {
	base := strings.ToLower(rel[strings.LastIndex(rel, "/")+1:])
	if lockfiles[base] {
		return true
	}
	for _, suf := range []string{".min.js", ".min.css", ".map"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

// criticalSecretRules are credentials that grant broad access on their own.
var criticalSecretRules = map[string]bool{
	"private-key-block": true, "aws-secret-access-key": true, "stripe-key": true,
}

func (secretsSeeder) Run(ctx context.Context, _ string, files []walk.File) ([]Lead, error) {
	var leads []Lead
	var firstErr error
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return leads, fmt.Errorf("built-in secret scan stopped early: %w; rerun the scan to cover the remaining files", err)
		}
		if skipForSecrets(f.Rel) {
			continue
		}
		text, err := walk.ReadText(f.Abs)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("built-in secret scan could not read %s: %w; check the file's permissions and rerun", f.Rel, err)
			}
			continue
		}
		leads = append(leads, secretLeads(f.Rel, text)...)
	}
	return leads, firstErr
}

func secretLeads(rel, text string) []Lead {
	matches := redact.Scan(text)
	leads := make([]Lead, 0, len(matches))
	for _, m := range matches {
		sev := "high"
		if criticalSecretRules[m.Rule] {
			sev = "critical"
		}
		l := Lead{
			RuleID:   m.Rule,
			Title:    "Hardcoded secret (" + m.Rule + ")",
			Class:    "hardcoded-secret",
			Surface:  finding.SurfaceCode,
			CWE:      []string{"CWE-798"},
			OWASP:    []string{owaspAuth},
			Severity: sev,
			File:     rel,
			Line:     m.Line,
			Snippet:  truncate(strings.TrimSpace(redactedLine(text, matches, m)), maxSnippet),
			Detail:   fmt.Sprintf("Rule %s matched a value with fingerprint %s. A credential stored in the repository is readable by everyone with access to the code and its history.", m.Rule, m.Hash),
			Fix:      "Revoke and rotate this credential, then load the new one from the environment or a secret manager. Removing the line is not enough because the value stays in version control history.",
		}
		if end := m.Line + strings.Count(text[m.Start:m.End], "\n"); end > m.Line {
			l.EndLine = end
		}
		leads = append(leads, l)
	}
	return leads
}

// redactedLine returns the line on which m starts with every match that
// touches the line replaced by its marker. It works from the matches of the
// whole text rather than rescanning the line, because a multi-line secret
// cut down to one line would no longer match and would leak.
func redactedLine(text string, matches []redact.Match, m redact.Match) string {
	ls := strings.LastIndexByte(text[:m.Start], '\n') + 1
	le := len(text)
	if i := strings.IndexByte(text[m.Start:], '\n'); i >= 0 {
		le = m.Start + i
	}
	var b strings.Builder
	pos := ls
	for _, o := range matches {
		if o.End <= ls || o.Start >= le {
			continue
		}
		if o.Start > pos {
			b.WriteString(text[pos:o.Start])
		}
		b.WriteString(redact.Marker(o.Rule, o.Hash))
		pos = max(pos, o.End)
	}
	if pos < le {
		b.WriteString(text[pos:le])
	}
	return b.String()
}
