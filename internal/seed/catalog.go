package seed

import (
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/redact"
)

// RuleInfo describes one built-in rule for a listing: what `spackle rules`
// prints and what `[scan] disable_rules` can name.
type RuleInfo struct {
	Source   string   `json:"source"` // the seeder that reports it
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Class    string   `json:"class"`
	Severity string   `json:"severity"`
	CWE      string   `json:"cwe"`
	Langs    []string `json:"languages"`
}

// infraChecks lists every infrastructure check. A new check must be added
// here; a test compares this list with the checks defined in the package.
var infraChecks = []infraCheck{
	dockerNoUser, dockerUserRoot, dockerFromLatest, dockerAddRemote, dockerCurlPipe, dockerEnvSecret, dockerPrivileged, dockerChmod777,
	k8sPrivileged, k8sHostNamespace, k8sHostPath, k8sPrivEsc, k8sRunAsRoot, k8sNoLimits, k8sImageLatest, k8sEnvSecret,
	tfPublicACL, tfPublicBlockOff, tfOpenIngress, tfUnencrypted, tfPublicDB, tfSecret,
	wfPwnRequest, wfRunInjection, wfUnpinnedAction, wfWriteAll, wfNoPermissions,
}

// infraLang names the files an infrastructure check reads, from its id.
func infraLang(id string) string {
	switch {
	case strings.HasPrefix(id, "docker-"):
		return "dockerfile"
	case strings.HasPrefix(id, "k8s-"):
		return "kubernetes"
	case strings.HasPrefix(id, "tf-"):
		return "terraform"
	case strings.HasPrefix(id, "workflow-"):
		return "github-actions"
	}
	return ""
}

// BuiltinRules lists every rule of the built-in seeders, by source and id.
func BuiltinRules() []RuleInfo {
	var out []RuleInfo
	for _, r := range codeRules {
		out = append(out, RuleInfo{Source: codeSeeder{}.Name(), ID: r.ID, Title: r.Title, Class: r.Class, Severity: r.Severity, CWE: r.CWE, Langs: r.Langs})
	}
	for _, c := range infraChecks {
		out = append(out, RuleInfo{Source: infraSeeder{}.Name(), ID: c.id, Title: c.title, Class: c.class, Severity: c.severity, CWE: c.cwe, Langs: []string{infraLang(c.id)}})
	}
	for _, name := range redact.Rules() {
		sev := "high"
		if criticalSecretRules[name] {
			sev = "critical"
		}
		out = append(out, RuleInfo{Source: secretsSeeder{}.Name(), ID: name, Title: "Hardcoded secret (" + name + ")", Class: "hardcoded-secret", Severity: sev, CWE: "CWE-798", Langs: []string{"any"}})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// UnknownBuiltinRules returns the entries of a disable_rules list that look
// like built-in rule ids (a built-in prefix such as py- or docker-, or a
// builtin-* source) but name no built-in rule, which is most likely a typo.
// Other ids may belong to an external scanner and are not checked.
func UnknownBuiltinRules(ids []string) []string {
	known := map[string]bool{}
	prefixes := map[string]bool{}
	sources := map[string]bool{}
	for _, r := range BuiltinRules() {
		known[r.ID] = true
		known[r.Source+":"+r.ID] = true
		sources[r.Source] = true
		if i := strings.Index(r.ID, "-"); i > 0 && r.Source != (secretsSeeder{}).Name() {
			prefixes[r.ID[:i+1]] = true
		}
	}
	var unknown []string
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if known[id] {
			continue
		}
		looksBuiltin := false
		if i := strings.LastIndex(id, ":"); i >= 0 {
			looksBuiltin = sources[id[:i]]
		} else if j := strings.Index(id, "-"); j > 0 {
			looksBuiltin = prefixes[id[:j+1]]
		}
		if looksBuiltin {
			unknown = append(unknown, id)
		}
	}
	return unknown
}
