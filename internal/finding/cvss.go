package finding

import (
	"fmt"
	"strings"

	gocvss40 "github.com/pandatix/go-cvss/40"
)

// Score validates a CVSS 4.0 vector and returns its score and the
// lowercase qualitative rating (critical, high, medium, low, none).
func Score(vector string) (float64, string, error) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:4.0/") {
		return 0, "", fmt.Errorf("%q is not a CVSS 4.0 vector: it must start with CVSS:4.0/", vector)
	}
	v, err := gocvss40.ParseVector(vector)
	if err != nil {
		return 0, "", fmt.Errorf("invalid CVSS 4.0 vector %q: %w", vector, err)
	}
	score := v.Score()
	rating, err := gocvss40.Rating(score)
	if err != nil {
		return 0, "", fmt.Errorf("rate CVSS score %.1f: %w", score, err)
	}
	return score, strings.ToLower(rating), nil
}

// SeverityFromVector builds a Severity from a vector, computing the score
// and label.
func SeverityFromVector(vector, reasoning string) (Severity, error) {
	score, label, err := Score(vector)
	if err != nil {
		return Severity{}, err
	}
	return Severity{Vector: strings.TrimSpace(vector), Score: score, Label: label, Reasoning: reasoning}, nil
}

// Default vectors for leads that have not been investigated. They describe
// the typical worst plausible case for the class and are refined by an
// investigator when a model is in use. Using a real vector, rather than a
// bare label, keeps every score reproducible and explainable.
var classVectors = map[string]string{ //nolint:gosec // CVSS vectors keyed by class name, not credentials
	"sql-injection":           "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
	"command-injection":       "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	"code-injection":          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	"unsafe-deserialization":  "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	"template-injection":      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	"path-traversal":          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
	"ssrf":                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:H/SI:L/SA:N",
	"xss":                     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
	"open-redirect":           "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
	"hardcoded-secret":        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
	"weak-crypto":             "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
	"weak-hash":               "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
	"insecure-random":         "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
	"tls-verification":        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
	"jwt-verification":        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
	"auth-bypass":             "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
	"broken-access-control":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
	"cors-misconfiguration":   "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
	"debug-enabled":           "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
	"information-disclosure":  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
	"missing-security-header": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
	"insecure-cookie":         "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
	"race-condition":          "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
	"vulnerable-dependency":   "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
	"container-privilege":     "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
	"container-hardening":     "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
	"supply-chain":            "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	"ci-injection":            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N",
	"ci-permissions":          "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
	"network-exposure":        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
	"public-storage":          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
	"unencrypted-storage":     "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
	"denial-of-service":       "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
	"xxe":                     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:L/SI:N/SA:N",
	"prototype-pollution":     "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N",
	"mass-assignment":         "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
	"directory-listing":       "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
	"exposed-file":            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
}

// DefaultVector returns the starting CVSS 4.0 vector for a class, and
// whether the class is known.
func DefaultVector(class string) (string, bool) {
	v, ok := classVectors[class]
	return v, ok
}

// Classes returns every class that has a default vector.
func Classes() []string {
	out := make([]string, 0, len(classVectors))
	for c := range classVectors {
		out = append(out, c)
	}
	return out
}
