package seed

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/finding"
)

// Secrets are assembled at run time so no realistic token literal is ever
// committed; see the note in internal/redact/redact_test.go.
var (
	testAWSKeyID  = "AKIA" + "IOSFODNN7EXAMPLE"
	testAWSSecret = "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYEXAMPLEKEY"
	testGitHub    = "gh" + "p_" + strings.Repeat("a1B2", 9)
	testStripe    = "sk" + "_live_" + strings.Repeat("4eC3", 6)
	// testRandomToken is shaped like a GitHub token with enough entropy that
	// scanners with entropy filters (gitleaks) still report it.
	testRandomToken = "gh" + "p_" + "x7Kq9LmZ2vTn4RbW" + "8cYd6FhJ1sPg3AeU5oIt"
	testPassword    = "Tr0ub4dor" + "&3xQz9!"
	testKeyBody     = "MIIEpAIBAAKCAQEA7x" + "Zq3vN8"
	testPEM         = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + testKeyBody + "\n" + testKeyBody + "\n-----END RSA " + "PRIVATE KEY-----"
)

var plantedSecrets = []string{testRandomToken, testAWSKeyID, testAWSSecret, testGitHub, testStripe, testPassword, testKeyBody}

// assertNoSecret fails if any planted secret appears in the JSON encoding
// of the leads, which is what reaches reports, the ledger and a model.
func assertNoSecret(t *testing.T, leads []Lead) {
	t.Helper()
	b, err := json.Marshal(leads)
	if err != nil {
		t.Fatal(err)
	}
	// JSON escapes & as &, so compare against the decoded form too.
	var decoded any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	flat := string(b) + "\n" + flatten(decoded)
	for _, s := range plantedSecrets {
		if strings.Contains(flat, s) {
			t.Errorf("a planted secret (%d bytes, starting %q) appears in the encoded leads", len(s), s[:4])
		}
	}
}

func flatten(v any) string {
	switch x := v.(type) {
	case string:
		return x + "\n"
	case []any:
		var b strings.Builder
		for _, e := range x {
			b.WriteString(flatten(e))
		}
		return b.String()
	case map[string]any:
		var b strings.Builder
		for _, e := range x {
			b.WriteString(flatten(e))
		}
		return b.String()
	}
	return ""
}

func TestSecretsSeeder(t *testing.T) {
	root, files := writeTree(t, map[string]string{
		"config/settings.py": "import os\nAWS_ACCESS_KEY_ID = \"" + testAWSKeyID + "\"\nAWS_SECRET_ACCESS_KEY = \"" + testAWSSecret + "\"\n\ndb_password = \"" + testPassword + "\"\nregion = \"us-east-1\"\n",
		"deploy/key.pem":     "# deploy key\n" + testPEM + "\n",
		"ci.sh":              "export GH=" + testGitHub + " STRIPE=" + testStripe + "\n",
		"crlf.env":           "A=1\r\nTOKEN=" + testGitHub + "\r\n",
		"clean.go":           "package clean\n\nconst password = \"changeme\"\n",
		// Lockfiles and minified bundles are skipped.
		"package-lock.json": "{\"token\": \"" + testGitHub + "\"}\n",
		"go.sum":            "example.com/x v1.0.0 h1:" + testGitHub + "\n",
		"yarn.lock":         testGitHub + "\n",
		"web/app.min.js":    "var t=\"" + testGitHub + "\";\n",
	})
	leads, err := secretsSeeder{}.Run(context.Background(), root, files)
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		file, rule, severity string
		line                 int
	}
	wants := []want{
		{"config/settings.py", "aws-access-key-id", "high", 2},
		{"config/settings.py", "aws-secret-access-key", "critical", 3},
		{"config/settings.py", "generic-secret", "high", 5},
		{"deploy/key.pem", "private-key-block", "critical", 2},
		{"ci.sh", "github-token", "high", 1},
		{"ci.sh", "stripe-key", "critical", 1},
		{"crlf.env", "github-token", "high", 2},
	}
	if len(leads) != len(wants) {
		for _, l := range leads {
			t.Logf("lead %s:%d %s", l.File, l.Line, l.RuleID)
		}
		t.Fatalf("got %d leads, want %d", len(leads), len(wants))
	}
	for _, w := range wants {
		var found *Lead
		for i := range leads {
			if leads[i].File == w.file && leads[i].RuleID == w.rule {
				found = &leads[i]
			}
		}
		if found == nil {
			t.Errorf("missing lead %+v", w)
			continue
		}
		if found.Line != w.line || found.Severity != w.severity {
			t.Errorf("%s %s: line %d severity %s, want line %d severity %s", w.file, w.rule, found.Line, found.Severity, w.line, w.severity)
		}
		if found.Class != "hardcoded-secret" || len(found.CWE) != 1 || found.CWE[0] != "CWE-798" || found.Surface != finding.SurfaceCode {
			t.Errorf("unexpected fields: %+v", *found)
		}
		if !strings.Contains(found.Detail, w.rule) || !strings.Contains(found.Detail, "fingerprint ") {
			t.Errorf("detail must name the rule and the hash: %q", found.Detail)
		}
		if !strings.Contains(found.Snippet, "[REDACTED:") && w.rule != "private-key-block" {
			t.Errorf("snippet is not the redacted line: %q", found.Snippet)
		}
		if found.ID != "" || found.Source != "" {
			t.Errorf("seeders must leave ID and Source to RunAll")
		}
	}
	assertNoSecret(t, leads)

	for _, l := range leads {
		switch {
		case l.RuleID == "private-key-block":
			if l.EndLine != 5 || l.Snippet != "[REDACTED:private-key-block:"+l.Detail[strings.Index(l.Detail, "fingerprint ")+12:][:8]+"]" {
				t.Errorf("private key lead: end line %d snippet %q", l.EndLine, l.Snippet)
			}
		case l.File == "ci.sh" && l.RuleID == "github-token":
			// Both secrets on the line are redacted in each lead's snippet.
			if strings.Count(l.Snippet, "[REDACTED:") != 2 || !strings.HasPrefix(l.Snippet, "export GH=[REDACTED:github-token:") {
				t.Errorf("snippet = %q", l.Snippet)
			}
		}
	}
}

func TestRunAllBuiltinsNeverLeakSecrets(t *testing.T) {
	root, files := writeTree(t, map[string]string{
		"app.py":     "import os\nos.system(\"deploy --key " + testStripe + " \" + host)\npassword = \"" + testPassword + "\"\n",
		"Dockerfile": "FROM alpine:3.20\nENV API_TOKEN=" + testGitHub + "\nUSER app\n",
		"k8s.yaml":   "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n      image: a:1\n      env:\n        - name: DB_PASSWORD\n          value: \"" + testPassword + "\"\n",
		"main.tf":    "resource \"aws_db_instance\" \"d\" {\n  password = \"" + testPassword + "\"\n}\n",
	})
	leads, statuses := RunAll(context.Background(), Builtin(), root, files, nil)
	for _, st := range statuses {
		if st.Error != "" || !st.Available {
			t.Errorf("seeder %s: available=%v error=%q", st.Name, st.Available, st.Error)
		}
	}
	for _, rule := range []string{"py-os-system", "stripe-key", "generic-secret", "docker-env-secret", "k8s-env-secret", "tf-hardcoded-secret"} {
		if !hasRule(leads, rule) {
			t.Errorf("missing %s lead; got %v", rule, ruleIDs(leads))
		}
	}
	for _, l := range leads {
		if l.ID == "" || l.Source == "" {
			t.Errorf("RunAll left a lead without ID or Source: %+v", l)
		}
		if _, ok := finding.DefaultVector(l.Class); !ok {
			t.Errorf("lead %s has unknown class %q", l.RuleID, l.Class)
		}
		if strings.Contains(l.File, `\`) || l.Line < 1 {
			t.Errorf("lead %s has file %q line %d", l.RuleID, l.File, l.Line)
		}
	}
	assertNoSecret(t, leads)
}
