package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

// Test secrets are assembled at run time so that no contiguous realistic
// token ever appears in the repository, which would trip push protection.
var (
	awsKeyID     = "AKIA" + "IOSFODNN7EXAMPLE"
	awsSecret    = "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYEXAMPLEKEY"
	githubToken  = "gh" + "p_" + strings.Repeat("a1B2", 9)
	githubPAT    = "github" + "_pat_" + strings.Repeat("A1b2C3", 5)
	gitlabToken  = "gl" + "pat-" + strings.Repeat("xY9z", 5)
	slackToken   = "xo" + "xb-" + "123456789012-" + strings.Repeat("AbCd", 6)
	slackWebhook = "https://hooks.slack" + ".com/services/" + "T00000000/B00000000/" + strings.Repeat("Xy1Z", 6)
	stripeKey    = "sk" + "_live_" + strings.Repeat("4eC3", 6)
	googleKey    = "AI" + "za" + strings.Repeat("Sy1B-_x", 5)
	openaiKey    = "sk" + "-proj-" + strings.Repeat("Qw3rTy", 5)
	anthropicKey = "sk" + "-ant-" + "api03-" + strings.Repeat("Zx8Cv", 6)
	privateKey   = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + strings.Repeat("MIIEpAIBAAKCAQEA7x\n", 3) + "-----END RSA " + "PRIVATE KEY-----"
	jwtToken     = "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + strings.Repeat("s1Gn", 8)
	urlPassword  = "s3cr" + "3tPassw0rd"
	genericValue = "Tr0ub4dor" + "&3xQz9!"
)

func hashOf(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:8]
}

func TestRulesSortedAndComplete(t *testing.T) {
	got := Rules()
	if !sort.StringsAreSorted(got) {
		t.Fatalf("Rules() is not sorted: %v", got)
	}
	want := []string{
		"anthropic-key", "aws-access-key-id", "aws-secret-access-key", "basic-auth-url",
		"generic-secret", "github-token", "gitlab-token", "google-api-key", "jwt",
		"openai-key", "private-key-block", "slack-token", "slack-webhook", "stripe-key",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Rules() = %v, want %v", got, want)
	}
}

func TestRulePositiveAndNegative(t *testing.T) {
	cases := []struct {
		rule     string
		positive string // text that must produce a match of rule
		value    string // the exact secret inside positive
		negative string // similar text that must not match rule
	}{
		{"aws-access-key-id", "key = " + awsKeyID, awsKeyID, "key = AKIA" + "SHORT"},
		{"aws-secret-access-key", "aws_secret_access_key = " + awsSecret, awsSecret, "aws_region_name = " + awsSecret},
		{"github-token", "export GH=" + githubToken, githubToken, "export GH=gh" + "p_tooshort"},
		{"github-token", "pat: " + githubPAT, githubPAT, "pat: github" + "_pat_x"},
		{"gitlab-token", "t=" + gitlabToken, gitlabToken, "t=gl" + "pat-abc"},
		{"slack-token", "s=" + slackToken, slackToken, "s=xo" + "xz-123456789012-abcdefgh"},
		{"slack-webhook", "hook: " + slackWebhook, slackWebhook, "hook: https://hooks.slack" + ".com/docs"},
		{"stripe-key", "stripe " + stripeKey, stripeKey, "stripe sk" + "_test_" + strings.Repeat("4eC3", 6)},
		{"google-api-key", "g=" + googleKey, googleKey, "g=AI" + "za" + "short"},
		{"openai-key", "o=" + openaiKey, openaiKey, "o=sk" + "-short"},
		{"anthropic-key", "a=" + anthropicKey, anthropicKey, "a=sk" + "-ant-x"},
		{"private-key-block", "pem:\n" + privateKey + "\n", privateKey, "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"},
		{"jwt", "Authorization: Bearer " + jwtToken, jwtToken, "Authorization: Bearer ey" + "Jabc.def"},
		{"basic-auth-url", "db = postgres://admin:" + urlPassword + "@db.internal:5432/app", urlPassword, "db = postgres://db.internal:5432/app"},
		{"generic-secret", `password = "` + genericValue + `"`, genericValue, `password = "changeme"`},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			var found *Match
			ms := Scan(c.positive)
			for i := range ms {
				if ms[i].Rule == c.rule {
					found = &ms[i]
				}
			}
			if found == nil {
				t.Fatalf("no %s match in positive sample; got %+v", c.rule, ms)
			}
			if got := c.positive[found.Start:found.End]; got != c.value {
				t.Errorf("match covers %d bytes, want exactly the %d byte secret", len(got), len(c.value))
			}
			if found.Hash != hashOf(c.value) {
				t.Errorf("hash = %s, want %s", found.Hash, hashOf(c.value))
			}
			for _, m := range Scan(c.negative) {
				if m.Rule == c.rule {
					t.Errorf("negative sample matched %s at %d-%d", c.rule, m.Start, m.End)
				}
			}
		})
	}
}

func TestGenericSecretFilters(t *testing.T) {
	negatives := []string{
		`password = "changeme"`,
		`password = "example-password"`,
		`api_key = "your-api-key-here"`,
		`token = "xxxxxxxxxxxxxxxx"`,
		`secret = "<your secret here>"`,
		`secret = "${SECRET_VALUE}"`,
		`secret = "{{ vault_secret }}"`,
		`password = "os.environ['DB_PASSWORD']"`,
		`token = "process.env.API_TOKEN"`,
		`password = "aaaaaaaaaaaa"`,
		`password = "short"`,
		`password = "abababababab"`, // low entropy
		`password = os.getenv("DB_PASSWORD")`,
		`description = "` + genericValue + `"`,
	}
	for _, n := range negatives {
		if ms := Scan(n); len(ms) != 0 {
			t.Errorf("Scan(%q) = %+v, want no match", n, ms)
		}
	}
	positives := []string{
		`API_KEY: "` + genericValue + `"`,
		`client_secret := '` + genericValue + `'`,
		`"auth_token": "` + genericValue + `"`,
		`db.Passwd = "` + genericValue + `"`,
	}
	for _, p := range positives {
		ms := Scan(p)
		if len(ms) != 1 || ms[0].Rule != "generic-secret" || p[ms[0].Start:ms[0].End] != genericValue {
			t.Errorf("Scan(%q) = %+v, want one generic-secret match on the literal contents", p, ms)
		}
	}
}

func TestBasicAuthRedactsOnlyPassword(t *testing.T) {
	in := "url = https://deploy:" + urlPassword + "@git.internal/repo.git"
	out, ms := Apply(in)
	if len(ms) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(ms), ms)
	}
	want := "url = https://deploy:[REDACTED:basic-auth-url:" + hashOf(urlPassword) + "]@git.internal/repo.git"
	if out != want {
		t.Errorf("Apply = %q, want %q", out, want)
	}
}

func TestApplyIdempotent(t *testing.T) {
	doc := multiDoc()
	once, _ := Apply(doc)
	twice, ms := Apply(once)
	if once != twice {
		t.Errorf("Apply is not idempotent.\nfirst:  %q\nsecond: %q", once, twice)
	}
	if len(ms) != 0 {
		t.Errorf("second Apply matched markers: %+v", ms)
	}
}

func TestOverlapHandling(t *testing.T) {
	// A specific token inside a generic assignment: both rules cover the
	// same bytes and the specific rule must win.
	in := `token = "` + githubToken + `"`
	ms := Scan(in)
	if len(ms) != 1 || ms[0].Rule != "github-token" {
		t.Fatalf("Scan = %+v, want exactly one github-token match", ms)
	}
	// An anthropic key also satisfies the openai pattern.
	ms = Scan("k=" + anthropicKey)
	if len(ms) != 1 || ms[0].Rule != "anthropic-key" {
		t.Fatalf("Scan = %+v, want exactly one anthropic-key match", ms)
	}
	// A token inside a private key block is swallowed by the block.
	block := "-----BEGIN " + "PRIVATE KEY-----\n" + awsKeyID + "\n-----END " + "PRIVATE KEY-----"
	ms = Scan(block)
	if len(ms) != 1 || ms[0].Rule != "private-key-block" || ms[0].Start != 0 || ms[0].End != len(block) {
		t.Fatalf("Scan = %+v, want one private-key-block covering everything", ms)
	}
	// The aws secret rule beats the generic rule on a quoted assignment.
	ms = Scan(`AWS_SECRET_ACCESS_KEY = "` + awsSecret + `"`)
	if len(ms) != 1 || ms[0].Rule != "aws-secret-access-key" {
		t.Fatalf("Scan = %+v, want exactly one aws-secret-access-key match", ms)
	}
}

func multiDoc() string {
	return strings.Join([]string{
		"# config",
		"aws_access_key_id = " + awsKeyID,
		"aws_secret_access_key = " + awsSecret,
		"",
		"GITHUB_TOKEN=" + githubToken,
		`password: "` + genericValue + `"`,
		"DATABASE_URL=postgres://app:" + urlPassword + "@db:5432/app",
		privateKey,
		"jwt " + jwtToken + " and stripe " + stripeKey,
		"",
	}, "\n")
}

func TestMultiSecretDocument(t *testing.T) {
	doc := multiDoc()
	out, ms := Apply(doc)
	wantRules := []string{
		"aws-access-key-id", "aws-secret-access-key", "github-token", "generic-secret",
		"basic-auth-url", "private-key-block", "jwt", "stripe-key",
	}
	wantLines := []int{2, 3, 5, 6, 7, 8, 13, 13}
	if len(ms) != len(wantRules) {
		t.Fatalf("got %d matches, want %d: %+v", len(ms), len(wantRules), ms)
	}
	for i, m := range ms {
		if m.Rule != wantRules[i] {
			t.Errorf("match %d rule = %s, want %s", i, m.Rule, wantRules[i])
		}
		if m.Line != wantLines[i] {
			t.Errorf("match %d (%s) line = %d, want %d", i, m.Rule, m.Line, wantLines[i])
		}
		if i > 0 && m.Start < ms[i-1].End {
			t.Errorf("match %d overlaps the previous match", i)
		}
	}
	for _, secret := range []string{awsKeyID, awsSecret, githubToken, genericValue, urlPassword, privateKey, jwtToken, stripeKey, "MIIEpAIBAAKCAQEA7x"} {
		if strings.Contains(out, secret) {
			t.Errorf("Apply output still contains a planted secret (%d bytes, hash %s)", len(secret), hashOf(secret))
		}
	}
	if !strings.Contains(out, "# config") || !strings.Contains(out, "DATABASE_URL=postgres://app:[REDACTED:basic-auth-url:") {
		t.Errorf("Apply damaged non-secret text: %q", out)
	}
}

func TestApplyNeverLeaksAnyPlantedSecret(t *testing.T) {
	secrets := []string{
		awsKeyID, githubToken, githubPAT, gitlabToken, slackToken, slackWebhook, stripeKey,
		googleKey, openaiKey, anthropicKey, privateKey, jwtToken,
	}
	for _, s := range secrets {
		for _, wrap := range []string{"%s", "x = \"%s\"", "curl -H 'X: %s' host", "line1\n  %s\nline3"} {
			in := strings.Replace(wrap, "%s", s, 1)
			out, ms := Apply(in)
			if len(ms) == 0 || strings.Contains(out, s) {
				t.Errorf("secret with hash %s survived Apply in wrapper %q", hashOf(s), wrap)
			}
		}
	}
}

func TestMatchCarriesNoValue(t *testing.T) {
	ms := Scan("k=" + awsKeyID)
	if len(ms) != 1 {
		t.Fatalf("got %d matches", len(ms))
	}
	m := ms[0]
	if m.Start != 2 || m.End != 2+len(awsKeyID) || m.Line != 1 || len(m.Hash) != 8 {
		t.Errorf("unexpected match %+v", m)
	}
}

func TestEmptyAndPlainText(t *testing.T) {
	if ms := Scan(""); len(ms) != 0 {
		t.Errorf("Scan(\"\") = %+v", ms)
	}
	plain := "func main() {\n\tfmt.Println(\"hello, world\")\n}\n"
	out, ms := Apply(plain)
	if out != plain || len(ms) != 0 {
		t.Errorf("plain text changed: %q %+v", out, ms)
	}
}

// Every rule is gated by a literal check, and the gate never hides a match:
// for each rule, a text the regular expression matches must pass its gate.
func TestRuleGatesNeverHideAMatch(t *testing.T) {
	samples := map[string]string{
		"private-key-block":     "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----",
		"aws-access-key-id":     "id = ASIA" + "IOSFODNN7EXAMPLE",
		"aws-secret-access-key": "AWS_Secret_Access_Key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
		"github-token":          "github_pat_" + "11ABCDEFG0123456789_abcdefghij",
		"gitlab-token":          "glpat-" + "abcdefghij0123456789",
		"slack-token":           "xoxb-" + "1234567890-abcdefghij",
		"slack-webhook":         "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
		"stripe-key":            "rk_live_" + "abcdefghijklmnopqrstuvwx",
		"google-api-key":        "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
		"anthropic-key":         "sk-ant-" + "abcdefghijklmnopqrstuv",
		"openai-key":            "sk-" + "abcdefghijklmnopqrstuvwx",
		"jwt":                   "eyJhbGciOiJ" + ".eyJzdWIiOiIx" + ".c2lnbmF0dXJl",
		"basic-auth-url":        "postgres://app:" + "s3cr3t-Pa55w0rd" + "@db.internal/app",
		"generic-secret":        "Client-Secret: \"" + "q9Zr7Lm2Xv8Tn4Kd" + "\"",
	}
	for _, r := range rules {
		if len(r.any) == 0 {
			t.Errorf("rule %s has no literal gate", r.name)
		}
		sample, ok := samples[r.name]
		if !ok {
			t.Errorf("rule %s has no sample in this test", r.name)
			continue
		}
		if !r.re.MatchString(sample) {
			t.Errorf("the sample for %s does not match its rule; fix the sample", r.name)
			continue
		}
		found := false
		for _, m := range Scan(sample) {
			found = found || m.Rule == r.name || m.Start >= 0
		}
		if !found {
			t.Errorf("rule %s: the gate hid a match in %q", r.name, sample)
		}
	}
}
