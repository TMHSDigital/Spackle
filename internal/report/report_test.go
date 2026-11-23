package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

var fixtureStart = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const (
	vecCritical = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	vecHigh     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
	vecMedium   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
	vecLow      = "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
)

func mustSeverity(vector, reasoning string) finding.Severity {
	s, err := finding.SeverityFromVector(vector, reasoning)
	if err != nil {
		panic(err)
	}
	return s
}

// Fixture findings, in the order fixtureFindings returns them before ranking.
const (
	fxCritical = iota
	fxHigh
	fxMedium
	fxFixed
	fxDismissed
)

func fixtureFindings() []finding.Finding {
	sqlLoc := finding.Location{File: "app/routes/orders.py", StartLine: 42, EndLine: 44, Symbol: "get_order"}
	xssLoc := finding.Location{Method: "GET", Endpoint: "/search", Parameter: "q"}
	rootLoc := finding.Location{File: "deploy/Dockerfile", StartLine: 1}
	hashLoc := finding.Location{File: "app/auth/tokens.py", StartLine: 17, EndLine: 19}
	pathLoc := finding.Location{File: "app/files.py", StartLine: 88}

	sqlID := finding.MakeID("sql-injection", sqlLoc)
	xssID := finding.MakeID("reflected-xss", xssLoc)

	critical := finding.Finding{
		ID:       sqlID,
		Title:    "SQL injection in the order lookup lets any visitor read the whole database",
		Surface:  finding.SurfaceCode,
		Class:    "sql-injection",
		CWE:      []string{"CWE-89"},
		OWASP:    []string{"A03:2021 Injection"},
		Location: sqlLoc,
		Severity: mustSeverity(vecCritical, "Reachable over the network with no login, and it exposes and can alter every table the application account can reach."),
		Flaw: finding.Flaw{
			Description: "The order id from the URL is formatted straight into a SQL string. Nothing between the route and the query parses or binds it, so the caller controls the statement.",
			Flow: []finding.FlowStep{
				{Role: "source", File: "app/routes/orders.py", Line: 40, Quote: "order_id = request.args.get(\"id\")", Note: "Attacker-controlled query parameter."},
				{Role: "propagation", File: "app/routes/orders.py", Line: 42, Quote: "sql = f\"SELECT * FROM orders WHERE id = {order_id}\"", Note: "Interpolated without binding."},
				{Role: "sink", File: "app/db.py", Line: 17, Quote: "def run(sql):\n\treturn conn.execute(sql).fetchall()", Note: "Executed as written."},
			},
		},
		Exploitation: finding.Exploitation{
			Preconditions: []string{"Network access to the application.", "No account is needed."},
			Steps: []string{
				"Request /orders?id=1 to confirm the endpoint answers.",
				"Request /orders?id=1 UNION SELECT email, password_hash, 3, 4 FROM users.",
				"Read every user's email and password hash from the response body.",
			},
			ChainsInto: []string{"Offline cracking of the unsalted hashes, then account takeover."},
		},
		Proof: finding.Proof{
			Status:    finding.ProofDemonstrated,
			Kind:      "script",
			Summary:   "The script sends the UNION payload and checks that a seeded user's email comes back.",
			Artifacts: []string{"poc/" + sqlID + "/poc.py", "poc/" + sqlID + "/output.txt"},
			Command:   "python poc.py --base http://app:8080",
			Result:    "HTTP/1.1 200 OK\n[{\"id\": \"alice@example.test\", \"total\": \"5f4dcc3b5aa765d61d8327deb882cf99\"}]\nPOC OK: leaked 1 seeded credential row",
			Isolation: "container, no network egress, read-only root, 512 MiB, 60 s",
		},
		BlastRadius: finding.BlastRadius{
			Gains:     []string{"Read access to every table the application account can read.", "Write access through stacked statements."},
			Exposed:   []string{"users.email", "users.password_hash", "orders"},
			KillChain: "Unauthenticated request, then database read, then credential cracking, then login as any user.",
			Related:   []string{xssID},
		},
		Remediation: finding.Remediation{
			Summary:        "Bind the order id as a query parameter and reject non-numeric ids at the route.",
			Patch:          "--- a/app/routes/orders.py\n+++ b/app/routes/orders.py\n@@ -40,5 +40,5 @@\n     order_id = request.args.get(\"id\")\n-    sql = f\"SELECT * FROM orders WHERE id = {order_id}\"\n-    rows = db.run(sql)\n+    rows = db.run(\"SELECT * FROM orders WHERE id = ?\", (int(order_id),))\n     return jsonify(rows)\n",
			Why:            "A bound parameter is sent as data, so the database never parses it as SQL.",
			DefenseInDepth: []string{"Give the application a database account that cannot read the users table.", "Hash passwords with a slow, salted algorithm."},
			Verification:   "verified",
			Branch:         "spackle/fix-" + sqlID,
		},
		Confidence: finding.Confidence{Level: finding.ConfidenceDemonstrated, Reason: "The proof of concept ran in the sandbox and returned a seeded credential row."},
		Origin:     []string{"hunter", "semgrep"},
		Status:     finding.StatusOpen,
	}

	high := finding.Finding{
		ID:       xssID,
		Title:    "Reflected cross-site scripting in the search page",
		Surface:  finding.SurfaceDAST,
		Class:    "reflected-xss",
		CWE:      []string{"CWE-79"},
		OWASP:    []string{"A03:2021 Injection"},
		Location: xssLoc,
		Severity: mustSeverity(vecHigh, "Needs a logged-in victim's session to be worth anything, and then reads what that session can read."),
		Flaw: finding.Flaw{
			Description: "The q parameter is echoed into the results heading without encoding.",
			Flow: []finding.FlowStep{
				{Role: "source", Quote: "GET /search?q=spackle7391<i>", Note: "Marker sent in the query string."},
				{Role: "sink", Quote: "<h2>Results for spackle7391<i></h2>", Note: "Marker reflected with the tag intact."},
			},
		},
		Exploitation: finding.Exploitation{
			Preconditions: []string{"The victim is logged in and follows a link the attacker supplies."},
			Steps:         []string{"Send the victim a link to /search with a script payload in q.", "The payload runs in the victim's session."},
		},
		Proof: finding.Proof{
			Status:  finding.ProofReasoned,
			Kind:    "http-sequence",
			Summary: "A harmless marker with angle brackets was reflected unencoded.",
			Reason:  "The scope file allows passive checks only, so no script payload was sent.",
		},
		BlastRadius: finding.BlastRadius{
			Gains:   []string{"Actions and reads as the victim."},
			Related: []string{sqlID},
		},
		Remediation: finding.Remediation{
			Summary: "HTML-encode q where the template writes it, and send a Content-Security-Policy that forbids inline script.",
		},
		Confidence: finding.Confidence{Level: finding.ConfidenceHigh, Reason: "The reflection was observed in a live response; script execution was not tested."},
		Origin:     []string{"dast"},
		Status:     finding.StatusOpen,
	}

	medium := finding.Finding{
		ID:       finding.MakeID("container-runs-as-root", rootLoc),
		Title:    "The application container runs as root",
		Surface:  finding.SurfaceInfra,
		Class:    "container-runs-as-root",
		CWE:      []string{"CWE-250"},
		Location: rootLoc,
		Severity: finding.Severity{Label: "medium", Unscored: true, Reasoning: "Label carried over from the scanner rule; it matters only after another flaw gives code execution."},
		Flaw: finding.Flaw{
			Description: "The Dockerfile never sets USER, so the process runs as uid 0 inside the container.",
			Flow:        []finding.FlowStep{{Role: "sink", File: "deploy/Dockerfile", Line: 1, Quote: "FROM python:3.12-slim"}},
		},
		Proof: finding.Proof{
			Status: finding.ProofNotRun,
			Reason: "A configuration weakness with no direct trigger; there is nothing to run.",
		},
		Remediation: finding.Remediation{
			Summary: "Create an unprivileged user in the image and switch to it with USER.",
		},
		Confidence: finding.Confidence{Level: finding.ConfidencePlausible, Reason: "Reported by one scanner rule and not checked against the deployed runtime settings."},
		Origin:     []string{"trivy"},
		Status:     finding.StatusOpen,
	}

	fixed := finding.Finding{
		ID:       finding.MakeID("weak-hash", hashLoc),
		Title:    "Password reset tokens are derived with MD5",
		Surface:  finding.SurfaceCode,
		Class:    "weak-hash",
		CWE:      []string{"CWE-328", "CWE-327"},
		Location: hashLoc,
		Severity: mustSeverity(vecLow, "Needs local access and a privileged position to observe tokens."),
		Flaw: finding.Flaw{
			Description: "Reset tokens are the MD5 of the user id and a timestamp, which is guessable.",
		},
		Proof: finding.Proof{
			Status: finding.ProofReasoned,
			Reason: "The token recipe is visible in the code; no token was forged.",
		},
		Remediation: finding.Remediation{
			Summary:      "Generate reset tokens from the operating system's random source.",
			Patch:        "--- a/app/auth/tokens.py\n+++ b/app/auth/tokens.py\n@@ -17,3 +17,1 @@\n-    raw = f\"{user.id}{time.time()}\"\n-    return hashlib.md5(raw.encode()).hexdigest()\n+    return secrets.token_urlsafe(32)\n",
			Verification: "verified",
			Branch:       "spackle/fix-" + finding.MakeID("weak-hash", hashLoc),
		},
		Confidence: finding.Confidence{Level: finding.ConfidenceHigh, Reason: "Traced from the reset handler to the token function."},
		Origin:     []string{"hunter"},
		Status:     finding.StatusFixed,
	}

	dismissed := finding.Finding{
		ID:       finding.MakeID("path-traversal", pathLoc),
		Title:    "Path traversal in the file download handler",
		Surface:  finding.SurfaceCode,
		Class:    "path-traversal",
		CWE:      []string{"CWE-22"},
		Location: pathLoc,
		Severity: mustSeverity(vecMedium, "Would expose files readable by the application."),
		Flaw: finding.Flaw{
			Description: "The name parameter is joined onto the upload directory.",
		},
		Proof: finding.Proof{
			Status: finding.ProofFailed,
			Reason: "The request with ../ segments returned 404.",
		},
		Remediation:   finding.Remediation{Summary: "No change is needed."},
		Confidence:    finding.Confidence{Level: finding.ConfidencePlausible, Reason: "The join looked unsafe before the caller was read."},
		Origin:        []string{"hunter"},
		Status:        finding.StatusDismissed,
		DismissReason: "The caller passes the name through secure_filename two lines earlier, so no separator reaches the join.",
	}

	return []finding.Finding{critical, high, medium, fixed, dismissed}
}

func fixtureRun() Run {
	return Run{
		ID:          "20261122T120000Z-demo",
		Version:     "0.1.0",
		Command:     "scan",
		Target:      "examples/demo-app",
		TargetKind:  "path",
		Commit:      "3850163c0ffee",
		Mode:        "agentic",
		Provider:    "openai-compatible",
		Model:       "local-coder-14b",
		Offline:     true,
		Scope:       "http://127.0.0.1:8080",
		ScopeSource: "scope-file",
		Isolation:   "container, no network egress, read-only root",
		StartedAt:   fixtureStart,
		EndedAt:     fixtureStart.Add(7*time.Minute + 31*time.Second),
		Outcome:     "budget-exhausted",
		Map: ledger.MapSummary{
			Files: 48, Skipped: 3, Languages: []string{"python", "dockerfile"}, Frameworks: []string{"flask"},
			EntryPoints: 9, InfraFiles: 2, TestCommand: "pytest -q", Endpoints: 6,
		},
		Seeders: []ledger.SeederStatus{
			{Name: "gitleaks", Available: false, Note: "not installed; secrets were searched with built-in patterns only", Leads: 0},
			{Name: "semgrep", Available: true, Leads: 7},
			{Name: "trivy", Available: true, Note: "configuration checks only", Leads: 2},
		},
		Findings: finding.Rank(fixtureFindings()),
		Skipped: []ledger.BudgetSkip{
			{Cap: "max model calls (40)", Skipped: []string{"app/admin/reports.py", "app/payments/webhook.py"}},
		},
		Rejected: []ledger.Reject{
			{Stage: "investigator", Intent: "I3 Check the export job for path traversal", Reason: "the investigation failed: the provider returned HTTP 500."},
			{Stage: "seed", Intent: "L-9f2c", Reason: "location has neither a file nor an endpoint"},
		},
		Notes: []string{"Live testing was limited to passive checks by the scope file."},
		Usage: Usage{
			ModelCalls: 40, InputTokens: 182400, OutputTokens: 21950,
			Estimated: true, CostKnown: false, SandboxRuns: 3, Leads: 9,
		},
	}
}

func render(t *testing.T, format string, run Run) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(format, run, &buf); err != nil {
		t.Fatalf("render %s: %v", format, err)
	}
	return buf.Bytes()
}

func TestFixtureIsValid(t *testing.T) {
	fs := fixtureFindings()
	for i := range fs {
		if err := fs[i].Validate(); err != nil {
			t.Errorf("fixture finding %s does not validate: %v", fs[i].ID, err)
		}
	}
	want := map[int]string{fxCritical: "critical", fxHigh: "high", fxMedium: "medium", fxFixed: "low", fxDismissed: "medium"}
	for i, label := range want {
		if got := fs[i].Severity.Label; got != label {
			t.Errorf("fixture finding %d has label %q, want %q", i, got, label)
		}
	}
	if !fs[fxMedium].Severity.Unscored {
		t.Error("the medium fixture finding must be unscored")
	}
}

func TestGolden(t *testing.T) {
	run := fixtureRun()
	for _, format := range Formats() {
		t.Run(format, func(t *testing.T) {
			ext, ok := Ext(format)
			if !ok {
				t.Fatalf("no extension for %s", format)
			}
			got := render(t, format, run)
			if bytes.ContainsRune(got, '\r') {
				t.Errorf("%s output contains a carriage return", format)
			}
			path := filepath.Join("testdata", "golden", "report."+ext)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden file (run go test ./internal/report -update to create it): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s output differs from %s (%d bytes, want %d); run go test ./internal/report -update and review the diff",
					format, path, len(got), len(want))
			}
		})
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	for _, format := range Formats() {
		first := render(t, format, fixtureRun())
		second := render(t, format, fixtureRun())
		if !bytes.Equal(first, second) {
			t.Errorf("%s rendered differently the second time", format)
		}
	}
	var a, b bytes.Buffer
	if err := Terminal(fixtureRun(), &a, true); err != nil {
		t.Fatal(err)
	}
	if err := Terminal(fixtureRun(), &b, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("colored terminal output rendered differently the second time")
	}
}

func TestProseIsPlainASCII(t *testing.T) {
	run := fixtureRun()
	for _, format := range []string{"terminal", "markdown"} {
		for i, c := range render(t, format, run) {
			if c > 0x7e || (c < 0x20 && c != '\n' && c != '\t') {
				t.Fatalf("%s output has byte 0x%02x at offset %d", format, c, i)
			}
		}
	}
	for _, format := range Formats() {
		out := string(render(t, format, run))
		if strings.ContainsRune(out, 0x2014) || strings.ContainsRune(out, 0x2013) {
			t.Errorf("%s output contains a dash that is not ASCII", format)
		}
		if !utf8.ValidString(out) {
			t.Errorf("%s output is not valid UTF-8", format)
		}
	}
}

func TestHonestLabels(t *testing.T) {
	run := fixtureRun()
	for _, format := range []string{"terminal", "markdown", "html"} {
		// The terminal report wraps prose, so compare with whitespace collapsed.
		out := strings.Join(strings.Fields(string(render(t, format, run))), " ")
		for _, want := range []string{
			"unscored (estimate)",
			"(estimated)",
			"unknown for this model",
			"Dismissed by review",
			"two lines earlier",
			"What was skipped",
			"app/payments/webhook.py",
			"not installed; secrets were searched with built-in patterns only",
			"the exploit path was argued from code or traffic and was not run",
			"The scope file allows passive checks only, so no script payload was sent.",
			"a lead that was not confirmed",
			"2026-11-22T12:00:00Z",
			"2026-11-22T12:07:31Z",
			"scope-file",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s output is missing %q", format, want)
			}
		}
		if strings.Contains(out, "$0") {
			t.Errorf("%s output shows a zero cost for a model with no known price", format)
		}
	}
}

func TestTerminalSummaryLine(t *testing.T) {
	lastLine := func(run Run) string {
		lines := strings.Split(strings.TrimRight(string(render(t, "terminal", run)), "\n"), "\n")
		return lines[len(lines)-1]
	}
	if got, want := lastLine(fixtureRun()), "Summary: 4 findings (1 critical, 1 high, 1 medium, 1 low), 1 demonstrated, 1 fixed, 1 dismissed"; got != want {
		t.Errorf("summary line\n got %q\nwant %q", got, want)
	}
	one := fixtureRun()
	one.Findings = one.Findings[:1]
	if got, want := lastLine(one), "Summary: 1 finding (1 critical, 0 high, 0 medium, 0 low), 1 demonstrated, 0 fixed, 0 dismissed"; got != want {
		t.Errorf("summary line\n got %q\nwant %q", got, want)
	}
	if got, want := lastLine(Run{}), "Summary: 0 findings (0 critical, 0 high, 0 medium, 0 low), 0 demonstrated, 0 fixed, 0 dismissed"; got != want {
		t.Errorf("summary line\n got %q\nwant %q", got, want)
	}
	// A patch that was written but not applied is counted apart from fixed
	// findings and called out above the summary line.
	patched := fixtureRun()
	patched.Findings[fxFixed].Status = finding.StatusPatchAvailable
	out := string(render(t, "terminal", patched))
	if !strings.Contains(out, "Patches available and not applied: 1.") || !strings.Contains(out, "1 demonstrated, 0 fixed, 1 dismissed") {
		t.Errorf("a patch-available finding is not reported apart from fixed ones:\n%s", out[max(0, len(out)-400):])
	}
	if c := patched.Count(); c.PatchAvailable != 1 || c.Fixed != 0 {
		t.Errorf("counts = %+v", c)
	}
}

var sgr = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestTerminalColor(t *testing.T) {
	plain := render(t, "terminal", fixtureRun())
	if bytes.ContainsRune(plain, 0x1b) {
		t.Error("terminal output without color contains an escape byte")
	}
	assertWidth(t, string(plain))

	var buf bytes.Buffer
	if err := Terminal(fixtureRun(), &buf, true); err != nil {
		t.Fatal(err)
	}
	colored := buf.String()
	for name, seq := range map[string]string{
		"critical": "\x1b[91m", "high": "\x1b[38;5;208m", "medium": "\x1b[33m", "low": "\x1b[34m", "dim": "\x1b[90m",
	} {
		if !strings.Contains(colored, seq) {
			t.Errorf("colored output has no %s sequence", name)
		}
	}
	if stripped := sgr.ReplaceAllString(colored, ""); stripped != string(plain) {
		t.Error("colored output with its SGR sequences removed differs from the plain output")
	}
}

func assertWidth(t *testing.T, out string) {
	t.Helper()
	for i, l := range strings.Split(out, "\n") {
		if n := utf8.RuneCountInString(l); n > termWidth {
			t.Errorf("line %d is %d columns wide, over %d: %q", i+1, n, termWidth, l)
		}
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		in    string
		width int
		want  []string
	}{
		{"", 10, []string{}},
		{"one two three", 7, []string{"one two", "three"}},
		{"one  two\nthree", 20, []string{"one two", "three"}},
		{"abcdefghij", 4, []string{"abcd", "efgh", "ij"}},
		{"a abcdefghij b", 4, []string{"a", "abcd", "efgh", "ij b"}},
		{"first\n\nsecond\n", 20, []string{"first", "", "second"}},
	}
	for _, tc := range tests {
		if got := wrapText(tc.in, tc.width); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("wrapText(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
		}
	}
}

func TestUnknownFormat(t *testing.T) {
	err := Render("pdf", fixtureRun(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("an unknown format rendered without error")
	}
	for _, f := range Formats() {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error %q does not name the format %s", err, f)
		}
	}
	for alias, want := range map[string]string{"md": "md", "TXT": "txt", "html": "html"} {
		if ext, ok := Ext(alias); !ok || ext != want {
			t.Errorf("Ext(%q) = %q, %v; want %q", alias, ext, ok, want)
		}
	}
}

func TestZeroFindings(t *testing.T) {
	run := fixtureRun()
	run.Findings, run.Skipped, run.Rejected, run.Notes = nil, nil, nil, nil
	for _, format := range []string{"terminal", "markdown", "html"} {
		out := string(render(t, format, run))
		// The terminal report wraps the sentence, so compare with whitespace collapsed.
		flat := strings.Join(strings.Fields(out), " ")
		for _, want := range []string{"no findings is not proof", "Nothing was skipped.", "No findings were dismissed."} {
			if !strings.Contains(flat, want) {
				t.Errorf("%s output for a run with no findings is missing %q", format, want)
			}
		}
	}
	for _, format := range []string{"json", "sarif"} {
		out := render(t, format, run)
		if !json.Valid(out) {
			t.Errorf("%s output for a run with no findings is not valid JSON", format)
		}
		if bytes.Contains(out, []byte("null")) && format == "sarif" {
			t.Errorf("sarif output for a run with no findings contains null")
		}
	}
}

// Non-ASCII test characters are built from code points so this file stays
// plain ASCII and hides nothing from a reader.
var (
	bidiOverride = string(rune(0x202e)) // right-to-left override
	eAcute       = string(rune(0xe9))
)

// hostile is content a malicious repository might plant in a file that ends
// up quoted in a report.
var hostile = "</script><script>alert(1)</script> | pipe ``` fence \x1b[2J\x1b[31mred\x07\x9b" + bidiOverride + "\r\x00"

func hostileRun() Run {
	run := fixtureRun()
	f := fixtureFindings()[fxCritical]
	f.Title = "Evil " + hostile
	f.Flaw.Flow[0].Quote = "x = 1\n```\n# Injected heading\n" + hostile + "\n````\n"
	f.Remediation.Patch = "--- a/x\n+++ b/x\n+" + hostile + "\n```\n"
	f.Proof.Result = hostile
	run.Findings = []finding.Finding{f}
	run.Notes = []string{hostile}
	return run
}

func TestInjectionHTML(t *testing.T) {
	out := strings.ToLower(string(render(t, "html", hostileRun())))
	if strings.Contains(out, "<script") {
		t.Error("html output contains an unescaped script tag")
	}
	if !strings.Contains(out, "&lt;/script&gt;&lt;script&gt;alert(1)") {
		t.Error("html output does not show the hostile text escaped")
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	out := string(render(t, "html", fixtureRun()))
	lower := strings.ToLower(out)
	for _, banned := range []string{"<script", "<link", "<img", "<iframe", "src=", "url(", "@import", "javascript:", "onclick", "onload"} {
		if strings.Contains(lower, banned) {
			t.Errorf("html output contains %q", banned)
		}
	}
	for _, want := range []string{
		`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`,
		"prefers-color-scheme: light",
		"--bg: #1B1714;", "--raised: #26201B;", "--border: #3A3029;", "--fg: #F3EDE4;", "--muted: #B5A999;",
		"--dim: #7F7466;", "--accent: #FF8A4C;", "--secondary: #C4A1FF;", "--critical: #FF5D5D;", "--high: #FF8A4C;",
		"--medium: #F2C14E;", "--low: #8FB8DE;", "--ok: #7BD389;", "--bg: #F6F1EA;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html output is missing %q", want)
		}
	}
	for _, f := range fixtureRun().Active() {
		if !strings.Contains(out, `<section id="`+f.ID+`"`) {
			t.Errorf("html output has no section for %s", f.ID)
		}
		if !strings.Contains(out, `<a href="#`+f.ID+`">`) {
			t.Errorf("html summary table does not link to %s", f.ID)
		}
	}
	// The only absolute URL in the page is the authorized scope from the fixture.
	if n := strings.Count(out, "http://") + strings.Count(out, "https://"); n != strings.Count(out, "http://127.0.0.1:8080")+strings.Count(out, "http://app:8080") {
		t.Errorf("html output contains an unexpected absolute URL")
	}
}

func TestInjectionMarkdown(t *testing.T) {
	out := string(render(t, "markdown", hostileRun()))
	if strings.ContainsRune(out, 0x1b) {
		t.Error("markdown output contains a raw escape byte")
	}
	if !strings.Contains(out, "\n`````text\n") || !strings.Contains(out, "\n````diff\n") {
		t.Error("markdown code fences are not longer than the backtick runs they contain")
	}

	// Walk the document the way a markdown parser tracks fences.
	open := 0 // length of the open fence, 0 when outside a code block
	sawInjected, sawUsage := false, false
	for _, line := range strings.Split(out, "\n") {
		ticks := len(line) - len(strings.TrimLeft(line, "`"))
		switch {
		case open == 0 && ticks >= 3:
			open = ticks
			continue
		case open > 0 && ticks >= open && strings.TrimLeft(line, "`") == "":
			open = 0
			continue
		}
		if line == "# Injected heading" {
			sawInjected = true
			if open == 0 {
				t.Error("target content escaped its code fence and became a heading")
			}
		}
		if open == 0 && strings.Contains(line, "<script>") && !strings.Contains(line, `\<script\>`) {
			t.Errorf("unescaped tag outside a code block: %q", line)
		}
		if line == "## Usage" {
			sawUsage = true
			if open != 0 {
				t.Error("the usage heading is inside a code block")
			}
		}
	}
	if open != 0 {
		t.Error("a code fence is still open at the end of the document")
	}
	if !sawInjected || !sawUsage {
		t.Errorf("did not walk the expected lines: injected %v, usage %v", sawInjected, sawUsage)
	}

	// The summary table row keeps its seven cells.
	found := false
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "| `SPK-") {
			continue
		}
		found = true
		bare := strings.ReplaceAll(strings.ReplaceAll(line, `\\`, ""), `\|`, "")
		if n := strings.Count(bare, "|"); n != 8 {
			t.Errorf("summary table row has %d unescaped pipes, want 8: %q", n, line)
		}
	}
	if !found {
		t.Error("no summary table row found")
	}
}

func TestMarkdownHelpers(t *testing.T) {
	if got, want := mdFence("a\n```\nb", "text"), "````text\na\n```\nb\n````\n"; got != want {
		t.Errorf("mdFence = %q, want %q", got, want)
	}
	if got, want := mdFence("plain", "diff"), "```diff\nplain\n```\n"; got != want {
		t.Errorf("mdFence = %q, want %q", got, want)
	}
	if got, want := mdInline("a|b\nc <d>"), `a\|b c \<d\>`; got != want {
		t.Errorf("mdInline = %q, want %q", got, want)
	}
	if got, want := mdCode("a`b"), "`` a`b ``"; got != want {
		t.Errorf("mdCode = %q, want %q", got, want)
	}
	if got, want := mdCodeCell("GET /a|b"), "`GET /a\\|b`"; got != want {
		t.Errorf("mdCodeCell = %q, want %q", got, want)
	}
	if got, want := mdPara("- item\n1. one\n# head\ntext"), "\\- item\n1\\. one\n\\# head\ntext"; got != want {
		t.Errorf("mdPara = %q, want %q", got, want)
	}
}

func TestInjectionTerminal(t *testing.T) {
	check := func(name, out string) {
		t.Helper()
		for i, r := range out {
			if (r < 0x20 && r != '\n') || (r >= 0x7f && r <= 0x9f) || r == 0x202e {
				t.Fatalf("%s terminal output has control character U+%04X at offset %d", name, r, i)
			}
		}
		for _, want := range []string{`\x1b[2J`, `\x1b[31mred`, `\x07`, `\x9b`, `\u` + "202e", `\x00`} {
			if !strings.Contains(out, want) {
				t.Errorf("%s terminal output does not show %s visibly", name, want)
			}
		}
		assertWidth(t, out)
	}
	check("plain", string(render(t, "terminal", hostileRun())))

	var buf bytes.Buffer
	if err := Terminal(hostileRun(), &buf, true); err != nil {
		t.Fatal(err)
	}
	// With color on, the only escape bytes are Spackle's own SGR sequences.
	check("colored", sgr.ReplaceAllString(buf.String(), ""))
}

func TestCleanControl(t *testing.T) {
	tests := map[string]string{
		"plain text\twith tab\n": "plain text\twith tab\n",
		"a\r\nb\rc":              "a\nb\nc",
		"\x1b]0;title\x07":       `\x1b]0;title\x07`,
		"bad \xff byte":          `bad \xff byte`,
		"caf" + eAcute + " " + bidiOverride + "evil": "caf" + eAcute + " " + `\u` + "202eevil",
		"\u009b31m": `\x9b31m`,
	}
	for in, want := range tests {
		if got := cleanControl(in); got != want {
			t.Errorf("cleanControl(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInjectionJSON(t *testing.T) {
	for _, format := range []string{"json", "sarif"} {
		out := render(t, format, hostileRun())
		if !json.Valid(out) {
			t.Errorf("%s output with hostile content is not valid JSON", format)
		}
		if bytes.ContainsRune(out, 0x1b) {
			t.Errorf("%s output contains a raw escape byte", format)
		}
	}
}

func TestJSONEnvelope(t *testing.T) {
	out := render(t, "json", fixtureRun())
	if !bytes.HasPrefix(out, []byte("{\n  \"schema\": \"spackle.report/v1\",\n  \"run\": {\n")) {
		t.Errorf("json output does not start with the documented envelope: %q", out[:60])
	}
	if !bytes.HasSuffix(out, []byte("}\n")) || bytes.HasSuffix(out, []byte("\n\n")) {
		t.Error("json output does not end with exactly one newline")
	}
	var env struct {
		Schema    string            `json:"schema"`
		Run       map[string]any    `json:"run"`
		Counts    map[string]int    `json:"counts"`
		Findings  []finding.Finding `json:"findings"`
		Dismissed []finding.Finding `json:"dismissed"`
		Skipped   []ledger.BudgetSkip
		Coverage  struct {
			Map     ledger.MapSummary     `json:"map"`
			Seeders []ledger.SeederStatus `json:"seeders"`
		} `json:"coverage"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	run := fixtureRun()
	if !reflect.DeepEqual(env.Findings, run.Active()) {
		t.Error("json findings do not round trip to the active findings")
	}
	if !reflect.DeepEqual(env.Dismissed, run.Dismissed()) {
		t.Error("json dismissed findings do not round trip")
	}
	if !reflect.DeepEqual(env.Skipped, run.Skipped) || !reflect.DeepEqual(env.Coverage.Seeders, run.Seeders) {
		t.Error("json skipped or seeders do not round trip")
	}
	wantCounts := map[string]int{
		"total": 5, "open": 3, "patch_available": 0, "fixed": 1, "dismissed": 1, "demonstrated": 1,
		"critical": 1, "high": 1, "medium": 1, "low": 1, "none": 0,
	}
	if !reflect.DeepEqual(env.Counts, wantCounts) {
		t.Errorf("json counts = %v, want %v", env.Counts, wantCounts)
	}
	if env.Run["started_at"] != "2026-11-22T12:00:00Z" || env.Run["target_kind"] != "path" {
		t.Errorf("json run block is wrong: %v", env.Run)
	}
	if cost, present := env.Usage["cost_usd"]; !present || cost != nil {
		t.Errorf("an unknown cost must be null, got %v", cost)
	}
	if env.Usage["tokens_estimated"] != true || env.Usage["cost_known"] != false {
		t.Errorf("json usage flags are wrong: %v", env.Usage)
	}
	// HTML escaping is off: the quoted markup appears as written.
	if !bytes.Contains(out, []byte("<h2>Results for spackle7391<i></h2>")) {
		t.Error("json output escaped HTML characters")
	}
}

func TestSARIF(t *testing.T) {
	run := fixtureRun()
	out := render(t, "sarif", run)
	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name           string `json:"name"`
					InformationURI string `json:"informationUri"`
					Version        string `json:"version"`
					Rules          []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						HelpURI    string `json:"helpUri"`
						Properties struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
			} `json:"invocations"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations           []map[string]json.RawMessage `json:"locations"`
				PartialFingerprints map[string]string            `json:"partialFingerprints"`
				Properties          map[string]any               `json:"properties"`
				Fixes               json.RawMessage              `json:"fixes"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatal(err)
	}
	if log.Schema != "https://json.schemastore.org/sarif-2.1.0.json" || log.Version != "2.1.0" {
		t.Errorf("schema %q version %q", log.Schema, log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(log.Runs))
	}
	r := log.Runs[0]
	d := r.Tool.Driver
	if d.Name != "Spackle" || d.InformationURI != "https://github.com/TMHSDigital/Spackle" || d.Version != "0.1.0" {
		t.Errorf("driver is %+v", d)
	}
	if len(r.Invocations) != 1 || !r.Invocations[0].ExecutionSuccessful {
		t.Error("a run that did not fail must report executionSuccessful true")
	}

	wantRules := []string{"container-runs-as-root", "reflected-xss", "sql-injection", "weak-hash"}
	var gotRules []string
	for _, rule := range d.Rules {
		gotRules = append(gotRules, rule.ID)
		if rule.ShortDescription.Text == "" {
			t.Errorf("rule %s has no short description", rule.ID)
		}
		if len(rule.Properties.Tags) == 0 || rule.Properties.Tags[0] != "security" {
			t.Errorf("rule %s tags are %v", rule.ID, rule.Properties.Tags)
		}
	}
	if !reflect.DeepEqual(gotRules, wantRules) {
		t.Errorf("rules are %v, want %v (sorted, dismissed class absent)", gotRules, wantRules)
	}
	if got := d.Rules[2].HelpURI; got != "https://cwe.mitre.org/data/definitions/89.html" {
		t.Errorf("sql-injection helpUri is %q", got)
	}
	if got, want := d.Rules[3].Properties.Tags, []string{"security", "external/cwe/cwe-327", "external/cwe/cwe-328"}; !reflect.DeepEqual(got, want) {
		t.Errorf("weak-hash tags are %v, want %v", got, want)
	}

	fs := fixtureFindings()
	if len(r.Results) != 4 {
		t.Fatalf("got %d results, want 4", len(r.Results))
	}
	if bytes.Contains(out, []byte(fs[fxDismissed].ID)) || bytes.Contains(out, []byte("path-traversal")) {
		t.Error("the dismissed finding appears in the sarif output")
	}
	byID := map[string]int{}
	for i, res := range r.Results {
		byID[res.PartialFingerprints["spackle/v1"]] = i
		if d.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %d has ruleIndex %d, which is not rule %s", i, res.RuleIndex, res.RuleID)
		}
		if res.Fixes != nil {
			t.Errorf("result %d has fixes", i)
		}
	}
	wantLevel := map[int]string{fxCritical: "error", fxHigh: "error", fxMedium: "warning", fxFixed: "note"}
	for idx, level := range wantLevel {
		i, ok := byID[fs[idx].ID]
		if !ok {
			t.Fatalf("no result for fixture finding %d", idx)
		}
		res := r.Results[i]
		if res.Level != level {
			t.Errorf("fixture finding %d has level %q, want %q", idx, res.Level, level)
		}
		if res.Properties["confidence"] != fs[idx].Confidence.Level || res.Properties["proof_status"] != fs[idx].Proof.Status {
			t.Errorf("fixture finding %d properties are %v", idx, res.Properties)
		}
		for _, part := range []string{fs[idx].Title, fs[idx].Flaw.Description, fs[idx].Remediation.Summary} {
			if !strings.Contains(res.Message.Text, part) {
				t.Errorf("fixture finding %d message is missing %q", idx, part)
			}
		}
	}

	crit := r.Results[byID[fs[fxCritical].ID]]
	if got := crit.Properties["security-severity"]; got != "9.3" {
		t.Errorf("critical security-severity is %#v, want the string 9.3", got)
	}
	var phys struct {
		ArtifactLocation struct {
			URI       string `json:"uri"`
			URIBaseID string `json:"uriBaseId"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
			EndLine   int `json:"endLine"`
		} `json:"region"`
	}
	if err := json.Unmarshal(crit.Locations[0]["physicalLocation"], &phys); err != nil {
		t.Fatal(err)
	}
	if phys.ArtifactLocation.URI != "app/routes/orders.py" || phys.ArtifactLocation.URIBaseID != "%SRCROOT%" ||
		phys.Region.StartLine != 42 || phys.Region.EndLine != 44 {
		t.Errorf("critical physical location is %+v", phys)
	}
	if _, has := crit.Locations[0]["logicalLocations"]; has {
		t.Error("a file-only finding has logical locations")
	}

	if _, has := r.Results[byID[fs[fxMedium].ID]].Properties["security-severity"]; has {
		t.Error("an unscored finding has a security-severity")
	}

	endpoint := r.Results[byID[fs[fxHigh].ID]]
	if _, has := endpoint.Locations[0]["physicalLocation"]; has {
		t.Error("an endpoint-only finding has a physical location")
	}
	var logical []struct {
		FullyQualifiedName string `json:"fullyQualifiedName"`
	}
	if err := json.Unmarshal(endpoint.Locations[0]["logicalLocations"], &logical); err != nil {
		t.Fatal(err)
	}
	if len(logical) != 1 || logical[0].FullyQualifiedName != "GET /search?q" {
		t.Errorf("endpoint logical location is %+v", logical)
	}

	failed := run
	failed.Outcome = "failed"
	if !bytes.Contains(render(t, "sarif", failed), []byte(`"executionSuccessful": false`)) {
		t.Error("a failed run must report executionSuccessful false")
	}
	if got := sarifURI(`dir with space\a#b.go`); got != "dir%20with%20space/a%23b.go" {
		t.Errorf("sarifURI = %q", got)
	}
}

func TestLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	tick := 0
	clock := func() time.Time {
		ts := fixtureStart.Add(time.Duration(tick) * time.Second)
		tick++
		return ts
	}
	w, err := ledger.Create(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	fs := fixtureFindings()
	critical := fs[fxCritical]
	stillOpen := fs[fxDismissed]
	stillOpen.Status, stillOpen.DismissReason = finding.StatusOpen, ""
	start := ledger.RunStart{
		RunID: "run-1", Version: "0.1.0", Command: "scan", Target: "examples/demo-app", TargetKind: "path",
		Commit: "abc123", Mode: "agentic", Provider: "openai-compatible", Model: "local-coder-14b", Offline: true,
		Scope: "http://127.0.0.1:8080", ScopeSource: "scope-file", Isolation: "container, no network egress",
	}
	mapSummary := ledger.MapSummary{Files: 48, Skipped: 3, Languages: []string{"python"}, EntryPoints: 9, InfraFiles: 2}
	skip := ledger.BudgetSkip{Cap: "max model calls (2)", Skipped: []string{"app/admin/reports.py"}}
	reject := ledger.Reject{Stage: "investigator", Intent: "I2 Trace the upload handler", Reason: "the draft quoted a line that is not in the file"}
	events := []struct {
		typ  string
		data any
	}{
		{ledger.TypeRunStart, start},
		{ledger.TypeMap, mapSummary},
		{ledger.TypeSeeder, ledger.SeederStatus{Name: "semgrep", Available: true, Leads: 2}},
		{ledger.TypeSeeder, ledger.SeederStatus{Name: "gitleaks", Available: false, Note: "not installed"}},
		{ledger.TypeLead, map[string]string{"rule": "python.sqli", "file": "app/routes/orders.py"}},
		{ledger.TypeLead, map[string]string{"rule": "python.path", "file": "app/files.py"}},
		{ledger.TypeFinding, stillOpen},
		{ledger.TypeFinding, critical},
		{ledger.TypeModelCall, ledger.ModelCall{Stage: "hunter", Provider: "openai-compatible", Model: "local-coder-14b", InputTokens: 1000, OutputTokens: 200, Estimated: true, CostKnown: false}},
		{ledger.TypeModelCall, ledger.ModelCall{Stage: "reviewer", Provider: "openai-compatible", Model: "local-coder-14b", InputTokens: 500, OutputTokens: 50, CostUSD: 0.25, CostKnown: true}},
		{ledger.TypeSandboxRun, ledger.SandboxRun{FindingID: critical.ID, Purpose: "poc", Image: "python:3.12-slim", Command: "python poc.py", Isolation: "container, no network egress"}},
		{ledger.TypeFinding, fs[fxDismissed]},
		{ledger.TypeBudgetSkip, skip},
		{ledger.TypeReject, reject},
		{ledger.TypeNote, "Live testing was limited to passive checks."},
		{ledger.TypeRunEnd, ledger.RunEnd{Outcome: "budget-exhausted"}},
	}
	for _, ev := range events {
		if _, err := w.Append(0, ev.typ, ev.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.StartedAt.Equal(fixtureStart) {
		t.Errorf("StartedAt = %s, want %s", got.StartedAt, fixtureStart)
	}
	if wantEnd := fixtureStart.Add(time.Duration(len(events)-1) * time.Second); !got.EndedAt.Equal(wantEnd) {
		t.Errorf("EndedAt = %s, want %s", got.EndedAt, wantEnd)
	}
	want := Run{
		ID: "run-1", Version: "0.1.0", Command: "scan", Target: "examples/demo-app", TargetKind: "path",
		Commit: "abc123", Mode: "agentic", Provider: "openai-compatible", Model: "local-coder-14b", Offline: true,
		Scope: "http://127.0.0.1:8080", ScopeSource: "scope-file", Isolation: "container, no network egress",
		StartedAt: got.StartedAt, EndedAt: got.EndedAt,
		Outcome: "budget-exhausted",
		Map:     mapSummary,
		Seeders: []ledger.SeederStatus{
			{Name: "gitleaks", Available: false, Note: "not installed"},
			{Name: "semgrep", Available: true, Leads: 2},
		},
		// The later upsert wins, so the second finding is dismissed and ranks last.
		Findings: []finding.Finding{critical, fs[fxDismissed]},
		Skipped:  []ledger.BudgetSkip{skip},
		Rejected: []ledger.Reject{reject},
		Notes:    []string{"Live testing was limited to passive checks."},
		Usage: Usage{
			ModelCalls: 2, InputTokens: 1500, OutputTokens: 250, CostUSD: 0.25,
			Estimated: true, CostKnown: false, SandboxRuns: 1, Leads: 2,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load returned\n%+v\nwant\n%+v", got, want)
	}
	if len(got.Dismissed()) != 1 || got.Dismissed()[0].DismissReason == "" {
		t.Error("the later upsert that dismissed the finding did not win")
	}

	// A loaded run renders the same bytes every time, in every format.
	for _, format := range Formats() {
		again, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(render(t, format, got), render(t, format, again)) {
			t.Errorf("%s differs between two loads of the same ledger", format)
		}
	}
}

func TestLoadIncompleteRun(t *testing.T) {
	dir := t.TempDir()
	tick := 0
	w, err := ledger.Create(dir, func() time.Time {
		ts := fixtureStart.Add(time.Duration(tick) * time.Minute)
		tick++
		return ts
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(0, ledger.TypeRunStart, ledger.RunStart{RunID: "run-2", Version: "0.1.0", Command: "scan", Target: ".", TargetKind: "path", Mode: "deterministic"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(0, ledger.TypeMap, ledger.MapSummary{Files: 3}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "incomplete" {
		t.Errorf("Outcome = %q, want incomplete", got.Outcome)
	}
	if want := fixtureStart.Add(time.Minute); !got.EndedAt.Equal(want) {
		t.Errorf("EndedAt = %s, want the last event's time %s", got.EndedAt, want)
	}
	if !got.Usage.CostKnown {
		t.Error("a run with no model call has a known cost of zero")
	}
	out := string(render(t, "terminal", got))
	if !strings.Contains(out, "Outcome: incomplete") || !strings.Contains(out, "Cost: $0.0000") {
		t.Errorf("terminal report of an incomplete run is missing its outcome or cost:\n%s", out)
	}

	if _, err := Load(t.TempDir()); err == nil {
		t.Error("loading a directory with no ledger did not fail")
	}
}

func TestSARIFPathsAreRelativeToTheRepositoryRoot(t *testing.T) {
	run := fixtureRun()
	run.RepoPrefix = "services/api"
	var buf bytes.Buffer
	if err := Render("sarif", run, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"uri": "services/api/app/routes/orders.py"`) {
		t.Fatalf("a scan of a repository subdirectory must emit URIs from the repository root:\n%s", buf.String())
	}
	if loc := sarifLocate(finding.Location{File: "a.go"}, ""); loc.PhysicalLocation.ArtifactLocation.URI != "a.go" {
		t.Fatalf("with no prefix the path must be unchanged: %+v", loc.PhysicalLocation)
	}
}

func TestRejectedWorkIsListedInEveryFormat(t *testing.T) {
	run := fixtureRun()
	for _, format := range Formats() {
		if format == "sarif" {
			continue // SARIF carries results only
		}
		var buf bytes.Buffer
		if err := Render(format, run, &buf); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		for _, want := range []string{"I3 Check the export job for path traversal", "L-9f2c"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s report does not mention rejected work %q", format, want)
			}
		}
	}
	if got := rejectLine(ledger.Reject{Stage: "investigator", Intent: "I1 x", Reason: "bad draft."}); got != "Investigation not completed: I1 x (bad draft)." {
		t.Errorf("rejectLine = %q", got)
	}
}
