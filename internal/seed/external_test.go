package seed

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/finding"
)

// jsonString quotes s as a JSON string, which matters for Windows paths.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func extRoot(t *testing.T) string {
	t.Helper()
	root, _ := writeTree(t, map[string]string{
		"src/app.py":         "print('hi')\n",
		"src/my dir/db.py":   "x = 1\n",
		"Dockerfile":         "FROM alpine\n",
		"package-lock.json":  "{}\n",
		"deploy/main.tf":     "# tf\n",
		"deploy/pod.yaml":    "a: 1\n",
		"services/go.mod":    "module x\n",
		"config/settings.py": "x = 1\n",
	})
	return root
}

func checkExternalLeads(t *testing.T, leads []Lead) {
	t.Helper()
	for _, l := range leads {
		if _, ok := finding.DefaultVector(l.Class); !ok {
			t.Errorf("lead %s has unknown class %q", l.RuleID, l.Class)
		}
		if l.File == "" || strings.Contains(l.File, `\`) || strings.HasPrefix(l.File, "/") || strings.Contains(l.File, "..") {
			t.Errorf("lead %s has file %q, want a forward-slash path relative to the root", l.RuleID, l.File)
		}
		if l.RuleID == "" || l.Title == "" || l.Detail == "" || l.Fix == "" || len(l.CWE) == 0 || strings.HasSuffix(l.Title, ".") {
			t.Errorf("incomplete lead: %+v", l)
		}
		switch l.Severity {
		case "critical", "high", "medium", "low":
		default:
			t.Errorf("lead %s severity %q", l.RuleID, l.Severity)
		}
		if l.Surface != finding.SurfaceCode && l.Surface != finding.SurfaceInfra {
			t.Errorf("lead %s surface %q", l.RuleID, l.Surface)
		}
		if l.ID != "" || l.Source != "" {
			t.Errorf("seeders must leave ID and Source to RunAll")
		}
	}
}

func TestParseSemgrep(t *testing.T) {
	root := extRoot(t)
	abs := filepath.Join(root, "src", "my dir", "db.py")
	data := `{"version":"1.90.0","errors":[],"results":[
	 {"check_id":"python.lang.security.audit.formatted-sql-query","path":"src/app.py",
	  "start":{"line":12,"col":5},"end":{"line":14,"col":2},
	  "extra":{"message":"Detected possible formatted SQL query with key ` + testGitHub + `. Use parameterized queries instead.",
	   "severity":"ERROR","lines":"` + testGitHub + `",
	   "metadata":{"cwe":["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],"owasp":["A03:2021 - Injection"]}}},
	 {"check_id":"python.flask.debug-enabled","path":` + jsonString(abs) + `,
	  "start":{"line":3},"end":{"line":3},
	  "extra":{"message":"Debug mode is on.","severity":"WARNING","metadata":{"cwe":"CWE-489: Active Debug Code","owasp":"A05:2021"}}},
	 {"check_id":"generic.style.todo","path":"src/app.py","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"todo","severity":"INFO","metadata":{}}},
	 {"check_id":"x.unknown-cwe","path":"src/app.py","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"m","severity":"INFO","metadata":{"cwe":["CWE-99999: Made up"]}}},
	 {"check_id":"x.traversal","path":"../outside.py","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"m","severity":"ERROR","metadata":{"cwe":["CWE-78"]}}},
	 {"check_id":"x.absolute","path":"/etc/passwd","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"m","severity":"ERROR","metadata":{"cwe":["CWE-78"]}}},
	 {"check_id":"x.missing","path":"src/nope.py","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"m","severity":"ERROR","metadata":{"cwe":["CWE-78"]}}}
	]}`
	var st parseStats
	leads, err := semgrepLeads([]byte(data), root, &st)
	if err != nil {
		t.Fatal(err)
	}
	if len(leads) != 2 || st.unclassified != 2 || st.outside != 3 {
		t.Fatalf("got %d leads, %d unclassified, %d outside; want 2, 2, 3: %+v", len(leads), st.unclassified, st.outside, leads)
	}
	checkExternalLeads(t, leads)
	assertNoSecret(t, leads)
	a, b := leads[0], leads[1]
	if a.RuleID != "python.lang.security.audit.formatted-sql-query" || a.Title != "formatted sql query" || a.Class != "sql-injection" ||
		a.File != "src/app.py" || a.Line != 12 || a.EndLine != 14 || a.Severity != "high" || a.CWE[0] != "CWE-89" || a.OWASP[0] != "A03:2021 - Injection" {
		t.Errorf("first lead: %+v", a)
	}
	if b.Class != "debug-enabled" || b.File != "src/my dir/db.py" || b.Line != 3 || b.EndLine != 0 || b.Severity != "medium" || b.CWE[0] != "CWE-489" {
		t.Errorf("second lead: %+v", b)
	}
	if !strings.Contains(st.note(), "2 result(s) skipped because no Spackle class") || !strings.Contains(st.note(), "3 result(s) skipped because their path") {
		t.Errorf("note = %q", st.note())
	}
	if got, err := parseSemgrep([]byte(data), root); err != nil || len(got) != 2 {
		t.Errorf("parseSemgrep = %d leads, %v", len(got), err)
	}
	if _, err := parseSemgrep([]byte("Traceback: boom"), root); err == nil || !strings.Contains(err.Error(), "semgrep") {
		t.Errorf("want a descriptive error for non-JSON output, got %v", err)
	}
}

func TestParseGitleaks(t *testing.T) {
	root := extRoot(t)
	abs := filepath.Join(root, "config", "settings.py")
	data := `[
	 {"Description":"Identified a GitHub Personal Access Token, value ` + testGitHub + `.","StartLine":7,"EndLine":7,"StartColumn":9,"EndColumn":48,
	  "Match":"token = ` + testGitHub + `","Secret":"` + testGitHub + `","File":` + jsonString(abs) + `,
	  "SymlinkFile":"","Commit":"","Entropy":4.1,"Author":"","Email":"","Date":"","Message":"","Tags":[],
	  "RuleID":"github-pat","Fingerprint":"config/settings.py:github-pat:7"},
	 {"Description":"AWS","StartLine":2,"EndLine":4,"Match":"REDACTED","Secret":"REDACTED","File":"src\\app.py","RuleID":"aws-access-token"},
	 {"Description":"x","StartLine":1,"EndLine":1,"Match":"m","Secret":"s","File":"..\\..\\Windows\\win.ini","RuleID":"generic-api-key"}
	]`
	var st parseStats
	leads, err := gitleaksLeads([]byte(data), root, &st)
	if err != nil {
		t.Fatal(err)
	}
	if len(leads) != 2 || st.outside != 1 || st.unclassified != 0 {
		t.Fatalf("got %d leads, stats %+v: %+v", len(leads), st, leads)
	}
	checkExternalLeads(t, leads)
	assertNoSecret(t, leads)
	a, b := leads[0], leads[1]
	if a.RuleID != "github-pat" || a.Class != "hardcoded-secret" || a.File != "config/settings.py" || a.Line != 7 || a.EndLine != 0 || a.Severity != "high" || a.CWE[0] != "CWE-798" {
		t.Errorf("first lead: %+v", a)
	}
	if !strings.Contains(a.Detail, "[REDACTED:github-token:") || a.Snippet != "" {
		t.Errorf("text from the scanner must be redacted and no snippet taken: %+v", a)
	}
	if b.File != "src/app.py" || b.Line != 2 || b.EndLine != 4 {
		t.Errorf("second lead: %+v", b)
	}
	if got, err := parseGitleaks([]byte("[]"), root); err != nil || len(got) != 0 {
		t.Errorf("empty report: %v %v", got, err)
	}
	if _, err := parseGitleaks([]byte(`{"oops":1}`), root); err == nil {
		t.Error("want an error for a report of the wrong shape")
	}
}

func TestParseOSV(t *testing.T) {
	root := extRoot(t)
	lock := filepath.Join(root, "package-lock.json")
	data := `{"results":[
	 {"source":{"path":` + jsonString(lock) + `,"type":"lockfile"},
	  "packages":[
	   {"package":{"name":"lodash","version":"4.17.15","ecosystem":"npm"},
	    "vulnerabilities":[
	     {"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection in lodash","aliases":["CVE-2021-23337"],
	      "affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]},
	     {"id":"GHSA-p6mc-m468-83gw","summary":"","affected":[]}],
	    "groups":[{"ids":["GHSA-35jh-r3h4-6jhm"],"max_severity":"7.2"},{"ids":["GHSA-p6mc-m468-83gw"],"max_severity":""}]},
	   {"package":{"name":"minimist","version":"0.0.8","ecosystem":"npm"},
	    "vulnerabilities":[{"id":"GHSA-xvch-5gv4-984h","summary":"Prototype Pollution in minimist."}],
	    "groups":[{"ids":["GHSA-xvch-5gv4-984h"],"max_severity":"9.8"}]}]},
	 {"source":{"path":"/somewhere/else/go.mod","type":"lockfile"},
	  "packages":[{"package":{"name":"x","version":"1"},"vulnerabilities":[{"id":"GO-1"},{"id":"GO-2"}]}]}
	],"experimental_config":{}}`
	var st parseStats
	leads, err := osvLeads([]byte(data), root, &st)
	if err != nil {
		t.Fatal(err)
	}
	if len(leads) != 3 || st.outside != 2 {
		t.Fatalf("got %d leads, stats %+v: %+v", len(leads), st, leads)
	}
	checkExternalLeads(t, leads)
	a := leads[0]
	if a.RuleID != "GHSA-35jh-r3h4-6jhm:lodash" || a.Class != "vulnerable-dependency" || a.CWE[0] != "CWE-1395" || a.File != "package-lock.json" ||
		a.Severity != "high" || a.Title != "lodash 4.17.15 is affected by GHSA-35jh-r3h4-6jhm" ||
		a.Detail != "lodash 4.17.15: Command Injection in lodash." || !strings.Contains(a.Fix, "4.17.21") {
		t.Errorf("first lead: %+v", a)
	}
	if leads[1].Severity != "medium" || !strings.Contains(leads[1].Detail, "No summary was published") {
		t.Errorf("second lead: %+v", leads[1])
	}
	if leads[2].Severity != "critical" || leads[2].Detail != "minimist 0.0.8: Prototype Pollution in minimist." {
		t.Errorf("third lead: %+v", leads[2])
	}
	if got, err := parseOSV([]byte(`{"results":[]}`), root); err != nil || len(got) != 0 {
		t.Errorf("empty report: %v %v", got, err)
	}
	if _, err := parseOSV([]byte("no package sources found"), root); err == nil {
		t.Error("want an error for non-JSON output")
	}
}

func TestParseTrivy(t *testing.T) {
	root := extRoot(t)
	data := `{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[
	 {"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm","Vulnerabilities":[
	   {"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.15","FixedVersion":"4.17.21",
	    "Title":"nodejs-lodash: command injection via template","Severity":"HIGH","CweIDs":["CWE-94"]},
	   {"VulnerabilityID":"CVE-2020-0001","PkgName":"left-pad","InstalledVersion":"1.0.0","Severity":"UNKNOWN"}]},
	 {"Target":"Dockerfile","Class":"config","Type":"dockerfile","Misconfigurations":[
	   {"Type":"Dockerfile Security Check","ID":"DS002","AVDID":"AVD-DS-0002","Title":"Image user should not be 'root'",
	    "Description":"Running containers with 'root' user can lead to a container escape situation.",
	    "Message":"Specify at least 1 USER command in Dockerfile with non-root user as argument",
	    "Resolution":"Add 'USER <non root user name>' line to the Dockerfile","Severity":"HIGH","Status":"FAIL",
	    "CauseMetadata":{"Provider":"Dockerfile","Service":"general","StartLine":0,"EndLine":0}},
	   {"ID":"DS001","Title":"':latest' tag used","Description":"Use a specific tag.","Message":"Specify a tag in the 'FROM' statement for image 'alpine'",
	    "Resolution":"Add a tag to the image in the 'FROM' statement","Severity":"MEDIUM","CauseMetadata":{"StartLine":1,"EndLine":1}}]},
	 {"Target":"deploy/pod.yaml","Class":"config","Type":"kubernetes","Misconfigurations":[
	   {"ID":"KSV017","Title":"Privileged container","Description":"Privileged containers share namespaces with the host.","Message":"Container 'a' should set 'privileged' to false",
	    "Resolution":"Change 'privileged' to false.","Severity":"HIGH","CauseMetadata":{"StartLine":8,"EndLine":12}}]},
	 {"Target":"deploy\\main.tf","Class":"config","Type":"terraform","Misconfigurations":[
	   {"ID":"AVD-AWS-0086","Title":"S3 Access block should block public ACL","Description":"S3 buckets should block public ACLs.","Message":"No public access block so not blocking public acls",
	    "Resolution":"Enable blocking any PUT calls with a public ACL specified","Severity":"HIGH","CauseMetadata":{"StartLine":3,"EndLine":5}},
	   {"ID":"AVD-AWS-0088","Title":"Unencrypted S3 bucket","Description":"S3 Buckets should be encrypted.","Message":"Bucket does not have encryption enabled",
	    "Resolution":"Configure bucket encryption","Severity":"HIGH","CauseMetadata":{"StartLine":3,"EndLine":5}},
	   {"ID":"AVD-AWS-0107","Title":"An ingress security group rule allows traffic from /0","Description":"Opening up ports to the public internet is generally to be avoided.","Message":"Security group rule allows ingress from public internet.",
	    "Resolution":"Set a more restrictive cidr range","Severity":"CRITICAL","CauseMetadata":{"StartLine":9,"EndLine":9}},
	   {"ID":"AVD-AWS-0089","Title":"S3 Bucket Logging","Description":"Ensures S3 bucket logging is enabled.","Message":"Bucket has logging disabled",
	    "Resolution":"Add a logging block","Severity":"LOW","CauseMetadata":{"StartLine":3,"EndLine":5}}]},
	 {"Target":"../../etc/shadow","Class":"config","Type":"terraform","Misconfigurations":[
	   {"ID":"AVD-AWS-0088","Title":"Unencrypted S3 bucket","Severity":"HIGH"}]}
	]}`
	var st parseStats
	leads, err := trivyLeads([]byte(data), root, &st)
	if err != nil {
		t.Fatal(err)
	}
	if len(leads) != 8 || st.unclassified != 1 || st.outside != 1 {
		for _, l := range leads {
			t.Logf("%s %s %s", l.File, l.RuleID, l.Class)
		}
		t.Fatalf("got %d leads, stats %+v", len(leads), st)
	}
	checkExternalLeads(t, leads)
	type want struct{ rule, class, file, sev string }
	wants := []want{
		{"CVE-2021-23337:lodash", "vulnerable-dependency", "package-lock.json", "high"},
		{"CVE-2020-0001:left-pad", "vulnerable-dependency", "package-lock.json", "low"},
		{"DS002", "container-hardening", "Dockerfile", "high"},
		{"DS001", "supply-chain", "Dockerfile", "medium"},
		{"KSV017", "container-privilege", "deploy/pod.yaml", "high"},
		{"AVD-AWS-0086", "public-storage", "deploy/main.tf", "high"},
		{"AVD-AWS-0088", "unencrypted-storage", "deploy/main.tf", "high"},
		{"AVD-AWS-0107", "network-exposure", "deploy/main.tf", "critical"},
	}
	for i, w := range wants {
		l := leads[i]
		if l.RuleID != w.rule || l.Class != w.class || l.File != w.file || l.Severity != w.sev {
			t.Errorf("lead %d = %s %s %s %s, want %+v", i, l.RuleID, l.Class, l.File, l.Severity, w)
		}
	}
	if !strings.Contains(leads[0].Fix, "4.17.21") || leads[0].Surface != finding.SurfaceCode {
		t.Errorf("vulnerability lead: %+v", leads[0])
	}
	if k := leads[4]; k.Line != 8 || k.EndLine != 12 || k.Surface != finding.SurfaceInfra || k.Fix != "Change 'privileged' to false." {
		t.Errorf("misconfiguration lead: %+v", k)
	}
	if got, err := parseTrivy([]byte(`{"SchemaVersion":2}`), root); err != nil || len(got) != 0 {
		t.Errorf("empty report: %v %v", got, err)
	}
	if _, err := parseTrivy([]byte("FATAL error"), root); err == nil {
		t.Error("want an error for non-JSON output")
	}
}

func TestParseHadolint(t *testing.T) {
	root := extRoot(t)
	data := `[
	 {"code":"DL3007","column":1,"file":"Dockerfile","level":"warning","line":1,"message":"Using latest is prone to errors if the image will ever update. Pin the version explicitly to a release tag"},
	 {"code":"DL3002","column":1,"file":".\\Dockerfile","level":"error","line":9,"message":"Last USER should not be root."},
	 {"code":"DL3059","column":1,"file":"Dockerfile","level":"info","line":4,"message":"Multiple consecutive RUN instructions. Consider consolidation."},
	 {"code":"SC2086","column":1,"file":"Dockerfile","level":"info","line":5,"message":"Double quote to prevent globbing and word splitting."},
	 {"code":"DL3007","column":1,"file":"../Dockerfile","level":"warning","line":1,"message":"Using latest"}
	]`
	var st parseStats
	leads, err := hadolintLeads([]byte(data), root, &st)
	if err != nil {
		t.Fatal(err)
	}
	if len(leads) != 2 || st.unclassified != 2 || st.outside != 1 {
		t.Fatalf("got %d leads, stats %+v: %+v", len(leads), st, leads)
	}
	checkExternalLeads(t, leads)
	if a := leads[0]; a.RuleID != "DL3007" || a.Class != "supply-chain" || a.File != "Dockerfile" || a.Line != 1 || a.Severity != "low" || a.Surface != finding.SurfaceInfra {
		t.Errorf("first lead: %+v", a)
	}
	if b := leads[1]; b.RuleID != "DL3002" || b.Class != "container-hardening" || b.File != "Dockerfile" || b.Line != 9 || b.Severity != "medium" || b.Title != "Last USER should not be root" {
		t.Errorf("second lead: %+v", b)
	}
	if _, err := parseHadolint([]byte("hadolint: openBinaryFile: does not exist"), root); err == nil {
		t.Error("want an error for non-JSON output")
	}
}

func TestClassForCWE(t *testing.T) {
	cases := map[string]string{
		"CWE-89": "sql-injection",
		"cwe-78": "command-injection",
		"CWE-79: Improper Neutralization of Input During Web Page Generation": "xss",
		"CWE-74":    "code-injection", // generic injection falls back to code-injection
		"CWE-917":   "code-injection",
		"CWE-502":   "unsafe-deserialization",
		"CWE-22":    "path-traversal",
		"CWE-918":   "ssrf",
		"CWE-798":   "hardcoded-secret",
		"CWE-327":   "weak-crypto",
		"CWE-328":   "weak-hash",
		"CWE-295":   "tls-verification",
		"CWE-611":   "xxe",
		"CWE-1321":  "prototype-pollution",
		"CWE-99999": "", // unknown is unclassified, never a catch-all
		"CWE-710":   "",
		"":          "",
		"garbage":   "",
	}
	for in, want := range cases {
		if got := classForCWE(in); got != want {
			t.Errorf("classForCWE(%q) = %q, want %q", in, got, want)
		}
	}
	for cwe, class := range cweClasses {
		if _, ok := finding.DefaultVector(class); !ok {
			t.Errorf("CWE-%s maps to unknown class %q", cwe, class)
		}
	}
	for code, cc := range hadolintClasses {
		if _, ok := finding.DefaultVector(cc[0]); !ok {
			t.Errorf("%s maps to unknown class %q", code, cc[0])
		}
	}
}

func TestScannerPath(t *testing.T) {
	root := extRoot(t)
	good := map[string]string{
		"src/app.py":                             "src/app.py",
		"./src/app.py":                           "src/app.py",
		`src\my dir\db.py`:                       "src/my dir/db.py",
		"src/../Dockerfile":                      "Dockerfile",
		filepath.Join(root, "deploy", "main.tf"): "deploy/main.tf",
		filepath.ToSlash(filepath.Join(root, "Dockerfile")): "Dockerfile",
	}
	for in, want := range good {
		if got, ok := scannerPath(root, in); !ok || got != want {
			t.Errorf("scannerPath(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", " ", ".", "..", "../x", "src/../../x", "/etc/passwd", `C:\Windows\win.ini`, "src/missing.py", filepath.Join(filepath.Dir(root), "other.py")} {
		if got, ok := scannerPath(root, bad); ok {
			t.Errorf("scannerPath(%q) = %q, want it rejected", bad, got)
		}
	}
}

func TestExternalUnavailableNote(t *testing.T) {
	e := &external{name: "nosuch", bin: "spackle-no-such-scanner-binary", site: "example.org"}
	ok, note := e.Available()
	if ok || !strings.Contains(note, "spackle-no-such-scanner-binary") || !strings.Contains(note, "example.org") {
		t.Errorf("Available() = %v, %q", ok, note)
	}
	for _, s := range External() {
		x := s.(*external)
		if x.site == "" || x.bin == "" || x.leads == nil || x.args == nil {
			t.Errorf("adapter %s is incomplete", x.name)
		}
		if _, isNoter := s.(Noter); !isNoter {
			t.Errorf("adapter %s must implement Noter", x.name)
		}
	}
}

func TestExternalArgs(t *testing.T) {
	root, files := writeTree(t, map[string]string{"a.py": "x=1\n", "svc/Dockerfile": "FROM a:1\n", "Dockerfile": "FROM a:1\n"})
	want := map[string]string{
		"semgrep":     "scan --json --quiet --config auto --metrics off " + root,
		"gitleaks":    "dir --report-format json --report-path - --redact --no-banner --exit-code 0 " + root,
		"osv-scanner": "scan source --format json -r " + root,
		"trivy":       "fs --format json --quiet --scanners vuln,misconfig " + root,
		"hadolint":    "--format json Dockerfile " + filepath.Join("svc", "Dockerfile"),
	}
	for _, s := range External() {
		x := s.(*external)
		argv, ok := x.args(root, files)
		if !ok || strings.Join(argv, " ") != want[x.name] {
			t.Errorf("%s args = %v (ok=%v), want %s", x.name, argv, ok, want[x.name])
		}
	}
	// hadolint has nothing to do without Dockerfiles, and Run must not
	// try to execute it then.
	h := External()[4].(*external)
	if _, ok := h.args(root, nil); ok {
		t.Error("hadolint must be skipped when the listing has no Dockerfile")
	}
	if leads, err := h.Run(context.Background(), root, nil); err != nil || leads != nil {
		t.Errorf("Run with no Dockerfiles = %v, %v", leads, err)
	}
}

// TestExternalScannersInstalled runs each adapter against a tiny target
// when its scanner is installed. It checks the contract (valid leads or a
// descriptive error), not what the scanner finds, because rule sets change
// and some scanners need the network.
func TestExternalScannersInstalled(t *testing.T) {
	needsNetwork := map[string]bool{"semgrep": true, "osv-scanner": true, "trivy": true}
	for _, s := range External() {
		x := s.(*external)
		t.Run(x.name, func(t *testing.T) {
			if _, err := exec.LookPath(x.bin); err != nil {
				t.Skipf("%s is not installed (not on PATH); install it to run this integration test", x.bin)
			}
			if testing.Short() {
				t.Skipf("skipping the %s integration run in -short mode", x.bin)
			}
			if ok, note := x.Available(); !ok {
				t.Fatalf("Available() = false (%s) although %s is on PATH", note, x.bin)
			}
			root, files := writeTree(t, map[string]string{
				"app.py":     "import os\n\ndef run(cmd):\n    os.system(cmd)\n",
				"conf.env":   "GITHUB_TOKEN=" + testRandomToken + "\n",
				"Dockerfile": "FROM alpine:latest\nUSER root\n",
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			leads, err := x.Run(ctx, root, files)
			if err != nil {
				if needsNetwork[x.name] {
					t.Skipf("%s is installed but its run failed, which is expected without network access: %v", x.bin, err)
				}
				t.Fatalf("%s run failed: %v", x.bin, err)
			}
			t.Logf("%s returned %d lead(s); note: %q", x.bin, len(leads), x.Note())
			checkExternalLeads(t, leads)
			assertNoSecret(t, leads)
			if x.name == "gitleaks" && len(leads) == 0 {
				t.Errorf("gitleaks found nothing in a file with a planted token")
			}
		})
	}
}
