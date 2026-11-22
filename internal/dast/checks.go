package dast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/TMHSDigital/spackle/internal/seed"
)

// Hosts used by probes. The .invalid top-level domain is reserved and never
// resolves, and the client would refuse both anyway: neither is in a scope.
const (
	corsProbeOrigin   = "https://spackle-origin-check.invalid"
	redirectProbeHost = "spackle-redirect-check.invalid"
	redirectProbeURL  = "https://" + redirectProbeHost + "/"
)

// signature is one recognizable piece of text.
type signature struct {
	name string
	re   *regexp.Regexp
}

// traceSignatures recognize stack traces and framework error pages. Each
// needs the structure of a real trace, not just a word, so prose that
// mentions "panic" or "fatal error" does not match.
var traceSignatures = []signature{
	{"Python traceback", regexp.MustCompile(`Traceback \(most recent call last\)`)},
	{"Java stack trace", regexp.MustCompile(`Exception in thread "|\bat [a-zA-Z_][\w$]*(?:\.[\w$<>]+)+\([\w$]+\.(?:java|kt|scala):\d+\)`)},
	{"Go panic", regexp.MustCompile(`goroutine \d+ \[running\]|(?m)(?:^|>)panic: `)},
	{"PHP error", regexp.MustCompile(`(?s)(?:Fatal error|Parse error)(?:</b>)?:.{0,400}? on line (?:<b>)?\d+`)},
	{".NET error page", regexp.MustCompile(`Server Error in '`)},
	{"Node.js stack trace", regexp.MustCompile(`\bat Object\.(?:<|&lt;)anonymous(?:>|&gt;)|\bat [\w$.<>]+ \([^()\n]+\.(?:js|ts|mjs|cjs):\d+:\d+\)`)},
}

// stackTrace returns the kind of stack trace in text and where it starts,
// or an empty name.
func stackTrace(text string) (string, int) {
	for _, s := range traceSignatures {
		if loc := s.re.FindStringIndex(text); loc != nil {
			return s.name, loc[0]
		}
	}
	return "", -1
}

// A quote inside an error page is often HTML-escaped, so the SQLite rule
// accepts the entity forms too.
var sqlSignatures = []signature{
	{"SQLite syntax error", regexp.MustCompile(`near (?:["']|&quot;|&#\d+;|&#x[0-9a-fA-F]+;).{0,80}?: syntax error`)},
	{"SQLite OperationalError", regexp.MustCompile(`sqlite3\.OperationalError`)},
	{"SQLite unrecognized token", regexp.MustCompile(`unrecognized token`)},
	{"MySQL syntax error", regexp.MustCompile(`You have an error in your SQL syntax`)},
	{"PostgreSQL unterminated string", regexp.MustCompile(`unterminated quoted string`)},
	{"PostgreSQL syntax error", regexp.MustCompile(`syntax error at or near`)},
	{"SQL Server unclosed quotation mark", regexp.MustCompile(`Unclosed quotation mark`)},
	{"Oracle error", regexp.MustCompile(`ORA-0\d{4}`)},
}

// sqlErrors returns the names of the database error signatures in text.
func sqlErrors(text string) []string {
	var out []string
	for _, s := range sqlSignatures {
		if s.re.MatchString(text) {
			out = append(out, s.name)
		}
	}
	return out
}

var (
	dirListing    = regexp.MustCompile(`(?i)<title>\s*Index of /|Directory listing for`)
	versionNumber = regexp.MustCompile(`\d+\.\d+`)
	passwdFile    = regexp.MustCompile(`root:[x*]:0:0:`)
	envLine       = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*=.*$`)
	fileExtension = regexp.MustCompile(`\.[A-Za-z][A-Za-z0-9]{1,4}$`)
)

var sessionWords = []string{"sess", "sid", "auth", "token", "jwt"}

func sessionCookie(name string) bool {
	low := strings.ToLower(name)
	for _, w := range sessionWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

// redirectParam reports parameter names that usually carry a URL to send
// the browser to.
func redirectParam(name string) bool {
	low := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(name))
	switch low {
	case "next", "url", "dest", "destination", "continue", "goto", "target":
		return true
	}
	return strings.Contains(low, "redirect") || strings.Contains(low, "return") ||
		strings.HasSuffix(low, "url") || strings.HasSuffix(low, "uri")
}

var fileWords = []string{"file", "path", "name", "doc", "page", "template", "download"}

// fileParam reports parameters that look like they name a file, by their
// name or by a value that ends in a file extension.
func fileParam(name, value string) bool {
	low := strings.ToLower(name)
	for _, w := range fileWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return fileExtension.MatchString(value)
}

func isHTML(h hop) bool {
	ct := strings.ToLower(h.header.Get("Content-Type"))
	if ct == "" {
		head := h.body
		if len(head) > 512 {
			head = head[:512]
		}
		low := bytes.ToLower(head)
		return bytes.Contains(low, []byte("<html")) || bytes.Contains(low, []byte("<!doctype html"))
	}
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
}

// excerpt returns up to 300 characters of the recorded (already redacted)
// response body around the first match of find, on one line. When the
// match fell outside the recorded part it returns the start of the body.
func excerpt(h hop, find func(string) int) string {
	text := h.ex.RespBody
	at := -1
	if find != nil {
		at = find(text)
	}
	start := 0
	if at > 60 {
		start = at - 60
		for start > 0 && !isRuneStart(text[start]) {
			start--
		}
	}
	return oneLine(text[start:], 300)
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// oneLine collapses whitespace and cuts to at most n characters.
func oneLine(s string, n int) string {
	fields := strings.Fields(s)
	out := []rune(redacted(strings.Join(fields, " ")))
	if len(out) > n {
		out = append(out[:n-3], '.', '.', '.')
	}
	return string(out)
}

func literal(needle string) func(string) int {
	return func(text string) int { return strings.Index(text, needle) }
}

func pattern(re *regexp.Regexp) func(string) int {
	return func(text string) int {
		if loc := re.FindStringIndex(text); loc != nil {
			return loc[0]
		}
		return -1
	}
}

// observe runs the passive checks on one response.
func (s *scanner) observe(h hop) {
	if h.ex.Status == 0 {
		return
	}
	s.checkSecurityHeaders(h)
	s.checkCookies(h)
	s.checkVersionHeaders(h)
	p := pathOf(h.url)
	text := string(h.body)

	if name, _ := stackTrace(text); name != "" {
		s.add("stack-trace|"+h.url.Host+p, seed.Lead{
			RuleID: "stack-trace", Class: "information-disclosure", Severity: "medium",
			CWE: []string{"CWE-209"}, OWASP: []string{"A05:2021 Security Misconfiguration"},
			Title:    fmt.Sprintf("%s shown to the client at %s", name, show(p, 80)),
			Method:   h.ex.Method,
			Endpoint: p,
			Detail:   fmt.Sprintf("%s %s answered with status %d and a body that contains a %s. It reveals file paths, code structure and library versions to anyone who can trigger the error.", h.ex.Method, show(p, 80), h.ex.Status, name),
			Fix:      "Turn off debug mode and detailed error pages in production, return a generic error page, and write the trace to the server log instead.",
			Snippet: excerpt(h, func(t string) int {
				_, at := stackTrace(t)
				return at
			}),
			Evidence: []string{h.ex.ID},
		})
	}
	if h.ex.Status == http.StatusOK && dirListing.MatchString(text) {
		s.add("directory-listing|"+h.url.Host+p, seed.Lead{
			RuleID: "directory-listing", Class: "directory-listing", Severity: "medium",
			CWE: []string{"CWE-548"}, OWASP: []string{"A05:2021 Security Misconfiguration"},
			Title:    fmt.Sprintf("Directory listing enabled at %s", show(p, 80)),
			Method:   h.ex.Method,
			Endpoint: p,
			Detail:   fmt.Sprintf("GET %s returned an automatic index of the directory, so every file in it can be found and downloaded without knowing its name.", show(p, 80)),
			Fix:      "Disable automatic directory indexes in the web server (for example Options -Indexes in Apache, autoindex off in nginx) and serve only the files that are meant to be public.",
			Snippet:  excerpt(h, pattern(dirListing)),
			Evidence: []string{h.ex.ID},
		})
	}
}

// checkSecurityHeaders looks at the first HTML page of the run only. The
// headers are set site-wide in practice, and one lead per header is more
// useful than one per page.
func (s *scanner) checkSecurityHeaders(h hop) {
	if s.headersChecked || !isHTML(h) || h.ex.Status >= 300 && h.ex.Status < 400 {
		return
	}
	s.headersChecked = true
	p := pathOf(h.url)
	csp := h.header.Get("Content-Security-Policy")
	lead := func(rule, header, what, fix string, cwe ...string) {
		s.add(rule, seed.Lead{
			RuleID: rule, Class: "missing-security-header", Severity: "low",
			CWE: cwe, OWASP: []string{"A05:2021 Security Misconfiguration"},
			Title:    "Missing security header: " + header,
			Method:   h.ex.Method,
			Endpoint: p,
			Detail:   fmt.Sprintf("The HTML response to %s %s (status %d) %s", h.ex.Method, show(p, 80), h.ex.Status, what),
			Fix:      fix,
			Snippet:  oneLine(fmt.Sprintf("HTTP %d; Content-Type: %s; %s is not set", h.ex.Status, h.header.Get("Content-Type"), header), 300),
			Evidence: []string{h.ex.ID},
		})
	}
	if strings.TrimSpace(csp) == "" {
		lead("missing-csp", "Content-Security-Policy",
			"has no Content-Security-Policy header, so the browser applies no restriction on where scripts may load from and an injected script runs freely.",
			"Send a Content-Security-Policy header on every HTML response, starting from default-src 'self' and allowing only the sources the application needs.",
			"CWE-693")
	}
	if !strings.EqualFold(strings.TrimSpace(h.header.Get("X-Content-Type-Options")), "nosniff") {
		lead("missing-x-content-type-options", "X-Content-Type-Options",
			"has no X-Content-Type-Options: nosniff header, so a browser may guess a content type and run an uploaded file as script.",
			"Send X-Content-Type-Options: nosniff on every response.",
			"CWE-693")
	}
	if h.header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		lead("missing-frame-protection", "X-Frame-Options or CSP frame-ancestors",
			"has neither an X-Frame-Options header nor a frame-ancestors directive in its Content-Security-Policy, so another site can load the page in a frame and trick a user into clicking on it.",
			"Send Content-Security-Policy: frame-ancestors 'none' (or 'self'), and X-Frame-Options: DENY for older browsers.",
			"CWE-693", "CWE-1021")
	}
	if h.url.Scheme == "https" && h.header.Get("Strict-Transport-Security") == "" {
		lead("missing-hsts", "Strict-Transport-Security",
			"was served over https without a Strict-Transport-Security header, so a browser will still try plain http and can be downgraded by a network attacker.",
			"Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every https response.",
			"CWE-693", "CWE-319")
	}
}

func (s *scanner) checkCookies(h hop) {
	p := pathOf(h.url)
	for _, raw := range h.header.Values("Set-Cookie") {
		pair, attrs, _ := strings.Cut(raw, ";")
		name, value, ok := strings.Cut(pair, "=")
		name = strings.TrimSpace(name)
		// An empty value clears the cookie; there is nothing to protect.
		if !ok || name == "" || strings.Trim(strings.TrimSpace(value), `"`) == "" || !sessionCookie(name) {
			continue
		}
		flags := map[string]bool{}
		for _, a := range strings.Split(attrs, ";") {
			k, _, _ := strings.Cut(a, "=")
			flags[strings.ToLower(strings.TrimSpace(k))] = true
		}
		var missing, cwe, fixes []string
		if !flags["httponly"] {
			missing = append(missing, "HttpOnly (page scripts can read it)")
			cwe = append(cwe, "CWE-1004")
			fixes = append(fixes, "HttpOnly")
		}
		if h.url.Scheme == "https" && !flags["secure"] {
			missing = append(missing, "Secure (it is also sent over plain http)")
			cwe = append(cwe, "CWE-614")
			fixes = append(fixes, "Secure")
		}
		if !flags["samesite"] {
			missing = append(missing, "SameSite (it is sent with requests that other sites start)")
			cwe = append(cwe, "CWE-1275")
			fixes = append(fixes, "SameSite=Lax or SameSite=Strict")
		}
		if len(missing) == 0 {
			continue
		}
		s.add("insecure-cookie|"+name, seed.Lead{
			RuleID: "insecure-cookie", Class: "insecure-cookie", Severity: "medium",
			CWE: cwe, OWASP: []string{"A05:2021 Security Misconfiguration"},
			Title:    fmt.Sprintf("Session cookie %s is set without protective attributes", show(name, 60)),
			Method:   h.ex.Method,
			Endpoint: p,
			Param:    name,
			Detail:   fmt.Sprintf("%s %s set the cookie %s without: %s.", h.ex.Method, show(p, 80), show(name, 60), strings.Join(missing, "; ")),
			Fix:      fmt.Sprintf("Set the cookie with %s.", strings.Join(fixes, ", ")),
			Snippet:  oneLine("Set-Cookie: "+maskSetCookie(raw), 300),
			Evidence: []string{h.ex.ID},
		})
	}
}

func (s *scanner) checkVersionHeaders(h hop) {
	p := pathOf(h.url)
	for _, name := range []string{"Server", "X-Powered-By"} {
		value := h.header.Get(name)
		if !versionNumber.MatchString(value) {
			continue
		}
		rule := "version-header-" + strings.ToLower(name)
		s.add(rule, seed.Lead{
			RuleID: rule, Class: "information-disclosure", Severity: "low",
			CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021 Security Misconfiguration"},
			Title:    fmt.Sprintf("%s header reveals a software version", name),
			Method:   h.ex.Method,
			Endpoint: p,
			Detail:   fmt.Sprintf("The response to %s %s carries the header %s: %s. An exact version tells an attacker which known vulnerabilities to try.", h.ex.Method, show(p, 80), name, show(redacted(value), 80)),
			Fix:      fmt.Sprintf("Remove the %s header or configure the server to send it without a version.", name),
			Snippet:  oneLine(name+": "+value, 300),
			Evidence: []string{h.ex.ID},
		})
	}
}

// checkCORS sends one request with a foreign Origin and reports a response
// that lets that origin read authenticated responses.
func (s *scanner) checkCORS(start *url.URL) {
	hops, ok := s.fetch("GET", start.String(), map[string]string{"Origin": corsProbeOrigin}, nil)
	if !ok {
		return
	}
	h := hops[len(hops)-1]
	acao := strings.TrimSpace(h.header.Get("Access-Control-Allow-Origin"))
	if !strings.EqualFold(strings.TrimSpace(h.header.Get("Access-Control-Allow-Credentials")), "true") {
		return
	}
	p := pathOf(h.url)
	l := seed.Lead{
		Class: "cors-misconfiguration",
		CWE:   []string{"CWE-942"}, OWASP: []string{"A05:2021 Security Misconfiguration"},
		Method:   "GET",
		Endpoint: p,
		Snippet:  oneLine(fmt.Sprintf("Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: true", acao), 300),
		Evidence: []string{h.ex.ID},
	}
	switch acao {
	case corsProbeOrigin:
		l.RuleID, l.Severity = "cors-reflected-origin", "high"
		l.Title = "CORS policy reflects any origin and allows credentials"
		l.Detail = fmt.Sprintf("A GET to %s with Origin: %s was answered with that origin in Access-Control-Allow-Origin and Access-Control-Allow-Credentials: true. Any website can therefore read responses using a visitor's cookies.", show(p, 80), corsProbeOrigin)
		l.Fix = "Compare the Origin header with a fixed list of trusted origins and echo it only on a match; never reflect an arbitrary origin together with Access-Control-Allow-Credentials: true."
	case "*":
		l.RuleID, l.Severity = "cors-wildcard-credentials", "medium"
		l.Title = "CORS policy combines a wildcard origin with credentials"
		l.Detail = fmt.Sprintf("A GET to %s with Origin: %s was answered with Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true. Browsers refuse this combination, but it shows the policy is meant to be open to every origin with credentials and is one code change away from being exploitable.", show(p, 80), corsProbeOrigin)
		l.Fix = "List the trusted origins explicitly, and send Access-Control-Allow-Credentials: true only for those."
	default:
		return
	}
	s.add(l.RuleID+"|"+p, l)
}

// exposedFile is a well-known path that should not be served, with the
// content that proves it is the real file and not a catch-all page.
type exposedFile struct {
	path  string
	what  string
	match func(body []byte) bool
	fix   string
}

var exposedFiles = []exposedFile{
	{"/.env", "an environment file, which usually holds database passwords and API keys",
		func(b []byte) bool {
			low := bytes.ToLower(b)
			if bytes.Contains(low, []byte("<html")) || bytes.Contains(low, []byte("<!doctype")) {
				return false
			}
			return len(envLine.FindAllIndex(b, 2)) >= 2
		},
		"Move the .env file out of the web root, block dotfiles in the web server, and rotate every secret the file held."},
	{"/.git/HEAD", "the HEAD of a Git repository, which means the whole repository and its history can be downloaded",
		func(b []byte) bool { return bytes.HasPrefix(b, []byte("ref: refs/")) },
		"Do not deploy the .git directory, block /.git in the web server, and rotate any secret that was ever committed."},
	{"/.git/config", "the configuration of a Git repository, which means the whole repository and its history can be downloaded",
		func(b []byte) bool { return bytes.Contains(b, []byte("[core]")) },
		"Do not deploy the .git directory, block /.git in the web server, and rotate any secret that was ever committed."},
	{"/.DS_Store", "a macOS folder index, which lists the names of files in the directory",
		func(b []byte) bool { return bytes.HasPrefix(b, []byte("\x00\x00\x00\x01Bud1")) },
		"Delete .DS_Store files from the deployment and block dotfiles in the web server."},
	{"/server-status", "the Apache status page, which shows current requests, client addresses and URLs",
		func(b []byte) bool { return bytes.Contains(b, []byte("Apache Server Status")) },
		"Restrict mod_status to local or administrative addresses (Require local) or disable it."},
	{"/actuator/env", "the Spring Boot environment endpoint, which lists configuration properties and can expose secrets",
		func(b []byte) bool {
			var doc map[string]json.RawMessage
			if json.Unmarshal(b, &doc) != nil {
				return false
			}
			_, ok := doc["propertySources"]
			return ok
		},
		"Expose only the health actuator endpoint publicly (management.endpoints.web.exposure.include=health) and put the others behind authentication."},
	{"/debug/pprof/", "the Go profiling index, which gives out stack dumps, heap contents and command-line arguments",
		// A page that merely echoes the requested path is not the index;
		// the real one lists the profiles by name.
		func(b []byte) bool {
			return bytes.Contains(b, []byte("/debug/pprof/")) && bytes.Contains(b, []byte("goroutine")) && bytes.Contains(b, []byte("heap"))
		},
		"Do not register net/http/pprof on the public listener; serve it on a separate local-only address."},
}

// checkExposedFiles requests each well-known path on the start host. Paths
// outside the scope's prefixes are refused by the client and skipped.
func (s *scanner) checkExposedFiles(start *url.URL) {
	for _, f := range exposedFiles {
		if s.capped || s.ctx.Err() != nil {
			return
		}
		u := url.URL{Scheme: start.Scheme, Host: start.Host, Path: f.path}
		hops, ok := s.fetch("GET", u.String(), nil, nil)
		if !ok {
			continue
		}
		h := hops[len(hops)-1]
		if h.ex.Status != http.StatusOK || h.url.Path != f.path || !f.match(h.body) {
			continue
		}
		snippet := excerpt(h, nil)
		switch f.path {
		case "/.env":
			snippet = envNames(h.body)
		case "/actuator/env":
			// Property values can be secrets in formats no rule knows.
			snippet = "JSON document with a propertySources list (values not shown)"
		}
		s.add("exposed-file|"+f.path, seed.Lead{
			RuleID: "exposed-file", Class: "exposed-file", Severity: "high",
			CWE: []string{"CWE-538"}, OWASP: []string{"A05:2021 Security Misconfiguration"},
			Title:    "Exposed file: " + f.path,
			Method:   "GET",
			Endpoint: f.path,
			Detail:   fmt.Sprintf("GET %s returned status 200 with %s.", f.path, f.what),
			Fix:      f.fix,
			Snippet:  snippet,
			Evidence: []string{h.ex.ID},
		})
	}
}

// envNames lists the variable names of an environment file with every
// value masked. The values are the secret, and the redaction rules only
// know some formats, so none of them is shown.
func envNames(body []byte) string {
	var parts []string
	for _, line := range envLine.FindAllString(strings.ToValidUTF8(string(body), "?"), 20) {
		name, _, _ := strings.Cut(strings.TrimSpace(line), "=")
		parts = append(parts, show(name, 60)+"="+masked)
	}
	return oneLine(strings.Join(parts, " "), 300)
}

// probeParam runs the active checks for one parameter of one endpoint.
func (s *scanner) probeParam(t *target, param string) {
	orig := t.values.Get(param)
	p := t.ep.Path
	method := t.ep.Method
	key := "|" + method + "|" + t.u.Host + p + "|" + param
	send := func(value string) (hop, bool) {
		if s.capped || s.ctx.Err() != nil {
			return hop{}, false
		}
		values := url.Values{}
		for name, vs := range t.values {
			values[name] = append([]string(nil), vs...)
		}
		values.Set(param, value)
		rawURL, body, headers := t.request(values)
		hops, ok := s.fetch(method, rawURL, headers, body)
		if !ok {
			return hop{}, false
		}
		return hops[len(hops)-1], true
	}
	where := fmt.Sprintf("%s %s with %s", method, show(p, 80), show(param, 60))

	// Angle brackets around a harmless tag: enough to see whether markup
	// survives, with nothing that executes.
	marker := "spk<i>7f3a" + s.nonce()
	if h, ok := send(marker); ok && isHTML(h) && bytes.Contains(h.body, []byte(marker)) {
		s.add("xss"+key, seed.Lead{
			RuleID: "reflected-xss", Class: "xss", Severity: "high",
			CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021 Injection"},
			Title:    fmt.Sprintf("Reflected cross-site scripting in parameter %s of %s", show(param, 60), show(p, 80)),
			Method:   method,
			Endpoint: p,
			Param:    param,
			Detail:   fmt.Sprintf("%s set to the marker %s returned an HTML page (status %d) that contains the marker with its angle brackets intact. Markup sent in this parameter is written into the page unescaped, so a crafted link runs script in the visitor's session.", where, marker, h.ex.Status),
			Fix:      "HTML-escape the parameter where it is written into the page (use the template engine's auto-escaping, and the escaping that fits the context for attributes, scripts and URLs).",
			Snippet:  excerpt(h, literal(marker)),
			Evidence: []string{h.ex.ID},
		})
	}

	if h, ok := send(orig + "'"); ok {
		var fresh []string
		for _, name := range sqlErrors(string(h.body)) {
			if !t.baseErrors[name] {
				fresh = append(fresh, name)
			}
		}
		if len(fresh) > 0 {
			s.add("sqli"+key, seed.Lead{
				RuleID: "sql-error", Class: "sql-injection", Severity: "critical",
				CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021 Injection"},
				Title:    fmt.Sprintf("SQL injection (error-based) in parameter %s of %s", show(param, 60), show(p, 80)),
				Method:   method,
				Endpoint: p,
				Param:    param,
				Detail:   fmt.Sprintf("%s set to its original value followed by a single quote returned status %d with a database error (%s) that the unmodified request did not produce. The value reaches a SQL statement without being bound as a parameter.", where, h.ex.Status, strings.Join(fresh, ", ")),
				Fix:      "Build the query with bound parameters (prepared statements) instead of string concatenation, and return a generic error page rather than the database message.",
				Snippet: excerpt(h, func(text string) int {
					for _, sig := range sqlSignatures {
						if loc := sig.re.FindStringIndex(text); loc != nil {
							return loc[0]
						}
					}
					return -1
				}),
				Evidence: []string{h.ex.ID},
			})
		}
	}

	if method != "GET" {
		// Forms that change state get the two injection checks only.
		return
	}

	if redirectParam(param) {
		if h, ok := send(redirectProbeURL); ok && h.ex.Status >= 300 && h.ex.Status < 400 {
			if loc, err := url.Parse(h.header.Get("Location")); err == nil && strings.EqualFold(loc.Hostname(), redirectProbeHost) {
				s.add("redirect"+key, seed.Lead{
					RuleID: "open-redirect", Class: "open-redirect", Severity: "medium",
					CWE: []string{"CWE-601"}, OWASP: []string{"A01:2021 Broken Access Control"},
					Title:    fmt.Sprintf("Open redirect in parameter %s of %s", show(param, 60), show(p, 80)),
					Method:   method,
					Endpoint: p,
					Param:    param,
					Detail:   fmt.Sprintf("%s set to %s returned status %d with a Location header pointing at that host. A link to this site can therefore send a visitor to any other site, which makes phishing links look trustworthy. The redirect was not followed.", where, redirectProbeURL, h.ex.Status),
					Fix:      "Redirect only to relative paths or to hosts on a fixed allowlist, and fall back to a default page for anything else.",
					Snippet:  oneLine(fmt.Sprintf("HTTP %d; Location: %s", h.ex.Status, h.header.Get("Location")), 300),
					Evidence: []string{h.ex.ID},
				})
			}
		}
	}

	if fileParam(param, orig) {
		for _, payload := range []string{`../../../../../../etc/passwd`, `..\..\..\..\..\..\windows\win.ini`} {
			h, ok := send(payload)
			if !ok {
				continue
			}
			var find func(string) int
			switch {
			case passwdFile.Match(h.body):
				find = pattern(passwdFile)
			case bytes.Contains(h.body, []byte("[fonts]")) && bytes.Contains(h.body, []byte("[extensions]")):
				find = literal("[fonts]")
			default:
				continue
			}
			s.add("traversal"+key, seed.Lead{
				RuleID: "path-traversal", Class: "path-traversal", Severity: "high",
				CWE: []string{"CWE-22"}, OWASP: []string{"A01:2021 Broken Access Control"},
				Title:    fmt.Sprintf("Path traversal in parameter %s of %s", show(param, 60), show(p, 80)),
				Method:   method,
				Endpoint: p,
				Param:    param,
				Detail:   fmt.Sprintf("%s set to %s returned status %d with the content of a system file. The parameter is used as a file path without being confined to the intended directory, so any file the server process can read can be downloaded.", where, payload, h.ex.Status),
				Fix:      "Resolve the requested name against a fixed base directory and refuse any result outside it, or map the parameter to an allowlist of files instead of using it as a path.",
				Snippet:  excerpt(h, find),
				Evidence: []string{h.ex.ID},
			})
			break
		}
	}
}

func pathOf(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}
