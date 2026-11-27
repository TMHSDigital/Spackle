package dast

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/seed"
)

// hitLog records which paths a test server was asked for.
type hitLog struct {
	mu    sync.Mutex
	paths []string
}

func (h *hitLog) add(r *http.Request) {
	h.mu.Lock()
	h.paths = append(h.paths, r.Method+" "+r.URL.Path)
	h.mu.Unlock()
}

func (h *hitLog) count(prefix string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, p := range h.paths {
		if strings.HasPrefix(p, prefix) {
			n++
		}
	}
	return n
}

// flawedApp is wrong in every way the baseline checks for. otherURL is a
// second server the app links and redirects to; it is never in scope.
func flawedApp(t *testing.T, otherURL string) (*httptest.Server, *hitLog) {
	t.Helper()
	log := &hitLog{}
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.1 (Unix)")
		w.Header().Set("X-Powered-By", "PHP/5.4.3")
		_, _ = io.WriteString(w, "<html><head><title>shop</title></head><body>"+body+"</body></html>")
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Add("Set-Cookie", "sessionid=abc123def456; Path=/")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/")
		page(w, `
<a href="/search?q=hello">search</a>
<a href='/item?id=1'>item</a>
<a href=/go?next=/home>go</a>
<a href="/view?file=readme.txt">view</a>
<a href="/files/">files</a>
<a href="/crash">crash</a>
<a href="/logout">log out</a>
<a href="/account/delete?id=1">delete account</a>
<a href="`+otherURL+`/elsewhere">partner</a>
<a href="mailto:a@example.test">mail</a>
<a href="#top">top</a>
<img src="/static/logo.png">
<form action="/comment" method="post">
  <input type="text" name="author" value="anon">
  <textarea name="text"></textarea>
  <input type="submit" name="go" value="Send">
</form>
<form action="/find">
  <input name="term" value="shoes">
  <select name="sort"><option>asc</option></select>
</form>`)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, _ *http.Request) { page(w, "home") })
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		page(w, "results for "+r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/find", func(w http.ResponseWriter, r *http.Request) {
		page(w, "found "+html.EscapeString(r.URL.Query().Get("term")))
	})
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.WriteHeader(http.StatusInternalServerError)
			page(w, `sqlite3.OperationalError: near "'": syntax error`)
			return
		}
		page(w, "item one")
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("next"))
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/view", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		f := r.URL.Query().Get("file")
		switch {
		case strings.Contains(f, "etc/passwd"):
			_, _ = io.WriteString(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/sbin/nologin\n")
		case strings.Contains(f, "win.ini"):
			_, _ = io.WriteString(w, "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n")
		default:
			_, _ = io.WriteString(w, "read me")
		}
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1></body></html>")
	})
	mux.HandleFunc("/crash", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		page(w, "<pre>Traceback (most recent call last):\n  File \"app.py\", line 3, in view\nKeyError: 'x'</pre>")
	})
	mux.HandleFunc("/comment", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if strings.Contains(r.PostForm.Get("author"), "'") {
			page(w, "You have an error in your SQL syntax; check the manual")
			return
		}
		page(w, "thanks: "+r.PostForm.Get("text"))
	})
	plain := func(path, body string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, body)
		})
	}
	plain("/.env", "DB_HOST=localhost\nDB_USER=app\nDB_PASSWORD="+"hunter"+"2222\n")
	plain("/.git/HEAD", "ref: refs/heads/main\n")
	plain("/.git/config", "[core]\n\trepositoryformatversion = 0\n")
	plain("/.DS_Store", "\x00\x00\x00\x01Bud1\x00\x00")
	plain("/server-status", "<h1>Apache Server Status for localhost</h1>")
	plain("/actuator/env", `{"activeProfiles":[],"propertySources":[{"name":"systemEnvironment"}]}`)
	plain("/debug/pprof/", "<title>/debug/pprof/</title>\nTypes of profiles available:\n1 goroutine\n2 heap\n")
	plain("/logout", "bye")
	plain("/account/delete", "deleted")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

// hardenedApp has the same shape as flawedApp with every flaw fixed.
func hardenedApp(t *testing.T) (*httptest.Server, *hitLog) {
	t.Helper()
	log := &hitLog{}
	mux := http.NewServeMux()
	secure := func(w http.ResponseWriter) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Server", "web")
	}
	page := func(w http.ResponseWriter, body string) {
		secure(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><head><title>shop</title></head><body>"+body+"</body></html>")
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			secure(w)
			http.NotFound(w, r)
			return
		}
		w.Header().Add("Set-Cookie", "sessionid=abc123def456; Path=/; HttpOnly; SameSite=Strict")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/")
		page(w, `
<a href="/search?q=hello">search</a>
<a href="/item?id=1">item</a>
<a href="/go?next=/home">go</a>
<a href="/view?file=readme.txt">view</a>
<a href="/docs?topic=sql">docs</a>
<form action="/find"><input name="term" value="shoes"></form>`)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, _ *http.Request) { page(w, "home") })
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		page(w, "results for "+html.EscapeString(r.URL.Query().Get("q")))
	})
	mux.HandleFunc("/find", func(w http.ResponseWriter, r *http.Request) {
		page(w, "found "+html.EscapeString(r.URL.Query().Get("term")))
	})
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "1" {
			secure(w)
			http.Error(w, "no such item", http.StatusNotFound)
			return
		}
		page(w, "item one")
	})
	// The documentation page always quotes a database error. It is in the
	// unmodified response too, so it is not evidence of injection.
	mux.HandleFunc("/docs", func(w http.ResponseWriter, _ *http.Request) {
		page(w, "MySQL reports: You have an error in your SQL syntax")
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		http.Redirect(w, r, "/home", http.StatusFound)
	})
	mux.HandleFunc("/view", func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		if r.URL.Query().Get("file") != "readme.txt" {
			http.Error(w, "no such file", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "read me")
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

func baseline(t *testing.T, c *Client, start string, opts Options) Result {
	t.Helper()
	u, err := url.Parse(start)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Baseline(context.Background(), c, u, opts)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	return res
}

// find returns the leads with the given class, narrowed by rule id when
// rule is not empty.
func find(leads []seed.Lead, class, rule string) []seed.Lead {
	var out []seed.Lead
	for _, l := range leads {
		if l.Class == class && (rule == "" || l.RuleID == rule) {
			out = append(out, l)
		}
	}
	return out
}

func one(t *testing.T, leads []seed.Lead, class, rule string) seed.Lead {
	t.Helper()
	got := find(leads, class, rule)
	if len(got) != 1 {
		t.Fatalf("leads with class %s rule %q: got %d, want 1\n%s", class, rule, len(got), describe(leads))
	}
	return got[0]
}

func describe(leads []seed.Lead) string {
	var b strings.Builder
	for _, l := range leads {
		fmt.Fprintf(&b, "  %s %s %s %s param=%q: %s\n", l.Class, l.RuleID, l.Method, l.Endpoint, l.Param, l.Title)
	}
	return b.String()
}

func TestBaselineFlawedApp(t *testing.T) {
	other, otherHits := counter(t)
	srv, log := flawedApp(t, other.URL)
	c := clientFor(t, srv.URL, "", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{})
	leads := res.Leads

	for _, rule := range []string{"missing-csp", "missing-x-content-type-options", "missing-frame-protection"} {
		l := one(t, leads, "missing-security-header", rule)
		if l.Endpoint != "/" || l.Severity != "low" {
			t.Fatalf("%s lead = %+v", rule, l)
		}
	}
	if got := find(leads, "missing-security-header", "missing-hsts"); len(got) != 0 {
		t.Fatal("HSTS was reported for a plain http target")
	}

	cookie := one(t, leads, "insecure-cookie", "")
	if cookie.Param != "sessionid" || cookie.Severity != "medium" {
		t.Fatalf("cookie lead = %+v", cookie)
	}
	if !strings.Contains(cookie.Detail, "HttpOnly") || !strings.Contains(cookie.Detail, "SameSite") {
		t.Fatalf("cookie detail = %q", cookie.Detail)
	}
	if strings.Contains(cookie.Detail, "Secure") {
		t.Fatalf("Secure was demanded over plain http: %q", cookie.Detail)
	}
	if strings.Contains(cookie.Snippet, "abc123def456") {
		t.Fatalf("cookie snippet holds the cookie value: %q", cookie.Snippet)
	}

	cors := one(t, leads, "cors-misconfiguration", "")
	if cors.Severity != "high" {
		t.Fatalf("cors lead = %+v", cors)
	}

	trace := one(t, leads, "information-disclosure", "stack-trace")
	if trace.Endpoint != "/crash" || trace.Severity != "medium" || !strings.Contains(trace.Snippet, "Traceback") {
		t.Fatalf("stack trace lead = %+v", trace)
	}
	for _, rule := range []string{"version-header-server", "version-header-x-powered-by"} {
		if l := one(t, leads, "information-disclosure", rule); l.Severity != "low" {
			t.Fatalf("%s lead = %+v", rule, l)
		}
	}

	if l := one(t, leads, "directory-listing", ""); l.Endpoint != "/files/" {
		t.Fatalf("directory listing lead = %+v", l)
	}

	xss := one(t, leads, "xss", "")
	if xss.Endpoint != "/search" || xss.Param != "q" || xss.Method != http.MethodGet || xss.Severity != "high" {
		t.Fatalf("xss lead = %+v", xss)
	}

	sqli := one(t, leads, "sql-injection", "")
	if sqli.Endpoint != "/item" || sqli.Param != "id" || sqli.Severity != "critical" {
		t.Fatalf("sql injection lead = %+v", sqli)
	}

	redir := one(t, leads, "open-redirect", "")
	if redir.Endpoint != "/go" || redir.Param != "next" {
		t.Fatalf("open redirect lead = %+v", redir)
	}

	trav := one(t, leads, "path-traversal", "")
	if trav.Endpoint != "/view" || trav.Param != "file" {
		t.Fatalf("path traversal lead = %+v", trav)
	}

	exposed := find(leads, "exposed-file", "")
	var paths []string
	for _, l := range exposed {
		paths = append(paths, l.Endpoint)
	}
	sort.Strings(paths)
	want := "/.DS_Store,/.env,/.git/HEAD,/.git/config,/actuator/env,/debug/pprof/,/server-status"
	if strings.Join(paths, ",") != want {
		t.Fatalf("exposed files = %v, want %s", paths, want)
	}
	for _, l := range exposed {
		if l.Endpoint == "/.env" && (strings.Contains(l.Snippet, "hunter") || strings.Contains(l.Snippet, "localhost")) {
			t.Fatalf(".env snippet holds values: %q", l.Snippet)
		}
	}

	// Every lead is usable by the caller as it stands.
	for _, l := range leads {
		if _, ok := finding.DefaultVector(l.Class); !ok {
			t.Errorf("class %q is unknown to finding.DefaultVector", l.Class)
		}
		if l.Surface != finding.SurfaceDAST || l.ID != "" || l.Source != "" {
			t.Errorf("lead %s: surface %q id %q source %q", l.RuleID, l.Surface, l.ID, l.Source)
		}
		if l.Title == "" || l.Detail == "" || l.Fix == "" || l.RuleID == "" || l.Endpoint == "" || l.Method == "" || len(l.CWE) == 0 {
			t.Errorf("lead is incomplete: %+v", l)
		}
		if strings.HasSuffix(l.Title, ".") {
			t.Errorf("title ends with a period: %q", l.Title)
		}
		if len([]rune(l.Snippet)) > 300 {
			t.Errorf("snippet of %s is %d chars", l.RuleID, len([]rune(l.Snippet)))
		}
		if len(l.Evidence) == 0 {
			t.Errorf("lead %s has no evidence", l.RuleID)
		}
		for _, id := range l.Evidence {
			if _, ok := c.Exchange(id); !ok {
				t.Errorf("lead %s: evidence %s does not resolve", l.RuleID, id)
			}
		}
		switch l.Severity {
		case "critical", "high", "medium", "low":
		default:
			t.Errorf("lead %s has severity %q", l.RuleID, l.Severity)
		}
	}

	// Identity is unique, so Finalize gives every lead its own id.
	ids := map[string]string{}
	for _, l := range leads {
		l.Source = "dast-baseline"
		l.Finalize()
		if prev, dup := ids[l.ID]; dup {
			t.Errorf("leads %q and %q share an id", prev, l.Title)
		}
		ids[l.ID] = l.Title
	}

	// The crawl stayed in scope and left session-ending links alone.
	if otherHits.Load() != 0 {
		t.Fatalf("the out-of-scope server saw %d requests", otherHits.Load())
	}
	if log.count("GET /logout") != 0 || log.count("GET /account/delete") != 0 {
		t.Fatal("the crawl followed a logout-like link")
	}
	if log.count("POST ") != 0 {
		t.Fatal("a POST was sent without allow_unsafe_methods")
	}
	notes := strings.Join(res.Notes, "\n")
	for _, want := range []string{"logout", "allow_unsafe_methods = true", "outside the authorized scope"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}

	wantEndpoints := map[string]string{
		"GET /":         "start",
		"GET /search":   "link",
		"GET /find":     "form",
		"POST /comment": "form",
	}
	for _, e := range res.Endpoints {
		key := e.Method + " " + e.Path
		if src, ok := wantEndpoints[key]; ok {
			if e.Source != src {
				t.Errorf("endpoint %s has source %q, want %q", key, e.Source, src)
			}
			delete(wantEndpoints, key)
		}
		if e.Path == "/logout" || strings.Contains(e.Path, "elsewhere") {
			t.Errorf("endpoint %s should not be listed", key)
		}
		if key == "GET /find" && strings.Join(e.Params, ",") != "sort,term" {
			t.Errorf("form params = %v, want sorted names", e.Params)
		}
		if key == "POST /comment" && strings.Join(e.Params, ",") != "author,text" {
			t.Errorf("POST form params = %v (submit buttons are not fields)", e.Params)
		}
	}
	if len(wantEndpoints) != 0 {
		t.Errorf("endpoints not discovered: %v", wantEndpoints)
	}
}

func TestBaselineHardenedApp(t *testing.T) {
	srv, _ := hardenedApp(t)
	c := clientFor(t, srv.URL, "", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{})
	if len(res.Leads) != 0 {
		t.Fatalf("a hardened app produced %d leads:\n%s", len(res.Leads), describe(res.Leads))
	}
	if len(res.Endpoints) < 5 {
		t.Fatalf("the crawl found only %d endpoints", len(res.Endpoints))
	}
	// The open-redirect probe was sent and the client stayed home.
	for _, ex := range c.Exchanges() {
		if strings.Contains(ex.URL, "spackle-redirect-check.invalid") && ex.Status == 0 {
			t.Fatalf("exchange %s has no response: %+v", ex.ID, ex)
		}
	}
}

func TestBaselineOpenRedirectIsNotFollowed(t *testing.T) {
	other, _ := counter(t)
	srv, _ := flawedApp(t, other.URL)
	c := clientFor(t, srv.URL, "", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{})
	l := one(t, res.Leads, "open-redirect", "")
	ex, ok := c.Exchange(l.Evidence[0])
	if !ok {
		t.Fatal("evidence does not resolve")
	}
	if ex.Status != http.StatusFound || !strings.Contains(ex.RespHeaders["Location"], "spackle-redirect-check.invalid") {
		t.Fatalf("proving exchange = %+v", ex)
	}
	if !strings.Contains(ex.Note, "out-of-scope host") {
		t.Fatalf("note = %q, want the refused redirect recorded", ex.Note)
	}
	for _, e := range c.Exchanges() {
		if u, err := url.Parse(e.URL); err != nil || u.Hostname() == "spackle-redirect-check.invalid" {
			t.Fatalf("a request was sent to the check host: %+v", e)
		}
	}
}

func TestBaselineUnsafeForms(t *testing.T) {
	other, _ := counter(t)
	srv, log := flawedApp(t, other.URL)
	c := clientFor(t, srv.URL, "allow_unsafe_methods = true", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{})
	var xss, sqli bool
	for _, l := range res.Leads {
		if l.Method != http.MethodPost {
			continue
		}
		if l.Endpoint != "/comment" {
			t.Fatalf("POST lead on %s", l.Endpoint)
		}
		switch {
		case l.Class == "xss" && l.Param == "text":
			xss = true
		case l.Class == "sql-injection" && l.Param == "author":
			sqli = true
		case l.Class == "xss" || l.Class == "sql-injection" || l.Class == "open-redirect" || l.Class == "path-traversal":
			t.Fatalf("unexpected POST lead: %+v", l)
		}
	}
	if !xss || !sqli {
		t.Fatalf("POST form leads: xss=%v sqli=%v\n%s", xss, sqli, describe(res.Leads))
	}
	if log.count("POST /comment") == 0 {
		t.Fatal("no POST reached the form")
	}
	if log.count("POST /logout") != 0 || log.count("GET /logout") != 0 {
		t.Fatal("a logout-like endpoint was requested")
	}
	if strings.Contains(strings.Join(res.Notes, "\n"), "allow_unsafe_methods = true") {
		t.Fatal("the not-probed note was added although unsafe methods are allowed")
	}
}

func TestBaselineHTTPS(t *testing.T) {
	serve := func(hardened bool) *httptest.Server {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if hardened {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000")
				w.Header().Set("Set-Cookie", "auth_token=v1v2v3v4; Secure; HttpOnly; SameSite=Lax")
			} else {
				w.Header().Set("Set-Cookie", "auth_token=v1v2v3v4; HttpOnly; SameSite=Lax")
			}
			_, _ = io.WriteString(w, "<html><body>hi</body></html>")
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	weak := serve(false)
	c := clientFor(t, weak.URL, "", ClientOptions{HTTP: weak.Client()})
	res := baseline(t, c, weak.URL+"/", Options{})
	one(t, res.Leads, "missing-security-header", "missing-hsts")
	cookie := one(t, res.Leads, "insecure-cookie", "")
	if !strings.Contains(cookie.Detail, "Secure") || strings.Contains(cookie.Detail, "HttpOnly") {
		t.Fatalf("cookie detail = %q, want only Secure reported", cookie.Detail)
	}
	if len(res.Leads) != 2 {
		t.Fatalf("leads:\n%s", describe(res.Leads))
	}

	strong := serve(true)
	c = clientFor(t, strong.URL, "", ClientOptions{HTTP: strong.Client()})
	if res := baseline(t, c, strong.URL+"/", Options{}); len(res.Leads) != 0 {
		t.Fatalf("hardened https app produced leads:\n%s", describe(res.Leads))
	}
}

func TestBaselineCORSWildcard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
	}))
	defer srv.Close()
	c := clientFor(t, srv.URL, "", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{})
	if l := one(t, res.Leads, "cors-misconfiguration", ""); l.Severity != "medium" {
		t.Fatalf("wildcard cors lead = %+v", l)
	}

	// A fixed allowed origin, or a wildcard without credentials, is fine.
	for _, hdr := range []map[string]string{
		{"Access-Control-Allow-Origin": "https://app.example.test", "Access-Control-Allow-Credentials": "true"},
		{"Access-Control-Allow-Origin": "*"},
	} {
		ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range hdr {
				w.Header().Set(k, v)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "{}")
		}))
		c := clientFor(t, ok.URL, "", ClientOptions{})
		res := baseline(t, c, ok.URL+"/", Options{})
		ok.Close()
		if got := find(res.Leads, "cors-misconfiguration", ""); len(got) != 0 {
			t.Fatalf("headers %v produced a cors lead", hdr)
		}
	}
}

func TestBaselineExposedFileNeedsSignature(t *testing.T) {
	// A catch-all app answers 200 with the same page for every path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.WriteString(w, "<html><body>app shell for "+html.EscapeString(r.URL.Path)+"</body></html>")
	}))
	defer srv.Close()
	c := clientFor(t, srv.URL, "", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{})
	if len(res.Leads) != 0 {
		t.Fatalf("a catch-all page produced leads:\n%s", describe(res.Leads))
	}
}

func TestBaselineExposedFilesRespectPathPrefix(t *testing.T) {
	other, _ := counter(t)
	srv, log := flawedApp(t, other.URL)
	c := clientFor(t, srv.URL+"/search", `path_prefixes = ["/search"]`, ClientOptions{})
	res := baseline(t, c, srv.URL+"/search?q=a", Options{})
	if got := find(res.Leads, "exposed-file", ""); len(got) != 0 {
		t.Fatalf("exposed files outside the path prefix were reported: %v", got)
	}
	if log.count("GET /.env") != 0 || log.count("GET /.git") != 0 {
		t.Fatal("a path outside the scope prefix was requested")
	}
	one(t, res.Leads, "xss", "")
}

// jsonAPI answers JSON with no links, so a crawl from / finds nothing else.
// /api/report leaks a stack trace that only a seeded route can reach.
func jsonAPI(t *testing.T) (*httptest.Server, *hitLog) {
	t.Helper()
	log := &hitLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `{"service":"api","version":1}`)
		case "/api/items", "/api/health", "/about/", "/admin/stats":
			_, _ = io.WriteString(w, `{"ok":true}`)
		case "/api/report":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"Traceback (most recent call last):\n  File \"/srv/app/report.py\", line 12, in build\nKeyError: 'x'"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

func TestBaselineSeedsRoutes(t *testing.T) {
	plain, _ := jsonAPI(t)
	without := baseline(t, clientFor(t, plain.URL, "", ClientOptions{}), plain.URL+"/", Options{})
	if len(without.Endpoints) != 1 || len(find(without.Leads, "information-disclosure", "stack-trace")) != 0 {
		t.Fatalf("without seeds the crawl should see only the start URL: %+v", without.Endpoints)
	}

	srv, log := jsonAPI(t)
	c := clientFor(t, srv.URL, "", ClientOptions{})
	seeds := []string{
		"/api/items", "/api/report", "GET /api/health", "about/", "/api/items", "/",
		"/users/:id", "/users/{id}", "/users/<int:id>", "^articles/$", "POST /api/items", "example.com/x", "//evil.test/x", "/a b", "/static/*",
	}
	res := baseline(t, c, srv.URL+"/", Options{Seeds: seeds})
	var routes []string
	for _, ep := range res.Endpoints {
		if ep.Source == "route" {
			routes = append(routes, ep.Method+" "+ep.Path)
		}
	}
	sort.Strings(routes)
	if want := "GET /about/,GET /api/health,GET /api/items,GET /api/report"; strings.Join(routes, ",") != want {
		t.Fatalf("route endpoints = %v, want %s", routes, want)
	}
	for _, p := range []string{"GET /api/items", "GET /api/report", "GET /api/health", "GET /about/"} {
		if log.count(p) == 0 {
			t.Errorf("%s was not requested", p)
		}
	}
	if log.count("GET /users") != 0 || log.count("POST ") != 0 || log.count("GET /static") != 0 {
		t.Fatalf("a route with a parameter, or a non-GET route, was requested: %v", log.paths)
	}
	one(t, res.Leads, "information-disclosure", "stack-trace")
	notes := strings.Join(res.Notes, "\n")
	if !strings.Contains(notes, "4 endpoint(s) were added from 15 source route(s)") || !strings.Contains(notes, "9 route(s)") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

func TestBaselineSeedsStayInScope(t *testing.T) {
	srv, log := jsonAPI(t)
	c := clientFor(t, srv.URL+"/api/items", `path_prefixes = ["/api"]`, ClientOptions{})
	u, err := url.Parse(srv.URL + "/api/items")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Baseline(context.Background(), c, u, Options{Seeds: []string{"/api/health", "/admin/stats"}})
	if err != nil {
		t.Fatal(err)
	}
	if log.count("GET /admin") != 0 {
		t.Fatal("a seeded route outside the path prefixes was requested")
	}
	if log.count("GET /api/health") == 0 {
		t.Fatal("a seeded route inside the scope was not requested")
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "outside the authorized scope") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

func TestBaselineMaxPages(t *testing.T) {
	var pages atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The CORS probe revisits the start page; it is not a crawled page.
		if r.Header.Get("Origin") == "" && (strings.HasPrefix(r.URL.Path, "/p") || r.URL.Path == "/") {
			pages.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		for i := 0; i < 30; i++ {
			fmt.Fprintf(&b, `<a href="/p%d">p</a>`, i)
		}
		_, _ = io.WriteString(w, "<html><body>"+b.String()+"</body></html>")
	}))
	defer srv.Close()
	c := clientFor(t, srv.URL, "", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{MaxPages: 4})
	if pages.Load() != 4 {
		t.Fatalf("pages fetched = %d, want 4", pages.Load())
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "MaxPages") {
		t.Fatalf("notes do not mention the page limit: %v", res.Notes)
	}
	if len(res.Endpoints) != 31 {
		t.Fatalf("endpoints = %d, want 31 (found even when not fetched)", len(res.Endpoints))
	}
}

func TestBaselineRequestCap(t *testing.T) {
	other, _ := counter(t)
	srv, log := flawedApp(t, other.URL)
	c := clientFor(t, srv.URL, "max_requests = 5", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{})
	if c.Requests() != 5 || log.count("") != 5 {
		t.Fatalf("requests = %d, server saw %d; want 5", c.Requests(), log.count(""))
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "request cap") {
		t.Fatalf("notes do not mention the request cap: %v", res.Notes)
	}
}

func TestBaselineSkipsParamsNearCap(t *testing.T) {
	other, _ := counter(t)
	srv, _ := flawedApp(t, other.URL)
	// Enough for the crawl and the fixed probes, too few for every parameter.
	c := clientFor(t, srv.URL, "max_requests = 30", ClientOptions{})
	res := baseline(t, c, srv.URL+"/", Options{})
	if c.Requests() > 30 {
		t.Fatalf("requests = %d, over the cap", c.Requests())
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "not probed") {
		t.Fatalf("notes do not say parameters were skipped: %v", res.Notes)
	}
}

func TestBaselineUnreachable(t *testing.T) {
	srv, _ := counter(t)
	c := clientFor(t, srv.URL, "", ClientOptions{})
	target := srv.URL
	srv.Close()
	u, _ := url.Parse(target + "/")
	if _, err := Baseline(context.Background(), c, u, Options{}); err == nil {
		t.Fatal("an unreachable target returned no error")
	}

	other, _ := counter(t)
	in, _ := counter(t)
	c = clientFor(t, in.URL, "", ClientOptions{})
	u, _ = url.Parse(other.URL + "/")
	if _, err := Baseline(context.Background(), c, u, Options{}); err == nil {
		t.Fatal("an out-of-scope start URL returned no error")
	}
	if _, err := Baseline(context.Background(), nil, u, Options{}); err == nil {
		t.Fatal("a nil client returned no error")
	}
	if _, err := Baseline(context.Background(), c, nil, Options{}); err == nil {
		t.Fatal("a nil start URL returned no error")
	}
}

func TestBaselineCancelled(t *testing.T) {
	srv, _ := hardenedApp(t)
	c := clientFor(t, srv.URL, "", ClientOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u, _ := url.Parse(srv.URL + "/")
	done := make(chan error, 1)
	go func() {
		_, err := Baseline(ctx, c, u, Options{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled run returned no error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled run did not stop")
	}
}

func TestExtractLinksAndForms(t *testing.T) {
	base, _ := url.Parse("http://app.test/dir/page?x=1")
	body := `<A HREF="one?a=1&amp;b=2">x</A> <a href='/two'>y</a> <a href=three>z</a>
<script src="/app.js"></script> <a href="javascript:alert(1)">j</a> <a href="#frag">f</a>
<form METHOD=POST action="/save"><input name=title value="t"><input type=hidden name="csrf" value="tok">
<input type="submit" name="s" value="go"><input type="file" name="up"><textarea name="body"></textarea>
<select name="kind"></select></form>
<form><input name="q"></form>`
	links, forms := extract([]byte(body), base)
	var got []string
	for _, l := range links {
		got = append(got, l.String())
	}
	want := "http://app.test/dir/one?a=1&b=2 http://app.test/two http://app.test/dir/three http://app.test/app.js"
	if strings.Join(got, " ") != want {
		t.Fatalf("links = %v\nwant    %s", got, want)
	}
	if len(forms) != 2 {
		t.Fatalf("forms = %+v", forms)
	}
	f := forms[0]
	if f.method != "POST" || f.action.String() != "http://app.test/save" {
		t.Fatalf("form = %+v", f)
	}
	if f.values.Get("title") != "t" || f.values.Get("csrf") != "tok" || !f.values.Has("body") || !f.values.Has("kind") {
		t.Fatalf("form values = %v", f.values)
	}
	if f.values.Has("s") || f.values.Has("up") {
		t.Fatalf("buttons and file inputs are not fields: %v", f.values)
	}
	if forms[1].method != "GET" || forms[1].action.String() != "http://app.test/dir/page" || !forms[1].values.Has("q") {
		t.Fatalf("default form = %+v", forms[1])
	}
}

func TestSignatures(t *testing.T) {
	traces := []string{
		"Traceback (most recent call last):\n  File",
		"Exception in thread \"main\" java.lang.NullPointerException",
		"\tat com.shop.Cart.total(Cart.java:42)",
		"goroutine 1 [running]:\nmain.main()",
		"<pre>panic: runtime error: index out of range",
		"<b>Fatal error</b>: Uncaught Error in /var/www/a.php on line <b>12</b>",
		"Server Error in '/' Application.",
		"    at Object.<anonymous> (/srv/app/index.js:10:5)",
		"    at Object.&lt;anonymous&gt; (/srv/app/index.js:10:5)",
	}
	for _, s := range traces {
		if name, _ := stackTrace(s); name == "" {
			t.Errorf("no stack trace found in %q", s)
		}
	}
	for _, s := range []string{
		"We looked at com.shop for a while. Do not panic: it is fine.",
		"There was a fatal error on our side, sorry.",
		"The goroutine model is explained on line 4.",
	} {
		if name, _ := stackTrace(s); name != "" {
			t.Errorf("stack trace %s found in harmless text %q", name, s)
		}
	}

	dbErrors := []string{
		`near "'": syntax error`,
		"near &#34;&#39;&#34;: syntax error",
		"sqlite3.OperationalError: bad",
		`unrecognized token: "'"`,
		"You have an error in your SQL syntax; check",
		"ERROR: unterminated quoted string at or near",
		`syntax error at or near "'"`,
		"Unclosed quotation mark after the character string",
		"ORA-01756: quoted string not properly terminated",
	}
	for _, s := range dbErrors {
		if len(sqlErrors(s)) == 0 {
			t.Errorf("no database error found in %q", s)
		}
	}
	if got := sqlErrors("Nothing matched your search for it's"); len(got) != 0 {
		t.Errorf("database error %v found in harmless text", got)
	}
}

func TestParamHeuristics(t *testing.T) {
	for _, name := range []string{"next", "url", "redirect", "return", "returnTo", "dest", "continue", "goto", "redirect_uri", "return_url"} {
		if !redirectParam(name) {
			t.Errorf("%s should be a redirect parameter", name)
		}
	}
	for _, name := range []string{"q", "id", "page", "curly"} {
		if redirectParam(name) {
			t.Errorf("%s should not be a redirect parameter", name)
		}
	}
	if !fileParam("file", "") || !fileParam("x", "report.pdf") || !fileParam("Template", "a") || !fileParam("downloadId", "7") {
		t.Error("file-like parameters were not recognized")
	}
	if fileParam("q", "hello") || fileParam("id", "1.5") {
		t.Error("an ordinary parameter was treated as a file")
	}
	for _, p := range []string{"/logout", "/user/SignOut", "/items/delete", "/a/remove/3", "/session/destroy"} {
		if !logoutLike(p) {
			t.Errorf("%s should be skipped", p)
		}
	}
	if logoutLike("/login") || logoutLike("/items") {
		t.Error("ordinary paths were treated as logout-like")
	}
}
