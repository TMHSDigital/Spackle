package dast

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/TMHSDigital/spackle/internal/authz"
)

// hostOf returns the host:port of a test server URL.
func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Host
}

// grantFor gates a scope file that lists the server's host:port. extra is
// appended to the scope file as further TOML lines.
func grantFor(t *testing.T, serverURL, extra string) *authz.Grant {
	t.Helper()
	file := filepath.Join(t.TempDir(), "scope.toml")
	body := fmt.Sprintf("hosts = [%q]\n%s\n", hostOf(t, serverURL), extra)
	if !strings.Contains(extra, "requests_per_second") {
		body += "requests_per_second = 50\n"
	}
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatalf("write scope file: %v", err)
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse %q: %v", serverURL, err)
	}
	g, err := authz.Gate(u, authz.Options{ScopeFile: file})
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	return g
}

func clientFor(t *testing.T, serverURL, extra string, opts ClientOptions) *Client {
	t.Helper()
	if opts.Sleep == nil {
		opts.Sleep = func(time.Duration) {}
	}
	c, err := NewClient(grantFor(t, serverURL, extra), opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// counter is a server that counts every request it receives.
func counter(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "other")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestNewClientNeedsGrant(t *testing.T) {
	if _, err := NewClient(nil, ClientOptions{}); err == nil {
		t.Fatal("NewClient(nil) returned no error")
	}
	if _, err := NewClient(&authz.Grant{}, ClientOptions{}); err == nil {
		t.Fatal("NewClient with a zero grant returned no error")
	}
}

func TestNewClientRefusesBadOperatorHeader(t *testing.T) {
	srv, _ := counter(t)
	_, err := NewClient(grantFor(t, srv.URL, ""), ClientOptions{Headers: map[string]string{"X-A": "a\r\nB: c"}})
	if err == nil {
		t.Fatal("operator header with CR LF was accepted")
	}
}

func TestDoOutOfScopeSendsNothing(t *testing.T) {
	in, inHits := counter(t)
	other, otherHits := counter(t)
	c := clientFor(t, in.URL, "", ClientOptions{})
	_, err := c.Do(context.Background(), "GET", other.URL+"/x", nil, nil)
	if !errors.Is(err, authz.ErrNotAuthorized) {
		t.Fatalf("err = %v, want ErrNotAuthorized", err)
	}
	if otherHits.Load() != 0 || inHits.Load() != 0 {
		t.Fatalf("requests were sent: other=%d in=%d", otherHits.Load(), inHits.Load())
	}
	if c.Requests() != 0 || len(c.Exchanges()) != 0 {
		t.Fatalf("a refused request was counted: %d requests, %d exchanges", c.Requests(), len(c.Exchanges()))
	}
}

func TestDoRefusesPathOutsidePrefix(t *testing.T) {
	in, hits := counter(t)
	c := clientFor(t, in.URL+"/api", `path_prefixes = ["/api"]`, ClientOptions{})
	if _, err := c.Do(context.Background(), "GET", in.URL+"/admin", nil, nil); !errors.Is(err, authz.ErrNotAuthorized) {
		t.Fatalf("err = %v, want ErrNotAuthorized", err)
	}
	if _, err := c.Do(context.Background(), "GET", in.URL+"/api/x", nil, nil); err != nil {
		t.Fatalf("in-prefix request failed: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
}

func TestRedirectOutOfScopeNotFollowed(t *testing.T) {
	other, otherHits := counter(t)
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/landing", http.StatusFound)
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "", ClientOptions{})
	ex, err := c.Do(context.Background(), "GET", in.URL+"/out", nil, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if ex.Status != http.StatusFound {
		t.Fatalf("status = %d, want 302", ex.Status)
	}
	if !strings.Contains(ex.Note, "out-of-scope host") || !strings.Contains(ex.Note, hostOf(t, other.URL)) {
		t.Fatalf("note = %q, want the refused host named", ex.Note)
	}
	if otherHits.Load() != 0 {
		t.Fatalf("the out-of-scope server saw %d requests", otherHits.Load())
	}
	if c.Requests() != 1 {
		t.Fatalf("requests = %d, want 1", c.Requests())
	}
}

// A client supplied by the caller must not be able to follow redirects on
// its own, whatever its CheckRedirect says.
func TestSuppliedClientCannotFollowRedirects(t *testing.T) {
	other, otherHits := counter(t)
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/landing", http.StatusFound)
	}))
	defer in.Close()
	permissive := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	c := clientFor(t, in.URL, "", ClientOptions{HTTP: permissive})
	if _, err := c.Do(context.Background(), "GET", in.URL+"/", nil, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if otherHits.Load() != 0 {
		t.Fatalf("the out-of-scope server saw %d requests", otherHits.Load())
	}
	if permissive.CheckRedirect == nil {
		t.Fatal("the caller's client was modified")
	}
}

func TestRedirectInScopeFollowed(t *testing.T) {
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			http.Redirect(w, r, "/b", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "landed on "+r.URL.Path)
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "", ClientOptions{})
	ex, err := c.Do(context.Background(), "GET", in.URL+"/a", nil, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if ex.Status != 200 || !strings.HasSuffix(ex.URL, "/b") || ex.RespBody != "landed on /b" {
		t.Fatalf("final exchange = %+v", ex)
	}
	all := c.Exchanges()
	if len(all) != 2 || all[0].ID != "X-0001" || all[1].ID != "X-0002" || ex.ID != "X-0002" {
		t.Fatalf("exchanges = %+v", all)
	}
	if all[0].Status != http.StatusFound {
		t.Fatalf("first hop status = %d", all[0].Status)
	}
	if c.Requests() != 2 {
		t.Fatalf("requests = %d, want 2 (every hop counts)", c.Requests())
	}
	got, ok := c.Exchange("X-0001")
	if !ok || got.ID != "X-0001" {
		t.Fatalf("Exchange(X-0001) = %+v, %v", got, ok)
	}
	if _, ok := c.Exchange("X-9999"); ok {
		t.Fatal("Exchange found an id that was never issued")
	}
}

func TestRedirectHopLimit(t *testing.T) {
	var hits atomic.Int64
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		http.Redirect(w, r, fmt.Sprintf("/loop%d", n), http.StatusFound)
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "", ClientOptions{})
	ex, err := c.Do(context.Background(), "GET", in.URL+"/loop0", nil, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if hits.Load() != 6 {
		t.Fatalf("hits = %d, want 6 (the request and 5 hops)", hits.Load())
	}
	if !strings.Contains(ex.Note, "5") {
		t.Fatalf("note = %q, want the hop limit", ex.Note)
	}
}

func TestRedirectDoesNotRepeatPost(t *testing.T) {
	var posts, gets atomic.Int64
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
			status := http.StatusSeeOther
			if r.URL.Path == "/keep" {
				status = http.StatusTemporaryRedirect
			}
			http.Redirect(w, r, "/done", status)
			return
		}
		gets.Add(1)
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "allow_unsafe_methods = true", ClientOptions{})
	ex, err := c.Do(context.Background(), "POST", in.URL+"/submit", nil, []byte("a=1"))
	if err != nil || ex.Method != http.MethodGet || ex.Status != 200 {
		t.Fatalf("303 after POST: ex = %+v, err = %v", ex, err)
	}
	ex, err = c.Do(context.Background(), "POST", in.URL+"/keep", nil, []byte("a=1"))
	if err != nil || ex.Status != http.StatusTemporaryRedirect || ex.Note == "" {
		t.Fatalf("307 after POST: ex = %+v, err = %v", ex, err)
	}
	if posts.Load() != 2 || gets.Load() != 1 {
		t.Fatalf("posts = %d, gets = %d; a redirect must never repeat a POST", posts.Load(), gets.Load())
	}
}

func TestPostNeedsUnsafeMethods(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int64
	in := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		body.Store(r.Method + " " + string(b))
	}))
	defer in.Close()

	safe := clientFor(t, in.URL, "", ClientOptions{})
	if _, err := safe.Do(context.Background(), "POST", in.URL+"/", nil, []byte("a=1")); !errors.Is(err, authz.ErrNotAuthorized) {
		t.Fatalf("err = %v, want ErrNotAuthorized", err)
	}
	if _, err := safe.Do(context.Background(), "get", in.URL+"/", nil, nil); !errors.Is(err, authz.ErrNotAuthorized) {
		t.Fatalf("lower-case method: err = %v, want ErrNotAuthorized", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("a refused request reached the server (%d hits)", hits.Load())
	}

	unsafe := clientFor(t, in.URL, "allow_unsafe_methods = true", ClientOptions{})
	ex, err := unsafe.Do(context.Background(), "POST", in.URL+"/", nil, []byte("a=1"))
	if err != nil {
		t.Fatalf("POST with unsafe methods allowed: %v", err)
	}
	if body.Load() != "POST a=1" || ex.ReqBody != "a=1" {
		t.Fatalf("server saw %v, exchange body %q", body.Load(), ex.ReqBody)
	}
}

func TestRequestCap(t *testing.T) {
	in, hits := counter(t)
	c := clientFor(t, in.URL, "max_requests = 2", ClientOptions{})
	for i := 0; i < 2; i++ {
		if _, err := c.Do(context.Background(), "GET", in.URL+"/", nil, nil); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Do(context.Background(), "GET", in.URL+"/", nil, nil); !errors.Is(err, ErrRequestCap) {
			t.Fatalf("err = %v, want ErrRequestCap", err)
		}
	}
	if hits.Load() != 2 || c.Requests() != 2 || len(c.Exchanges()) != 2 {
		t.Fatalf("hits = %d, requests = %d, exchanges = %d; want 2 each", hits.Load(), c.Requests(), len(c.Exchanges()))
	}
}

func TestRequestCapStopsRedirectChain(t *testing.T) {
	var hits atomic.Int64
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "max_requests = 2", ClientOptions{})
	ex, err := c.Do(context.Background(), "GET", in.URL+"/", nil, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if hits.Load() != 2 || !strings.Contains(ex.Note, "cap") {
		t.Fatalf("hits = %d, note = %q", hits.Load(), ex.Note)
	}
}

func TestRateLimitSleeps(t *testing.T) {
	in, _ := counter(t)
	var mu sync.Mutex
	var slept []time.Duration
	c := clientFor(t, in.URL, "requests_per_second = 1", ClientOptions{Sleep: func(d time.Duration) {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
	}})
	for i := 0; i < 3; i++ {
		if _, err := c.Do(context.Background(), "GET", in.URL+"/", nil, nil); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(slept) != 2 {
		t.Fatalf("Sleep was called %d times, want 2 (between 3 requests)", len(slept))
	}
	for _, d := range slept {
		if d <= 0 || d > time.Second {
			t.Fatalf("slept %v, want a wait of at most one second", d)
		}
	}
}

func TestHeaderInjectionRefused(t *testing.T) {
	in, hits := counter(t)
	c := clientFor(t, in.URL, "", ClientOptions{})
	bad := []map[string]string{
		{"X-A": "a\r\nInjected: 1"},
		{"X-A": "a\nb"},
		{"X-A\r\nInjected": "1"},
		{"": "empty name"},
		{"Bad Name": "1"},
	}
	for _, h := range bad {
		if _, err := c.Do(context.Background(), "GET", in.URL+"/", h, nil); err == nil {
			t.Fatalf("headers %q were accepted", h)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("hits = %d, want 0", hits.Load())
	}
}

func TestHopByHopHeadersDropped(t *testing.T) {
	var seen atomic.Value
	in := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		h := r.Header.Clone()
		h.Set("Seen-Host", r.Host)
		seen.Store(h)
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "", ClientOptions{})
	ex, err := c.Do(context.Background(), "GET", in.URL+"/", map[string]string{
		"Host":                "evil.test",
		"host":                "evil2.test",
		"Content-Length":      "999",
		"Transfer-Encoding":   "chunked",
		"Connection":          "upgrade",
		"Upgrade":             "websocket",
		"Proxy-Authorization": "Basic abc",
		"User-Agent":          "not-spackle",
		"X-Keep":              "1",
	}, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	h, _ := seen.Load().(http.Header)
	if h.Get("Seen-Host") != hostOf(t, in.URL) {
		t.Fatalf("server saw Host %q", h.Get("Seen-Host"))
	}
	if h.Get("X-Keep") != "1" {
		t.Fatal("an ordinary header was dropped")
	}
	if h.Get("Upgrade") != "" || h.Get("Proxy-Authorization") != "" {
		t.Fatalf("hop-by-hop headers reached the server: %v", h)
	}
	if h.Get("User-Agent") != "spackle (authorized security testing)" {
		t.Fatalf("User-Agent = %q", h.Get("User-Agent"))
	}
	for name := range ex.ReqHeaders {
		switch strings.ToLower(name) {
		case "host", "content-length", "transfer-encoding", "connection", "upgrade", "proxy-authorization":
			t.Fatalf("exchange records dropped header %s", name)
		}
	}
	if ex.ReqHeaders["X-Keep"] != "1" {
		t.Fatalf("request headers = %v", ex.ReqHeaders)
	}
}

func TestExchangeRedaction(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	var auth atomic.Value
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization") + "|" + r.Header.Get("X-Operator"))
		w.Header().Add("Set-Cookie", "sessionid=topsecretvalue; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/")
		_, _ = io.WriteString(w, "key: "+secret+"\n")
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "allow_unsafe_methods = true", ClientOptions{Headers: map[string]string{"X-Operator": "yes"}})
	ex, err := c.Do(context.Background(), "POST", in.URL+"/", map[string]string{
		"Authorization": "Bearer abc.def.ghi",
		"Cookie":        "sessionid=topsecretvalue",
		"X-Api-Key":     "k-123456",
	}, []byte("note="+secret))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if auth.Load() != "Bearer abc.def.ghi|yes" {
		t.Fatalf("server saw %v; the real header values must be sent", auth.Load())
	}
	for _, name := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if ex.ReqHeaders[name] != "[redacted]" {
			t.Fatalf("%s recorded as %q", name, ex.ReqHeaders[name])
		}
	}
	sc := ex.RespHeaders["Set-Cookie"]
	if strings.Contains(sc, "topsecretvalue") || strings.Contains(sc, "dark") {
		t.Fatalf("Set-Cookie value recorded: %q", sc)
	}
	if !strings.Contains(sc, "sessionid=[redacted]") || !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "theme=[redacted]") {
		t.Fatalf("Set-Cookie = %q, want names and attributes kept", sc)
	}
	if strings.Contains(ex.RespBody, secret) || !strings.Contains(ex.RespBody, "[REDACTED:") {
		t.Fatalf("response body not redacted: %q", ex.RespBody)
	}
	if strings.Contains(ex.ReqBody, secret) {
		t.Fatalf("request body not redacted: %q", ex.ReqBody)
	}
	for _, stored := range c.Exchanges() {
		if strings.Contains(fmt.Sprintf("%+v", stored), "topsecretvalue") {
			t.Fatal("a stored exchange holds the cookie value")
		}
	}
}

func TestBodyCapsAndUTF8(t *testing.T) {
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = io.WriteString(w, strings.Repeat("a", 3<<20))
			return
		}
		_, _ = w.Write([]byte{'o', 'k', 0xff, 0xfe, '!'})
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "allow_unsafe_methods = true", ClientOptions{})
	ex, err := c.Do(context.Background(), "GET", in.URL+"/big", nil, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(ex.RespBody) > 64<<10 || len(ex.RespBody) < 60<<10 {
		t.Fatalf("response body recorded %d bytes, want it capped near 64 KiB", len(ex.RespBody))
	}
	ex, err = c.Do(context.Background(), "POST", in.URL+"/", nil, []byte(strings.Repeat("b", 40<<10)))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(ex.ReqBody) > 16<<10 {
		t.Fatalf("request body recorded %d bytes, want at most 16 KiB", len(ex.ReqBody))
	}
	if !utf8.ValidString(ex.RespBody) || !strings.HasPrefix(ex.RespBody, "ok") || !strings.HasSuffix(ex.RespBody, "!") {
		t.Fatalf("invalid UTF-8 was not replaced: %q", ex.RespBody)
	}
}

func TestOnRecordAndCopies(t *testing.T) {
	in, _ := counter(t)
	var got []string
	c := clientFor(t, in.URL, "", ClientOptions{OnRecord: func(e Exchange) { got = append(got, e.ID) }})
	for i := 0; i < 3; i++ {
		if _, err := c.Do(context.Background(), "GET", in.URL+"/", map[string]string{"X-N": "1"}, nil); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if strings.Join(got, ",") != "X-0001,X-0002,X-0003" {
		t.Fatalf("OnRecord saw %v", got)
	}
	all := c.Exchanges()
	all[0].ID = "changed"
	all[1].ReqHeaders["X-N"] = "changed"
	again := c.Exchanges()
	if again[0].ID != "X-0001" || again[1].ReqHeaders["X-N"] != "1" {
		t.Fatal("Exchanges returned memory shared with the client")
	}
}

func TestTransportErrorIsRecorded(t *testing.T) {
	in, _ := counter(t)
	c := clientFor(t, in.URL, "", ClientOptions{})
	target := in.URL
	in.Close()
	ex, err := c.Do(context.Background(), "GET", target+"/", nil, nil)
	if err == nil {
		t.Fatal("a request to a closed server returned no error")
	}
	if ex.Status != 0 || ex.Error == "" || ex.ID != "X-0001" {
		t.Fatalf("exchange = %+v", ex)
	}
}

func TestUserinfoIsNeverSent(t *testing.T) {
	var auth atomic.Value
	auth.Store("")
	in := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
	}))
	defer in.Close()
	c := clientFor(t, in.URL, "", ClientOptions{})
	ex, err := c.Do(context.Background(), "GET", "http://user:pw@"+hostOf(t, in.URL)+"/", nil, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if auth.Load() != "" || strings.Contains(ex.URL, "user") {
		t.Fatalf("userinfo was used: header %q, url %q", auth.Load(), ex.URL)
	}
}
