package dast

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func toolFor(t *testing.T, extra string) (*Client, *httptest.Server, func(args string) (string, error)) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Seen", r.Header.Get("X-Probe"))
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/long" {
			_, _ = io.WriteString(w, strings.Repeat("z", 9000))
			return
		}
		_, _ = io.WriteString(w, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	}))
	t.Cleanup(srv.Close)
	c := clientFor(t, srv.URL, extra, ClientOptions{})
	base, err := url.Parse(srv.URL + "/app/")
	if err != nil {
		t.Fatal(err)
	}
	tool := HTTPTool(c, base)
	return c, srv, func(args string) (string, error) {
		return tool.Run(context.Background(), json.RawMessage(args))
	}
}

func TestHTTPToolDef(t *testing.T) {
	c, srv, _ := toolFor(t, "")
	base, _ := url.Parse(srv.URL)
	def := HTTPTool(c, base).Def()
	if def.Name != "http_request" || def.Description == "" {
		t.Fatalf("def = %+v", def)
	}
	var schema map[string]any
	if err := json.Unmarshal(def.Schema, &schema); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	if schema["additionalProperties"] != false {
		t.Fatal("the schema must refuse unknown fields")
	}
}

func TestHTTPToolHappyPath(t *testing.T) {
	c, _, run := toolFor(t, "")
	out, err := run(`{"method": "GET", "url": "/path?x=1", "headers": {"X-Probe": "hello"}}`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, want := range []string{"X-0001", "HTTP 200 OK", "Content-Type: text/plain", "X-Seen: hello", "GET /path?x=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("result lacks %q:\n%s", want, out)
		}
	}
	if c.Requests() != 1 {
		t.Fatalf("requests = %d", c.Requests())
	}
}

func TestHTTPToolDefaultsToGet(t *testing.T) {
	_, _, run := toolFor(t, "")
	out, err := run(`{"url": "/only-url"}`)
	if err != nil || !strings.Contains(out, "GET /only-url") {
		t.Fatalf("out = %q, err = %v", out, err)
	}
}

func TestHTTPToolRelativeAndAbsolute(t *testing.T) {
	_, srv, run := toolFor(t, "")
	out, err := run(`{"url": "relative?y=2"}`)
	if err != nil || !strings.Contains(out, "GET /app/relative?y=2") {
		t.Fatalf("relative: out = %q, err = %v", out, err)
	}
	out, err = run(`{"url": "` + srv.URL + `/abs?z=3"}`)
	if err != nil || !strings.Contains(out, "GET /abs?z=3") {
		t.Fatalf("absolute: out = %q, err = %v", out, err)
	}
}

func TestHTTPToolOutOfScope(t *testing.T) {
	other, otherHits := counter(t)
	c, _, run := toolFor(t, "")
	for _, args := range []string{
		`{"url": "` + other.URL + `/x"}`,
		`{"url": "//` + hostOf(t, other.URL) + `/x"}`,
		`{"url": "file:///etc/passwd"}`,
	} {
		_, err := run(args)
		if err == nil {
			t.Fatalf("%s was not refused", args)
		}
		if !strings.Contains(err.Error(), "scope") && !strings.Contains(err.Error(), "refused") {
			t.Fatalf("error does not explain the scope rule: %v", err)
		}
	}
	if otherHits.Load() != 0 || c.Requests() != 0 {
		t.Fatalf("requests were sent: other=%d client=%d", otherHits.Load(), c.Requests())
	}
}

func TestHTTPToolDisallowedMethod(t *testing.T) {
	c, _, run := toolFor(t, "")
	_, err := run(`{"method": "POST", "url": "/x", "body": "a=1"}`)
	if err == nil || !strings.Contains(err.Error(), "allow_unsafe_methods") {
		t.Fatalf("err = %v, want the scope rule for unsafe methods", err)
	}
	if _, err := run(`{"method": "TRACE", "url": "/x"}`); err == nil {
		t.Fatal("TRACE was not refused")
	}
	if c.Requests() != 0 {
		t.Fatalf("requests = %d, want 0", c.Requests())
	}
}

func TestHTTPToolPostWhenAllowed(t *testing.T) {
	_, _, run := toolFor(t, "allow_unsafe_methods = true")
	out, err := run(`{"method": "POST", "url": "/x", "body": "a=1"}`)
	if err != nil || !strings.Contains(out, "POST /x a=1") {
		t.Fatalf("out = %q, err = %v", out, err)
	}
}

func TestHTTPToolBadArguments(t *testing.T) {
	c, _, run := toolFor(t, "")
	for _, args := range []string{
		`{"url": "/x", "follow": true}`,
		`{"method": "GET"}`,
		`{"url": 7}`,
		`not json`,
		`{"url": "/x"} {"url": "/y"}`,
	} {
		if _, err := run(args); err == nil {
			t.Fatalf("%s was accepted", args)
		}
	}
	if c.Requests() != 0 {
		t.Fatalf("requests = %d, want 0", c.Requests())
	}
}

func TestHTTPToolTruncatesBody(t *testing.T) {
	_, _, run := toolFor(t, "")
	out, err := run(`{"url": "/long"}`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := strings.Count(out, "z"); n != 6000 {
		t.Fatalf("body bytes shown = %d, want 6000", n)
	}
	if !strings.Contains(out, "truncated") {
		t.Fatal("the result does not say the body was cut")
	}
}

func TestHTTPToolRequestCap(t *testing.T) {
	_, _, run := toolFor(t, "max_requests = 1")
	if _, err := run(`{"url": "/a"}`); err != nil {
		t.Fatalf("first request: %v", err)
	}
	_, err := run(`{"url": "/b"}`)
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("err = %v, want the request cap explained", err)
	}
}

func TestHTTPToolWithoutClient(t *testing.T) {
	tool := HTTPTool(nil, nil)
	if _, err := tool.Run(context.Background(), json.RawMessage(`{"url": "/x"}`)); err == nil {
		t.Fatal("a tool with no client ran")
	}
}
