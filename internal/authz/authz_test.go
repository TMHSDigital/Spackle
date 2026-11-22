package authz

import (
	"bytes"
	"errors"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

// grantFor obtains a grant through the config source, the simplest path
// through Gate.
func grantFor(t *testing.T, target string, s config.Scope) *Grant {
	t.Helper()
	g, err := Gate(mustURL(t, target), Options{Config: s, Yes: true})
	if err != nil {
		t.Fatalf("Gate(%s): %v", target, err)
	}
	return g
}

func writeScope(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func wantRefused(t *testing.T, err error, words ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("got nil error, want a refusal")
	}
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("error does not wrap ErrNotAuthorized: %v", err)
	}
	for _, w := range words {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not contain %q", err, w)
		}
	}
}

func TestPermitsHosts(t *testing.T) {
	tests := []struct {
		name   string
		hosts  []string
		target string // must be in scope, used to obtain the grant
		url    string
		ok     bool
	}{
		{"same host default port", []string{"example.test"}, "http://example.test/", "http://example.test/x", true},
		{"https default port", []string{"example.test"}, "http://example.test/", "https://example.test/x", true},
		{"explicit default port in url", []string{"example.test"}, "http://example.test/", "http://example.test:80/", true},
		{"https explicit 443", []string{"example.test"}, "http://example.test/", "https://example.test:443/", true},
		{"case-insensitive", []string{"Example.TEST"}, "http://example.test/", "http://EXAMPLE.test/", true},
		{"userinfo ignored", []string{"example.test"}, "http://example.test/", "http://user:pw@example.test/", true},
		{"redirect to another host", []string{"example.test"}, "http://example.test/", "http://evil.test/", false},
		{"userinfo does not spoof host", []string{"example.test"}, "http://example.test/", "http://example.test@evil.test/", false},
		{"no suffix matching", []string{"example.test"}, "http://example.test/", "http://sub.example.test/", false},
		{"no prefix matching", []string{"example.test"}, "http://example.test/", "http://example.test.evil.test/", false},
		{"trailing dot is another host", []string{"example.test"}, "http://example.test/", "http://example.test./", false},
		{"portless scope refuses other port", []string{"example.test"}, "http://example.test/", "http://example.test:8080/", false},
		{"portless scope refuses https on 80", []string{"example.test"}, "http://example.test/", "https://example.test:80/", false},
		{"port scope matches port", []string{"example.test:8443"}, "https://example.test:8443/", "http://example.test:8443/", true},
		{"port scope refuses default port", []string{"example.test:8443"}, "https://example.test:8443/", "https://example.test/", false},
		{"port scope refuses other port", []string{"example.test:8443"}, "https://example.test:8443/", "https://example.test:8444/", false},
		{"explicit 80 matches portless http", []string{"example.test:80"}, "http://example.test/", "http://example.test/", true},
		{"explicit 80 refuses portless https", []string{"example.test:80"}, "http://example.test/", "https://example.test/", false},
		{"localhost is not 127.0.0.1", []string{"localhost:8081"}, "http://localhost:8081/", "http://127.0.0.1:8081/", false},
		{"localhost is not ::1", []string{"localhost:8081"}, "http://localhost:8081/", "http://[::1]:8081/", false},
		{"127.0.0.1 is not localhost", []string{"127.0.0.1"}, "http://127.0.0.1/", "http://localhost/", false},
		{"ipv6 default port", []string{"[::1]"}, "http://[::1]/", "http://[::1]/x", true},
		{"ipv6 with port", []string{"[::1]:8080"}, "http://[::1]:8080/", "http://[::1]:8080/x", true},
		{"ipv6 long form is the same address", []string{"[::1]:8080"}, "http://[::1]:8080/", "http://[0:0:0:0:0:0:0:1]:8080/", true},
		{"ipv6 port mismatch", []string{"[::1]:8080"}, "http://[::1]:8080/", "http://[::1]/", false},
		{"other ipv6", []string{"[::1]"}, "http://[::1]/", "http://[::2]/", false},
		{"ipv4-mapped is not ipv4", []string{"127.0.0.1"}, "http://127.0.0.1/", "http://[::ffff:127.0.0.1]/", false},
		{"empty host", []string{"example.test"}, "http://example.test/", "http:///x", false},
		{"ftp scheme", []string{"example.test"}, "http://example.test/", "ftp://example.test/", false},
		{"file scheme", []string{"example.test"}, "http://example.test/", "file:///etc/passwd", false},
		{"no scheme", []string{"example.test"}, "http://example.test/", "//example.test/", false},
		{"opaque", []string{"example.test"}, "http://example.test/", "http:example.test", false},
		{"second host listed", []string{"a.test", "b.test:9000"}, "http://a.test/", "http://b.test:9000/", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := grantFor(t, tc.target, config.Scope{Hosts: tc.hosts})
			err := g.Permits(mustURL(t, tc.url), "GET")
			if tc.ok && err != nil {
				t.Fatalf("Permits(%s) = %v, want nil", tc.url, err)
			}
			if !tc.ok {
				wantRefused(t, err)
			}
		})
	}
}

func TestPermitsNamesLoopbackAliasing(t *testing.T) {
	g := grantFor(t, "http://localhost:8081/", config.Scope{Hosts: []string{"localhost:8081"}})
	err := g.Permits(mustURL(t, "http://127.0.0.1:8081/"), "GET")
	wantRefused(t, err, "127.0.0.1", "localhost", "[::1]", "different hosts")

	// No note when the target is not a loopback name.
	err = g.Permits(mustURL(t, "http://evil.test/"), "GET")
	wantRefused(t, err, "evil.test", "localhost:8081")
	if strings.Contains(err.Error(), "different hosts") {
		t.Errorf("unexpected loopback note: %v", err)
	}
}

func TestPermitsPaths(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		path     string
		ok       bool
	}{
		{"default prefix root", nil, "/anything/at/all", true},
		{"default prefix empty path", nil, "", true},
		{"prefix itself", []string{"/api"}, "/api", true},
		{"prefix with slash", []string{"/api"}, "/api/", true},
		{"under prefix", []string{"/api"}, "/api/v1/users", true},
		{"query is ignored", []string{"/api"}, "/api/v1?next=/admin", true},
		{"prefix boundary", []string{"/api"}, "/apiv2", false},
		{"outside prefix", []string{"/api"}, "/admin", false},
		{"root outside prefix", []string{"/api"}, "/", false},
		{"empty path outside prefix", []string{"/api"}, "", false},
		{"case matters", []string{"/api"}, "/API/x", false},
		{"traversal", []string{"/api"}, "/api/../admin", false},
		{"traversal staying inside", []string{"/api"}, "/api/v1/../v2", true},
		{"encoded traversal", []string{"/api"}, "/api/%2e%2e/admin", false},
		{"encoded traversal upper", []string{"/api"}, "/api/%2E%2E/admin", false},
		{"encoded slash", []string{"/api"}, "/api%2f..%2fadmin", false},
		{"encoded slash under root", []string{"/"}, "/api%2Fx", false},
		{"encoded backslash", []string{"/"}, "/api%5c..%5cadmin", false},
		{"double encoded dot", []string{"/"}, "/api/%252e%252e/admin", false},
		{"double encoded slash", []string{"/"}, "/api%252fadmin", false},
		{"dot segment", []string{"/api"}, "/api/./x", true},
		{"double slash", []string{"/api"}, "//api//x", true},
		{"trailing slash prefix", []string{"/api/"}, "/api/x", true},
		{"trailing slash prefix boundary", []string{"/api/"}, "/apiv2", false},
		{"second prefix", []string{"/api", "/health"}, "/health", true},
		{"traversal under root is cleaned", []string{"/"}, "/a/../b", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			first := "/"
			if len(tc.prefixes) > 0 {
				first = tc.prefixes[0]
			}
			g := grantFor(t, "http://example.test"+first, config.Scope{Hosts: []string{"example.test"}, PathPrefixes: tc.prefixes})
			err := g.Permits(mustURL(t, "http://example.test"+tc.path), "GET")
			if tc.ok && err != nil {
				t.Fatalf("Permits(%s) = %v, want nil", tc.path, err)
			}
			if !tc.ok {
				wantRefused(t, err)
			}
		})
	}
}

func TestPermitsLiteralBackslash(t *testing.T) {
	g := grantFor(t, "http://example.test/", config.Scope{Hosts: []string{"example.test"}})
	u := &url.URL{Scheme: "http", Host: "example.test", Path: `/api\..\admin`}
	wantRefused(t, g.Permits(u, "GET"), "backslash")
}

func TestPermitsMethods(t *testing.T) {
	tests := []struct {
		method string
		safe   bool // allowed without the flag
		unsafe bool // allowed with the flag
	}{
		{"GET", true, true}, {"HEAD", true, true}, {"OPTIONS", true, true},
		{"POST", false, true}, {"PUT", false, true}, {"PATCH", false, true}, {"DELETE", false, true},
		{"TRACE", false, false}, {"CONNECT", false, false}, {"PROPFIND", false, false},
		{"get", false, false}, {"", false, false}, {"GET ", false, false},
	}
	u := mustURL(t, "http://example.test/")
	for _, tc := range tests {
		t.Run("method "+tc.method, func(t *testing.T) {
			for _, allow := range []bool{false, true} {
				g := grantFor(t, "http://example.test/", config.Scope{Hosts: []string{"example.test"}, AllowUnsafeMethods: allow})
				want := tc.safe
				if allow {
					want = tc.unsafe
				}
				err := g.Permits(u, tc.method)
				if want && err != nil {
					t.Errorf("allow=%v: Permits = %v, want nil", allow, err)
				}
				if !want {
					wantRefused(t, err)
				}
			}
		})
	}
	g := grantFor(t, "http://example.test/", config.Scope{Hosts: []string{"example.test"}})
	wantRefused(t, g.Permits(u, "POST"), "allow_unsafe_methods")
}

func TestZeroAndNilGrant(t *testing.T) {
	u := mustURL(t, "http://localhost/")
	var nilGrant *Grant
	for name, g := range map[string]*Grant{"nil": nilGrant, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			wantRefused(t, g.Permits(u, "GET"), "--authorize")
			if s := g.Scope(); len(s.Hosts) != 0 || s.AllowUnsafeMethods || s.MaxRequests != 0 {
				t.Errorf("Scope() = %+v, want empty", s)
			}
			if g.Source() != "" || g.Statement() != "" {
				t.Errorf("Source/Statement not empty: %q %q", g.Source(), g.Statement())
			}
			if g.Summary() == "" {
				t.Error("Summary() is empty")
			}
		})
	}
}

func TestGrantCopyAndScopeCopy(t *testing.T) {
	g := grantFor(t, "http://example.test/api", config.Scope{Hosts: []string{"example.test"}, PathPrefixes: []string{"/api"}})
	cp := *g
	if err := cp.Permits(mustURL(t, "http://example.test/api/x"), "GET"); err != nil {
		t.Fatalf("copy refuses an in-scope request: %v", err)
	}
	wantRefused(t, cp.Permits(mustURL(t, "http://evil.test/api"), "GET"))
	wantRefused(t, cp.Permits(mustURL(t, "http://example.test/admin"), "GET"))
	wantRefused(t, cp.Permits(mustURL(t, "http://example.test/api"), "POST"))

	// Mutating what Scope returns must not widen the grant.
	s := g.Scope()
	s.Hosts[0] = "evil.test"
	s.PathPrefixes[0] = "/"
	s.AllowUnsafeMethods = true
	wantRefused(t, g.Permits(mustURL(t, "http://evil.test/api"), "GET"))
	wantRefused(t, g.Permits(mustURL(t, "http://example.test/admin"), "GET"))
	if got := g.Scope().Hosts[0]; got != "example.test" {
		t.Errorf("Scope().Hosts[0] = %q after mutation of a copy", got)
	}
}

func TestGateDoesNotAliasCallerScope(t *testing.T) {
	s := config.Scope{Hosts: []string{"example.test"}, PathPrefixes: []string{"/api"}}
	g := grantFor(t, "http://example.test/api", s)
	s.Hosts[0] = "evil.test"
	s.PathPrefixes[0] = "/"
	wantRefused(t, g.Permits(mustURL(t, "http://evil.test/api"), "GET"))
	wantRefused(t, g.Permits(mustURL(t, "http://example.test/admin"), "GET"))
}

func TestScopeHostValidation(t *testing.T) {
	bad := []string{
		"", " ", "http://example.test", "example.test/", "example.test/api", "*.example.test", "*",
		"exa mple.test", "example.test ", "\texample.test", "user@example.test", "user:pw@example.test:80",
		"example.test:", ":8080", "example.test:0", "example.test:65536", "example.test:http", "example.test:-1",
		"::1", "[::1", "[::1]x", "[::1]:", "[127.0.0.1]", "[nope]", "a:b:c", `example.test\x`, "ex%61mple.test",
		"example.test?x", "example.test#x",
	}
	for _, h := range bad {
		t.Run("bad "+h, func(t *testing.T) {
			_, err := Gate(mustURL(t, "http://example.test/"), Options{Config: config.Scope{Hosts: []string{"example.test", h}}, Yes: true})
			wantRefused(t, err, "localhost:8081")
		})
	}
	good := map[string]string{
		"example.test": "http://example.test/", "EXAMPLE.test:8080": "http://example.test:8080/",
		"127.0.0.1:9": "http://127.0.0.1:9/", "[::1]": "http://[::1]/", "[::1]:65535": "http://[::1]:65535/",
		"my_host-1": "http://my_host-1/", "example.test:0443": "https://example.test/",
	}
	for h, target := range good {
		t.Run("good "+h, func(t *testing.T) {
			grantFor(t, target, config.Scope{Hosts: []string{h}})
		})
	}
}

func TestScopePrefixValidation(t *testing.T) {
	for _, p := range []string{"api", "", "/api/../admin", `/api\x`, ".."} {
		t.Run("prefix "+p, func(t *testing.T) {
			_, err := Gate(mustURL(t, "http://example.test/"), Options{Config: config.Scope{Hosts: []string{"example.test"}, PathPrefixes: []string{p}}, Yes: true})
			wantRefused(t, err, "prefix")
		})
	}
}

func TestCaps(t *testing.T) {
	tests := []struct {
		name    string
		max     int
		rps     float64
		wantMax int
		wantRPS float64
	}{
		{"defaults", 0, 0, 400, 5},
		{"negative", -1, -3, 400, 5},
		{"kept", 50, 2.5, 50, 2.5},
		{"rps capped", 1000, 500, 1000, 50},
		{"rps at cap", 1, 50, 1, 50},
		{"nan", 0, math.NaN(), 400, 5},
		{"inf", 0, math.Inf(1), 400, 50},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := grantFor(t, "http://example.test/", config.Scope{Hosts: []string{"example.test"}, MaxRequests: tc.max, RequestsPerSecond: tc.rps})
			s := g.Scope()
			if s.MaxRequests != tc.wantMax || s.RequestsPerSecond != tc.wantRPS {
				t.Errorf("caps = %d, %v; want %d, %v", s.MaxRequests, s.RequestsPerSecond, tc.wantMax, tc.wantRPS)
			}
		})
	}
}

func TestGateNoScope(t *testing.T) {
	loop := mustURL(t, "http://127.0.0.1:8081/")
	tests := []struct {
		name string
		opts Options
		word string
	}{
		{"yes mode", Options{Yes: true, Interactive: true, Stdin: strings.NewReader("127.0.0.1:8081\n")}, "--yes"},
		{"not interactive", Options{Stdin: strings.NewReader("127.0.0.1:8081\n")}, "not a terminal"},
		{"interactive without streams", Options{Interactive: true}, "127.0.0.1:8081"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if tc.opts.Stdin != nil {
				tc.opts.Stderr = &stderr
			}
			g, err := Gate(loop, tc.opts)
			wantRefused(t, err, "--authorize <scope-file>", "[scope]", "spackle.toml", tc.word)
			if g != nil {
				t.Error("got a grant with the refusal")
			}
			if stderr.Len() != 0 {
				t.Errorf("prompted when it must not: %q", stderr.String())
			}
		})
	}
}

func TestGateRejectsBadTargets(t *testing.T) {
	opts := Options{Config: config.Scope{Hosts: []string{"example.test"}}, Yes: true}
	_, err := Gate(nil, opts)
	wantRefused(t, err)
	_, err = Gate(mustURL(t, "ftp://example.test/"), opts)
	wantRefused(t, err, "ftp", "http")
	_, err = Gate(mustURL(t, "http:///x"), opts)
	wantRefused(t, err, "host")
	_, err = Gate(mustURL(t, "http://example.test/"), Options{Config: config.Scope{Hosts: []string{"example.test"}, PathPrefixes: []string{"/api"}}, Yes: true})
	wantRefused(t, err, "/api")
}

func TestGateInteractive(t *testing.T) {
	tests := []struct {
		name   string
		target string
		input  string
		ok     bool
	}{
		{"exact host with port", "http://localhost:8081/app", "localhost:8081\n", true},
		{"crlf", "http://localhost:8081/", "localhost:8081\r\n", true},
		{"trimmed and case-insensitive", "http://localhost:8081/", "  LOCALHOST:8081 \n", true},
		{"no trailing newline", "http://localhost:8081/", "localhost:8081", true},
		{"default port omitted", "https://example.test/", "example.test\n", true},
		{"ipv6", "http://[::1]:8080/", "[::1]:8080\n", true},
		{"y", "http://localhost:8081/", "y\n", false},
		{"yes", "http://localhost:8081/", "yes\n", false},
		{"empty line", "http://localhost:8081/", "\n", false},
		{"eof", "http://localhost:8081/", "", false},
		{"wrong host", "http://localhost:8081/", "127.0.0.1:8081\n", false},
		{"host without port", "http://localhost:8081/", "localhost\n", false},
		{"wrong port", "http://localhost:8081/", "localhost:8080\n", false},
		{"full url", "http://localhost:8081/", "http://localhost:8081/\n", false},
		{"match only on second line", "http://localhost:8081/", "no\nlocalhost:8081\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			target := mustURL(t, tc.target)
			g, err := Gate(target, Options{
				Interactive: true, Stdin: strings.NewReader(tc.input), Stderr: &stderr,
				Config: config.Scope{MaxRequests: 25, RequestsPerSecond: 2, AllowUnsafeMethods: true, PathPrefixes: []string{"/app"}, Statement: "ignored"},
			})
			if !strings.Contains(stderr.String(), "Only test systems you own or have written permission to test.") {
				t.Errorf("notice missing from stderr: %q", stderr.String())
			}
			if !tc.ok {
				wantRefused(t, err, "--authorize")
				if g != nil {
					t.Error("got a grant with the refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("Gate: %v", err)
			}
			want := strings.ToLower(strings.TrimSpace(tc.input))
			if !strings.Contains(stderr.String(), "Spackle will send requests to "+want+".") {
				t.Errorf("notice does not name %s: %q", want, stderr.String())
			}
			s := g.Scope()
			if len(s.Hosts) != 1 || s.Hosts[0] != want {
				t.Errorf("hosts = %v, want [%s]", s.Hosts, want)
			}
			if len(s.PathPrefixes) != 1 || s.PathPrefixes[0] != "/" {
				t.Errorf("prefixes = %v, want [/]", s.PathPrefixes)
			}
			if s.AllowUnsafeMethods {
				t.Error("an interactive grant must be safe methods only")
			}
			if s.MaxRequests != 25 || s.RequestsPerSecond != 2 {
				t.Errorf("caps = %d, %v; want 25, 2 from config", s.MaxRequests, s.RequestsPerSecond)
			}
			if g.Source() != "interactive" || g.Statement() != "" {
				t.Errorf("source %q statement %q", g.Source(), g.Statement())
			}
			wantRefused(t, g.Permits(target, "POST"))
			wantRefused(t, g.Permits(mustURL(t, "http://other.test/"), "GET"))
		})
	}
}

func TestGateInteractiveLeavesRestOfStdin(t *testing.T) {
	in := strings.NewReader("localhost\nnext answer\n")
	if _, err := Gate(mustURL(t, "http://localhost/"), Options{Interactive: true, Stdin: in, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	rest := make([]byte, 64)
	n, _ := in.Read(rest)
	if string(rest[:n]) != "next answer\n" {
		t.Errorf("rest of stdin = %q, want the second line untouched", rest[:n])
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("broken") }

func TestGateInteractiveIOFailures(t *testing.T) {
	u := mustURL(t, "http://localhost/")
	_, err := Gate(u, Options{Interactive: true, Stdin: strings.NewReader("localhost\n"), Stderr: failWriter{}})
	wantRefused(t, err, "notice", "--authorize")
	_, err = Gate(u, Options{Interactive: true, Stdin: failReader{}, Stderr: &bytes.Buffer{}})
	wantRefused(t, err, "broken", "--authorize")
	// A stream with no newline cannot be read without bound.
	_, err = Gate(u, Options{Interactive: true, Stdin: strings.NewReader(strings.Repeat("a", 1<<16)), Stderr: &bytes.Buffer{}})
	wantRefused(t, err)
}

func TestGatePrecedence(t *testing.T) {
	file := writeScope(t, "hosts = [\"file.test\"]\n")
	cfg := config.Scope{Hosts: []string{"config.test"}}
	prompt := func() Options {
		return Options{Interactive: true, Stdin: strings.NewReader("config.test\n"), Stderr: &bytes.Buffer{}}
	}

	// The scope file wins over config.
	o := prompt()
	o.ScopeFile, o.Config = file, cfg
	g, err := Gate(mustURL(t, "http://file.test/"), o)
	if err != nil {
		t.Fatal(err)
	}
	if g.Source() != "scope-file" {
		t.Errorf("source = %q, want scope-file", g.Source())
	}

	// A scope file that does not list the target is an error naming both,
	// with no fall through to config or to the prompt.
	o = prompt()
	o.ScopeFile, o.Config = file, cfg
	stderr := o.Stderr.(*bytes.Buffer)
	_, err = Gate(mustURL(t, "http://config.test/"), o)
	wantRefused(t, err, "config.test", "file.test", "--authorize", filepath.ToSlash(file))
	if stderr.Len() != 0 {
		t.Errorf("prompted although a scope file was given: %q", stderr.String())
	}

	// Config wins over the prompt, and does not fall through either.
	o = prompt()
	o.Config = cfg
	stderr = o.Stderr.(*bytes.Buffer)
	g, err = Gate(mustURL(t, "http://config.test/"), o)
	if err != nil {
		t.Fatal(err)
	}
	if g.Source() != "config" || stderr.Len() != 0 {
		t.Errorf("source = %q, stderr = %q", g.Source(), stderr.String())
	}
	o = prompt()
	o.Config = cfg
	_, err = Gate(mustURL(t, "http://other.test/"), o)
	wantRefused(t, err, "other.test", "config.test")

	// A missing scope file is a refusal, not a reason to use config.
	o = prompt()
	o.ScopeFile, o.Config = filepath.Join(t.TempDir(), "absent.toml"), cfg
	_, err = Gate(mustURL(t, "http://config.test/"), o)
	wantRefused(t, err, "absent.toml", "--authorize")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error does not wrap os.ErrNotExist: %v", err)
	}
}

func TestGateLoopbackStillNeedsScope(t *testing.T) {
	for _, target := range []string{"http://localhost/", "http://127.0.0.1:3000/", "http://[::1]:3000/"} {
		_, err := Gate(mustURL(t, target), Options{Yes: true})
		wantRefused(t, err, "--authorize")
	}
	file := writeScope(t, "hosts = [\"localhost:3000\"]\n")
	_, err := Gate(mustURL(t, "http://127.0.0.1:3000/"), Options{ScopeFile: file, Yes: true})
	wantRefused(t, err, "127.0.0.1:3000", "localhost:3000", "different hosts")
}

func TestLoadScopeFile(t *testing.T) {
	const keys = `hosts = ["localhost:8081", "Staging.Example.test"]
path_prefixes = ["/api/", "/health"]
allow_unsafe_methods = true
max_requests = 120
requests_per_second = 80.0
statement = "my own staging box"
`
	for name, body := range map[string]string{"top level": keys, "scope table": "[scope]\n" + keys} {
		t.Run(name, func(t *testing.T) {
			s, err := LoadScopeFile(writeScope(t, body))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(s.Hosts, ",") != "localhost:8081,staging.example.test" {
				t.Errorf("hosts = %v", s.Hosts)
			}
			if strings.Join(s.PathPrefixes, ",") != "/api,/health" {
				t.Errorf("prefixes = %v", s.PathPrefixes)
			}
			if !s.AllowUnsafeMethods || s.MaxRequests != 120 || s.RequestsPerSecond != 50 || s.Statement != "my own staging box" {
				t.Errorf("scope = %+v", s)
			}
		})
	}

	t.Run("defaults", func(t *testing.T) {
		s, err := LoadScopeFile(writeScope(t, "hosts = [\"localhost\"]\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(s.PathPrefixes, ",") != "/" || s.AllowUnsafeMethods || s.MaxRequests != 400 || s.RequestsPerSecond != 5 {
			t.Errorf("scope = %+v", s)
		}
	})

	bad := []struct {
		name, body, word string
	}{
		{"unknown top-level key", "hosts = [\"localhost\"]\nhost = \"x\"\n", "unknown keys: host"},
		{"unknown key in scope", "[scope]\nhosts = [\"localhost\"]\nallow_unsafe = true\n", "scope.allow_unsafe"},
		{"unknown table", "hosts = [\"localhost\"]\n[dast]\nallow_unsafe_methods = true\n", "dast"},
		{"both places", "hosts = [\"localhost\"]\n[scope]\nhosts = [\"other.test\"]\n", "both"},
		{"no hosts", "statement = \"mine\"\n", "no hosts"},
		{"empty hosts", "hosts = []\n", "no hosts"},
		{"empty file", "", "no hosts"},
		{"empty scope table", "[scope]\n", "no hosts"},
		{"wildcard host", "hosts = [\"*.example.test\"]\n", "wildcards"},
		{"url host", "hosts = [\"http://localhost:8081\"]\n", "scheme"},
		{"bad prefix", "hosts = [\"localhost\"]\npath_prefixes = [\"api\"]\n", "prefix"},
		{"wrong type", "hosts = \"localhost\"\n", "TOML"},
		{"not toml", "hosts = [\n", "TOML"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			file := writeScope(t, tc.body)
			_, err := LoadScopeFile(file)
			if err == nil || !strings.Contains(err.Error(), tc.word) || !strings.Contains(err.Error(), file) {
				t.Fatalf("err = %v, want one naming the file and containing %q", err, tc.word)
			}
			_, err = Gate(mustURL(t, "http://localhost/"), Options{ScopeFile: file, Yes: true})
			wantRefused(t, err, tc.word)
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadScopeFile(filepath.Join(t.TempDir(), "nope.toml"))
		if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "--authorize") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestGrantAccessors(t *testing.T) {
	file := writeScope(t, "hosts = [\"localhost:8081\"]\nstatement = \"I own this box\"\n")
	g, err := Gate(mustURL(t, "http://localhost:8081/"), Options{ScopeFile: file, Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if g.Source() != "scope-file" || g.Statement() != "I own this box" {
		t.Errorf("source %q statement %q", g.Source(), g.Statement())
	}
	want := "hosts localhost:8081; paths /; safe methods only; max 400 requests (scope-file " + filepath.ToSlash(file) + ")"
	if g.Summary() != want {
		t.Errorf("Summary() =\n %s\nwant\n %s", g.Summary(), want)
	}

	g = grantFor(t, "https://a.test/api", config.Scope{
		Hosts: []string{"a.test", "b.test:9000"}, PathPrefixes: []string{"/api", "/v2"}, AllowUnsafeMethods: true, MaxRequests: 10, Statement: "contract 12",
	})
	want = "hosts a.test, b.test:9000; paths /api, /v2; unsafe methods allowed; max 10 requests (config)"
	if g.Summary() != want {
		t.Errorf("Summary() =\n %s\nwant\n %s", g.Summary(), want)
	}
	if g.Source() != "config" || g.Statement() != "contract 12" {
		t.Errorf("source %q statement %q", g.Source(), g.Statement())
	}
	if strings.Contains(g.Summary(), "\n") {
		t.Error("Summary must be one line")
	}
}
