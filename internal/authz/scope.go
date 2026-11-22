package authz

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"

	"github.com/TMHSDigital/spackle/internal/config"
)

// Caps applied to every grant. They bound the traffic a run can send even
// when the operator leaves the values out or sets them too high.
const (
	defaultMaxRequests       = 400
	defaultRequestsPerSecond = 5
	maxRequestsPerSecond     = 50
)

const hostForm = `use a plain host or host:port, for example "localhost:8081", "staging.example.test" or "[::1]:8080"`

// hostPort is one authorized host. Port 0 means "the default port of the
// request scheme", which is what a scope entry without a port stands for.
type hostPort struct {
	host string
	port int
}

func (h hostPort) String() string {
	s := h.host
	if strings.Contains(s, ":") {
		s = "[" + s + "]"
	}
	if h.port != 0 {
		s += ":" + strconv.Itoa(h.port)
	}
	return s
}

// scopeFile is the on-disk form: the keys either at the top level or under
// [scope], so a table copied from spackle.toml works unchanged.
type scopeFile struct {
	Hosts              []string      `toml:"hosts"`
	PathPrefixes       []string      `toml:"path_prefixes"`
	AllowUnsafeMethods bool          `toml:"allow_unsafe_methods"`
	MaxRequests        int           `toml:"max_requests"`
	RequestsPerSecond  float64       `toml:"requests_per_second"`
	Statement          string        `toml:"statement"`
	Scope              *config.Scope `toml:"scope"`
}

// LoadScopeFile reads a scope file (TOML). Keys may be at the top level or
// under [scope]: hosts, path_prefixes, allow_unsafe_methods, max_requests,
// requests_per_second, statement. Unknown keys are an error. The returned
// scope is validated and has its defaults and caps applied.
func LoadScopeFile(file string) (config.Scope, error) {
	raw, err := os.ReadFile(file) //nolint:gosec // the operator names their own scope file
	if err != nil {
		return config.Scope{}, fmt.Errorf("read scope file %s: %w. Pass --authorize with the path of a TOML file that lists the hosts you may test", file, err)
	}
	var f scopeFile
	md, err := toml.Decode(string(raw), &f)
	if err != nil {
		return config.Scope{}, fmt.Errorf("scope file %s is not valid TOML: %w. Fix the syntax; a minimal file is: hosts = [\"localhost:8081\"]", file, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return config.Scope{}, fmt.Errorf("scope file %s has unknown keys: %s. A misspelled key could silently widen or narrow the scope, so remove it or use one of hosts, path_prefixes, allow_unsafe_methods, max_requests, requests_per_second, statement", file, strings.Join(keys, ", "))
	}
	topLevel := false
	for _, k := range md.Keys() {
		if len(k) > 0 && k[0] != "scope" {
			topLevel = true
			break
		}
	}
	scope := config.Scope{
		Hosts: f.Hosts, PathPrefixes: f.PathPrefixes, AllowUnsafeMethods: f.AllowUnsafeMethods,
		MaxRequests: f.MaxRequests, RequestsPerSecond: f.RequestsPerSecond, Statement: f.Statement,
	}
	if f.Scope != nil {
		if topLevel {
			return config.Scope{}, fmt.Errorf("scope file %s sets keys both at the top level and under [scope], so it is unclear which apply. Keep all keys in one place", file)
		}
		scope = *f.Scope
	}
	norm, _, _, err := normalize(scope)
	if err != nil {
		return config.Scope{}, fmt.Errorf("scope file %s: %w", file, err)
	}
	return norm, nil
}

// normalize validates a scope and returns it with defaults and caps applied,
// along with the parsed hosts and cleaned prefixes used for matching.
func normalize(s config.Scope) (config.Scope, []hostPort, []string, error) {
	if len(s.Hosts) == 0 {
		return config.Scope{}, nil, nil, errors.New("the scope lists no hosts, and a scope with no hosts authorizes nothing. Add hosts, for example hosts = [\"localhost:8081\"]")
	}
	out := config.Scope{AllowUnsafeMethods: s.AllowUnsafeMethods, Statement: s.Statement}
	hosts := make([]hostPort, 0, len(s.Hosts))
	for _, raw := range s.Hosts {
		h, err := parseScopeHost(raw)
		if err != nil {
			return config.Scope{}, nil, nil, err
		}
		hosts = append(hosts, h)
		out.Hosts = append(out.Hosts, h.String())
	}
	prefixes := s.PathPrefixes
	if len(prefixes) == 0 {
		prefixes = []string{"/"}
	}
	for _, p := range prefixes {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, `\`) || hasDotDot(p) {
			return config.Scope{}, nil, nil, fmt.Errorf("scope path prefix %q is not usable: a prefix must start with / and contain no backslash or \"..\" segment. Use a form such as \"/\" or \"/api\"", p)
		}
		out.PathPrefixes = append(out.PathPrefixes, path.Clean(p))
	}
	out.MaxRequests = s.MaxRequests
	if out.MaxRequests <= 0 {
		out.MaxRequests = defaultMaxRequests
	}
	// The negated comparison also sends NaN to the default.
	out.RequestsPerSecond = s.RequestsPerSecond
	if !(out.RequestsPerSecond > 0) { //nolint:staticcheck // written this way so NaN takes the default
		out.RequestsPerSecond = defaultRequestsPerSecond
	}
	out.RequestsPerSecond = math.Min(out.RequestsPerSecond, maxRequestsPerSecond)
	return out, hosts, append([]string(nil), out.PathPrefixes...), nil
}

func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// parseScopeHost accepts only host or host:port. Anything that could widen
// the match (wildcards) or that suggests the operator pasted a URL is
// refused rather than interpreted, because a guess here decides where
// traffic may go.
func parseScopeHost(raw string) (hostPort, error) {
	bad := func(why string) (hostPort, error) {
		return hostPort{}, fmt.Errorf("scope host %q is not accepted: %s. %s", raw, why, hostForm)
	}
	switch {
	case raw == "":
		return bad("it is empty")
	case strings.Contains(raw, "://"):
		return bad("it contains a scheme")
	case strings.ContainsAny(raw, `/\`):
		return bad("it contains a slash")
	case strings.Contains(raw, "*"):
		return bad("wildcards are not supported, every host is listed exactly")
	case strings.Contains(raw, "@"):
		return bad("it contains userinfo")
	case strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return bad("it contains whitespace")
	}
	host, port := raw, ""
	if strings.HasPrefix(raw, "[") {
		end := strings.Index(raw, "]")
		if end < 0 {
			return bad("the IPv6 bracket is not closed")
		}
		addr, err := netip.ParseAddr(raw[1:end])
		if err != nil || !addr.Is6() {
			return bad("the brackets do not hold an IPv6 address")
		}
		host = addr.String()
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return bad("only :port may follow the bracket")
			}
			port = rest[1:]
			if port == "" {
				return bad("the port is empty")
			}
		}
	} else {
		switch strings.Count(raw, ":") {
		case 0:
		case 1:
			host, port, _ = strings.Cut(raw, ":")
			if port == "" {
				return bad("the port is empty")
			}
		default:
			return bad("an IPv6 address must be in brackets")
		}
		if host == "" {
			return bad("the host is empty")
		}
		for _, r := range host {
			if !isHostRune(r) {
				return bad("a host may hold only ASCII letters, digits, dots, hyphens and underscores (write international names in punycode)")
			}
		}
		host = strings.ToLower(host)
	}
	h := hostPort{host: host}
	if port != "" {
		n, ok := parsePort(port)
		if !ok {
			return bad("the port is not a number from 1 to 65535")
		}
		h.port = n
	}
	return h, nil
}

func isHostRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_'
}

func parsePort(s string) (int, bool) {
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// endpoint is the host and effective port of a request URL.
type endpoint struct {
	host        string
	port        int
	defaultPort int
}

// String is the form the operator types to confirm: the port appears only
// when it is not the scheme default.
func (e endpoint) String() string {
	h := hostPort{host: e.host}
	if e.port != e.defaultPort {
		h.port = e.port
	}
	return h.String()
}

func (e endpoint) matches(h hostPort) bool {
	if h.host != e.host {
		return false
	}
	if h.port == 0 {
		return e.port == e.defaultPort
	}
	return h.port == e.port
}

// endpointOf extracts the host and port to match. Userinfo is never looked
// at, so "http://allowed@evil.test/" is judged as evil.test.
func endpointOf(u *url.URL) (endpoint, error) {
	if u == nil {
		return endpoint{}, fmt.Errorf("%w: no URL was given, so there is nothing to check against the scope. Give a full http or https URL", ErrNotAuthorized)
	}
	var e endpoint
	switch strings.ToLower(u.Scheme) {
	case "http":
		e.defaultPort = 80
	case "https":
		e.defaultPort = 443
	default:
		return endpoint{}, fmt.Errorf("%w: scheme %q is refused because Spackle sends live requests over http and https only. Use an http or https URL", ErrNotAuthorized, u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || u.Opaque != "" {
		return endpoint{}, fmt.Errorf("%w: the URL has no host, and an empty host is never in scope. Give a full URL such as http://localhost:8081/", ErrNotAuthorized)
	}
	if strings.Contains(host, ":") {
		// Same address, same spelling: [0:0:0:0:0:0:0:1] and [::1] are one host.
		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.String()
		}
	}
	e.host = host
	e.port = e.defaultPort
	if p := u.Port(); p != "" {
		n, ok := parsePort(p)
		if !ok {
			return endpoint{}, fmt.Errorf("%w: port %q of host %q is not a number from 1 to 65535, so it cannot match a scope entry. Fix the URL", ErrNotAuthorized, p, host)
		}
		e.port = n
	}
	return e, nil
}

// requestPath returns the path to compare with the prefixes: decoded and
// cleaned, so "/api/../admin" is judged as "/admin". Encodings that a server
// may decode differently from us are refused outright, because we cannot
// know which path the server will act on.
func requestPath(u *url.URL) (string, error) {
	refuse := func(why string) (string, error) {
		return "", fmt.Errorf("%w: path %q is refused because %s, and a server may resolve it to a path outside the scope. Send the plain path instead", ErrNotAuthorized, u.EscapedPath(), why)
	}
	esc := strings.ToLower(u.EscapedPath())
	if strings.Contains(esc, "%2f") || strings.Contains(esc, "%5c") {
		return refuse("it holds an encoded slash or backslash")
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		return refuse("it does not start with /")
	}
	if strings.Contains(p, `\`) {
		return refuse("it holds a backslash")
	}
	// Still encoded after one decode means it was encoded twice.
	low := strings.ToLower(p)
	if strings.Contains(low, "%2e") || strings.Contains(low, "%2f") || strings.Contains(low, "%5c") {
		return refuse("it holds a doubly encoded dot, slash or backslash")
	}
	c := path.Clean(p)
	if hasDotDot(c) {
		return refuse("it still holds \"..\" after cleaning")
	}
	return c, nil
}

func underPrefix(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if pre == "/" || p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// loopbackNote explains the most common surprise: the three loopback names
// are not aliases here, because treating them as one would mean resolving
// names, and the scope is matched without DNS.
func loopbackNote(host string, hosts []hostPort) string {
	loop := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	if !loop[host] {
		return ""
	}
	for _, h := range hosts {
		if h.host != host && loop[h.host] {
			return " Note: localhost, 127.0.0.1 and [::1] are three different hosts to Spackle (no aliasing), so list the one the URL uses."
		}
	}
	return ""
}
