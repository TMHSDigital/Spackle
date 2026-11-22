// Package authz is the authorized-scope gate for live targets. Spackle may
// send traffic to a running application only when the operator has stated
// that they own it or are authorized to test it, and Gate is the only way to
// obtain the Grant that the live-request code requires. A gate cannot stop an
// operator who lies; it makes authorization explicit, recorded and bounded.
package authz

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/TMHSDigital/spackle/internal/config"
)

// ErrNotAuthorized is wrapped by every refusal from this package.
var ErrNotAuthorized = errors.New("not authorized")

// Grant sources.
const (
	sourceScopeFile   = "scope-file"
	sourceConfig      = "config"
	sourceInteractive = "interactive"
)

const howToAuthorize = "Pass --authorize <scope-file> or add a [scope] table with hosts to spackle.toml"

// Options control how authorization is obtained.
type Options struct {
	// ScopeFile is the path given with --authorize. Empty when not given.
	ScopeFile string
	// Config is the [scope] table from spackle.toml; its Hosts are empty when not configured.
	Config config.Scope
	// Yes is true for --yes and CI mode: never prompt.
	Yes bool
	// Interactive is true when stdin is a terminal a human can answer on.
	Interactive bool
	Stdin       io.Reader
	Stderr      io.Writer
}

// Grant is proof that a scope was authorized. The zero value permits nothing.
// Its fields are unexported: only Gate can make a usable one. A copy enforces
// the same scope as the original, since nothing in it is mutated after Gate.
type Grant struct {
	source string
	// detail is the scope file path for the summary.
	detail   string
	scope    config.Scope
	hosts    []hostPort
	prefixes []string
}

// Gate decides whether target may be tested. Precedence: ScopeFile, then
// Config, then an interactive confirmation. A source that is present but does
// not cover the target is a refusal: Gate never falls through to the next
// source, so a wrong scope file cannot be papered over by a prompt. It
// returns ErrNotAuthorized (wrapped) when authorization is missing or does
// not cover the target.
func Gate(target *url.URL, opts Options) (*Grant, error) {
	ep, err := endpointOf(target)
	if err != nil {
		return nil, err
	}
	g := &Grant{}
	var raw config.Scope
	switch {
	case opts.ScopeFile != "":
		g.source, g.detail = sourceScopeFile, filepath.ToSlash(opts.ScopeFile)
		raw, err = LoadScopeFile(opts.ScopeFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
		}
	case len(opts.Config.Hosts) > 0:
		g.source = sourceConfig
		raw = opts.Config
	case opts.Yes:
		return nil, fmt.Errorf("%w: %s is a live target and no scope was given; --yes and CI runs never prompt for one. %s", ErrNotAuthorized, ep, howToAuthorize)
	case !opts.Interactive:
		return nil, fmt.Errorf("%w: %s is a live target, no scope was given, and stdin is not a terminal (piped input is not consent). %s", ErrNotAuthorized, ep, howToAuthorize)
	default:
		if err := confirm(ep, opts); err != nil {
			return nil, err
		}
		g.source = sourceInteractive
		raw = config.Scope{
			Hosts:             []string{ep.String()},
			MaxRequests:       opts.Config.MaxRequests,
			RequestsPerSecond: opts.Config.RequestsPerSecond,
		}
	}
	g.scope, g.hosts, g.prefixes, err = normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: the scope from %s is not valid: %w", ErrNotAuthorized, g.origin(), err)
	}
	if err := g.Permits(target, "GET"); err != nil {
		return nil, fmt.Errorf("%w (the scope came from %s). Add the target to that scope if you are authorized to test it, or pass --authorize <scope-file> with a scope that covers it", err, g.origin())
	}
	return g, nil
}

// confirm asks the operator to type the exact host. A bare "y" is not
// accepted: typing the host shows the operator read which system is about
// to receive traffic.
func confirm(ep endpoint, opts Options) error {
	want := ep.String()
	if opts.Stdin == nil || opts.Stderr == nil {
		return fmt.Errorf("%w: cannot ask for confirmation to test %s because no terminal input or output is available. %s", ErrNotAuthorized, want, howToAuthorize)
	}
	_, err := fmt.Fprintf(opts.Stderr, "Spackle will send requests to %s. Only test systems you own or have written permission to test.\nType the host exactly as shown (%s) to confirm: ", want, want)
	if err != nil {
		return fmt.Errorf("%w: the notice for %s could not be shown (%w), so no consent can be taken. %s", ErrNotAuthorized, want, err, howToAuthorize)
	}
	line, err := readLine(opts.Stdin)
	if err != nil {
		return fmt.Errorf("%w: reading the confirmation for %s failed (%w). Run again and type the host, or use a scope: %s", ErrNotAuthorized, want, err, howToAuthorize)
	}
	if !strings.EqualFold(strings.TrimSpace(line), want) {
		return fmt.Errorf("%w: the confirmation did not match %q, and only the exact host confirms (not y or yes). Run again and type %s, or use a scope: %s", ErrNotAuthorized, want, want, howToAuthorize)
	}
	return nil
}

// readLine reads one line a byte at a time so nothing after the newline is
// consumed from the operator's terminal. The length cap keeps a stream with
// no newline from being read without bound.
func readLine(r io.Reader) (string, error) {
	const maxLine = 1024
	var line []byte
	buf := make([]byte, 1)
	idle := 0
	for len(line) < maxLine {
		n, err := r.Read(buf)
		if n > 0 {
			idle = 0
			if buf[0] == '\n' {
				break
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
		if n == 0 {
			if idle++; idle > 100 {
				return "", io.ErrNoProgress
			}
		}
	}
	return string(line), nil
}

func (g *Grant) origin() string {
	if g.source == sourceScopeFile {
		return "scope file " + g.detail
	}
	if g.source == sourceConfig {
		return "the [scope] table in the config"
	}
	return "the interactive confirmation"
}

func (g *Grant) usable() bool { return g != nil && g.source != "" && len(g.hosts) > 0 }

// Permits reports whether a request to u with the given method is inside the
// grant. Every refusal wraps ErrNotAuthorized. Call it for each request,
// including each redirect hop, since a redirect can leave the scope.
func (g *Grant) Permits(u *url.URL, method string) error {
	if !g.usable() {
		return fmt.Errorf("%w: there is no grant, so no live request may be sent. Obtain one from the scope gate. %s", ErrNotAuthorized, howToAuthorize)
	}
	ep, err := endpointOf(u)
	if err != nil {
		return err
	}
	switch method {
	case "GET", "HEAD", "OPTIONS":
	case "POST", "PUT", "PATCH", "DELETE":
		if !g.scope.AllowUnsafeMethods {
			return fmt.Errorf("%w: method %s is refused because it can change state and the scope allows safe methods only. Set allow_unsafe_methods = true in the scope if you are authorized to send it", ErrNotAuthorized, method)
		}
	default:
		return fmt.Errorf("%w: method %q is refused because only GET, HEAD, OPTIONS, POST, PUT, PATCH and DELETE (upper case) are ever sent. Use one of those", ErrNotAuthorized, method)
	}
	inScope := false
	for _, h := range g.hosts {
		if ep.matches(h) {
			inScope = true
			break
		}
	}
	if !inScope {
		// Name the effective port: a portless URL and a portless scope entry
		// can still differ by scheme default.
		return fmt.Errorf("%w: host %q (port %d) is not in the authorized scope, which lists %s; hosts match exactly, with no wildcards, aliases or DNS.%s Do not send this request", ErrNotAuthorized, ep.String(), ep.port, strings.Join(g.scope.Hosts, ", "), loopbackNote(ep.host, g.hosts))
	}
	p, err := requestPath(u)
	if err != nil {
		return err
	}
	if !underPrefix(p, g.prefixes) {
		return fmt.Errorf("%w: path %q on %s is outside the authorized path prefixes %s. Do not send this request, or widen path_prefixes in the scope if you are authorized", ErrNotAuthorized, p, ep.String(), strings.Join(g.prefixes, ", "))
	}
	return nil
}

// Scope returns a copy of the authorized scope. A nil or zero Grant returns
// the empty scope.
func (g *Grant) Scope() config.Scope {
	if !g.usable() {
		return config.Scope{}
	}
	s := g.scope
	s.Hosts = append([]string(nil), g.scope.Hosts...)
	s.PathPrefixes = append([]string(nil), g.scope.PathPrefixes...)
	return s
}

// Source is "scope-file", "config" or "interactive". It is empty for a nil
// or zero Grant.
func (g *Grant) Source() string {
	if !g.usable() {
		return ""
	}
	return g.source
}

// Summary is one line for the ledger and reports, e.g.
// "hosts localhost:8081; paths /; safe methods only; max 400 requests (scope-file ./scope.toml)".
func (g *Grant) Summary() string {
	if !g.usable() {
		return "no authorized scope"
	}
	methods := "safe methods only"
	if g.scope.AllowUnsafeMethods {
		methods = "unsafe methods allowed"
	}
	src := g.source
	if g.detail != "" {
		src += " " + g.detail
	}
	return fmt.Sprintf("hosts %s; paths %s; %s; max %d requests (%s)",
		strings.Join(g.scope.Hosts, ", "), strings.Join(g.scope.PathPrefixes, ", "), methods, g.scope.MaxRequests, src)
}

// Statement returns the operator's authorization statement, if any.
func (g *Grant) Statement() string {
	if !g.usable() {
		return ""
	}
	return g.scope.Statement
}
