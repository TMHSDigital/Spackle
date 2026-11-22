// Package dast analyzes a running web application that the operator owns or
// is authorized to test. Every request goes through a Client, and a Client
// cannot exist without an authz.Grant: the grant decides which hosts, paths
// and methods may be contacted, how many requests a run may send and how
// fast. Responses are untrusted input. Nothing a target returns can widen
// the scope, raise a cap or change which probes exist.
package dast

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/TMHSDigital/spackle/internal/authz"
	"github.com/TMHSDigital/spackle/internal/redact"
)

// ErrRequestCap is returned when the scope's request cap has been used up.
var ErrRequestCap = errors.New("request cap reached")

const (
	defaultUserAgent = "spackle (authorized security testing)"
	masked           = "[redacted]"
	maxRedirectHops  = 5
	// maxRead bounds how much of a response is read at all, so a target
	// cannot exhaust memory with an endless body.
	maxRead        = 1 << 20
	maxReqStored   = 16 << 10
	maxRespStored  = 64 << 10
	defaultTimeout = 15 * time.Second
)

// Exchange is one recorded request and response.
type Exchange struct {
	ID          string            `json:"id"` // "X-0001", sequential per client
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	ReqHeaders  map[string]string `json:"request_headers,omitempty"`  // credential values replaced by "[redacted]"
	ReqBody     string            `json:"request_body,omitempty"`     // redacted, capped at 16 KiB
	Status      int               `json:"status"`                     // 0 when no response
	RespHeaders map[string]string `json:"response_headers,omitempty"` // Set-Cookie keeps attributes, not the value
	RespBody    string            `json:"response_body,omitempty"`    // redacted, capped at 64 KiB, valid UTF-8
	DurationMS  int64             `json:"duration_ms"`
	Note        string            `json:"note,omitempty"` // for example a redirect that was not followed
	Error       string            `json:"error,omitempty"`
}

// ClientOptions configure a Client.
type ClientOptions struct {
	// HTTP is the transport to use. Nil means a client with a 15 second
	// timeout. Redirect handling of a supplied client is replaced: the
	// Client follows redirects itself so every hop is checked.
	HTTP *http.Client
	// OnRecord is called once per exchange, in order. It must not call Do.
	OnRecord func(Exchange)
	// Sleep waits between requests for the rate limit. Nil means a wait
	// that ends early when the request context is cancelled.
	Sleep func(time.Duration)
	// UserAgent defaults to "spackle (authorized security testing)".
	UserAgent string
	// Headers are sent on every request (operator-supplied authentication).
	Headers map[string]string
}

// Client sends requests inside an authorized scope and records them.
type Client struct {
	grant       *authz.Grant
	http        *http.Client
	onRecord    func(Exchange)
	sleep       func(time.Duration)
	headers     map[string]string
	maxRequests int
	interval    time.Duration

	// sendMu serializes Do. The rate limit already means one request at a
	// time, and it keeps exchange ids in the order requests were sent.
	sendMu sync.Mutex

	mu        sync.Mutex
	exchanges []Exchange
	requests  int
	last      time.Time
}

// hop is one request and its response as the checks see it: the recorded
// exchange plus the unredacted headers and body, which are used for
// detection and never stored.
type hop struct {
	ex     Exchange
	url    *url.URL
	header http.Header
	body   []byte
}

// NewClient returns a client bound to a grant. A nil grant is an error: there is no way to
// build a client without authorization.
func NewClient(g *authz.Grant, opts ClientOptions) (*Client, error) {
	if g == nil || g.Source() == "" {
		return nil, fmt.Errorf("%w: a live-target client needs a grant from the scope gate and none was given. Pass --authorize <scope-file> or add a [scope] table with hosts to spackle.toml", authz.ErrNotAuthorized)
	}
	scope := g.Scope()
	if scope.MaxRequests <= 0 || !(scope.RequestsPerSecond > 0) { //nolint:staticcheck // written this way so NaN is refused too
		return nil, fmt.Errorf("%w: the grant has no request cap or rate limit, so no request may be sent. This is a Spackle bug: report it", authz.ErrNotAuthorized)
	}
	operator, err := cleanHeaders(opts.Headers)
	if err != nil {
		return nil, fmt.Errorf("the headers configured for every request are not usable: %w", err)
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	if strings.ContainsAny(ua, "\r\n\x00") {
		return nil, errors.New("the configured User-Agent contains a line break, which would let it inject headers. Use a single line of text")
	}
	headers := map[string]string{"User-Agent": ua}
	maps.Copy(headers, operator)

	hc := &http.Client{Timeout: defaultTimeout}
	if opts.HTTP != nil {
		// A copy, so the caller's client keeps its own redirect policy.
		cp := *opts.HTTP
		hc = &cp
	}
	// The transport must never follow a redirect by itself: a hop it took
	// would not have passed the scope check.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Client{
		grant:       g,
		http:        hc,
		onRecord:    opts.OnRecord,
		sleep:       opts.Sleep,
		headers:     headers,
		maxRequests: scope.MaxRequests,
		interval:    time.Duration(float64(time.Second) / scope.RequestsPerSecond),
	}, nil
}

// Do sends one request. The URL and method are checked with the grant before anything is sent;
// a refused request returns an error wrapping authz.ErrNotAuthorized and sends nothing.
// Redirects are followed manually, at most 5 hops, each hop re-checked against the scope;
// a hop that leaves scope is not followed and is recorded in Note. Every hop counts against
// the request cap and waits for the rate limit. The returned exchange is the last hop.
func (c *Client) Do(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (Exchange, error) {
	hops, err := c.roundTrips(ctx, method, rawURL, headers, body)
	if len(hops) == 0 {
		return Exchange{}, err
	}
	return cloneExchange(hops[len(hops)-1].ex), err
}

// roundTrips is Do that also returns every hop with its raw response.
func (c *Client) roundTrips(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) ([]hop, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("the URL %s could not be parsed, so nothing was sent. Give a full http or https URL", show(rawURL, 120))
	}
	u = sendable(u)
	if err := c.grant.Permits(u, method); err != nil {
		return nil, fmt.Errorf("the request was not sent: %w", err)
	}
	extra, err := cleanHeaders(headers)
	if err != nil {
		return nil, fmt.Errorf("the request was not sent: %w", err)
	}
	// The User-Agent says who is sending this traffic and why. It is the
	// operator's to set, not a caller's.
	delete(extra, "User-Agent")

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	var hops []hop
	for followed := 0; ; followed++ {
		h, err := c.send(ctx, method, u, extra, body)
		if errors.Is(err, ErrRequestCap) {
			return hops, err
		}
		next, nextMethod, note := c.nextHop(h, method, followed)
		if next != nil && c.atCap() {
			next, note = nil, "redirect not followed: the request cap was reached"
		}
		h.ex.Note = note
		c.record(&h)
		hops = append(hops, h)
		if err != nil || next == nil {
			return hops, err
		}
		if next.Host != u.Host {
			// Headers chosen for one host are not replayed to another.
			extra = nil
		}
		if nextMethod != method {
			body = nil
		}
		u, method = next, nextMethod
	}
}

// sendable returns u without the parts that must never reach the wire: a
// fragment is not part of a request, and userinfo would be turned into an
// Authorization header by the transport although the scope check ignores it.
func sendable(u *url.URL) *url.URL {
	cp := *u
	cp.User = nil
	cp.Fragment, cp.RawFragment = "", ""
	return &cp
}

// nextHop decides whether the response in h is a redirect to follow. It
// returns the target and method, or a nil target and a note saying why the
// redirect was left alone.
func (c *Client) nextHop(h hop, method string, followed int) (*url.URL, string, string) {
	switch h.ex.Status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return nil, "", ""
	}
	loc := h.header.Get("Location")
	if loc == "" {
		return nil, "", ""
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return nil, "", "redirect not followed: the Location header could not be parsed"
	}
	target := sendable(h.url.ResolveReference(ref))
	nextMethod := method
	if method != http.MethodGet && method != http.MethodHead {
		if h.ex.Status == http.StatusTemporaryRedirect || h.ex.Status == http.StatusPermanentRedirect {
			// These statuses ask for the same method and body again. A
			// state-changing request is sent once, where the caller aimed it.
			return nil, "", fmt.Sprintf("redirect not followed: status %d would repeat the %s at another URL", h.ex.Status, method)
		}
		nextMethod = http.MethodGet
	}
	if err := c.grant.Permits(target, nextMethod); err != nil {
		root := *target
		root.Path, root.RawPath, root.RawQuery = "/", "", ""
		if c.grant.Permits(&root, nextMethod) != nil {
			return nil, "", fmt.Sprintf("redirect to out-of-scope host %s refused", show(target.Host, 100))
		}
		return nil, "", fmt.Sprintf("redirect to out-of-scope path %s refused", show(target.EscapedPath(), 100))
	}
	if followed >= maxRedirectHops {
		return nil, "", fmt.Sprintf("redirect not followed: the limit of %d hops was reached", maxRedirectHops)
	}
	return target, nextMethod, ""
}

func (c *Client) atCap() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests >= c.maxRequests
}

// send performs one round trip. The caller has already checked the scope.
// The returned hop is not recorded yet.
func (c *Client) send(ctx context.Context, method string, u *url.URL, extra map[string]string, body []byte) (hop, error) {
	c.mu.Lock()
	if c.requests >= c.maxRequests {
		c.mu.Unlock()
		return hop{}, fmt.Errorf("%w: all %d requests the scope allows for this run have been sent, so nothing more will be. Raise max_requests in the scope if more are needed", ErrRequestCap, c.maxRequests)
	}
	c.requests++
	last := c.last
	c.mu.Unlock()

	if !last.IsZero() {
		if wait := c.interval - time.Since(last); wait > 0 {
			c.pause(ctx, wait)
		}
	}
	c.mu.Lock()
	c.last = time.Now()
	c.mu.Unlock()

	headers := maps.Clone(c.headers)
	maps.Copy(headers, extra)
	h := hop{url: u, ex: Exchange{
		Method:     method,
		URL:        redacted(u.String()),
		ReqHeaders: maskRequestHeaders(headers),
		ReqBody:    storable(body, maxReqStored),
	}}

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		h.ex.Error = "the request could not be built"
		return h, fmt.Errorf("the request to %s could not be built: %w", show(u.Host, 100), err)
	}
	for name, value := range headers {
		req.Header[name] = []string{value}
	}

	start := time.Now()
	resp, err := c.http.Do(req) //nolint:gosec // the URL passed the scope gate above; sending it is this package's purpose
	h.ex.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		h.ex.Error = show(redacted(err.Error()), 300)
		return h, fmt.Errorf("the request to %s got no response: %w. Check that the target is running and reachable", show(u.Host, 100), err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if cerr := resp.Body.Close(); cerr != nil && readErr == nil {
		readErr = cerr
	}
	if readErr != nil {
		// The status and headers arrived; what was read of the body is kept.
		h.ex.Error = show("the response body was cut short: "+redacted(readErr.Error()), 300)
	}
	h.header = resp.Header
	h.body = raw
	h.ex.Status = resp.StatusCode
	h.ex.RespHeaders = maskResponseHeaders(resp.Header)
	h.ex.RespBody = storable(raw, maxRespStored)
	return h, nil
}

// pause waits for the rate limit.
func (c *Client) pause(ctx context.Context, d time.Duration) {
	if c.sleep != nil {
		c.sleep(d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// record gives the exchange its id, stores it and reports it.
func (c *Client) record(h *hop) {
	c.mu.Lock()
	h.ex.ID = fmt.Sprintf("X-%04d", len(c.exchanges)+1)
	c.exchanges = append(c.exchanges, h.ex)
	c.mu.Unlock()
	if c.onRecord != nil {
		c.onRecord(cloneExchange(h.ex))
	}
}

// Exchanges returns a copy of every recorded exchange, in order.
func (c *Client) Exchanges() []Exchange {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Exchange, len(c.exchanges))
	for i, ex := range c.exchanges {
		out[i] = cloneExchange(ex)
	}
	return out
}

// Exchange returns the recorded exchange with the given id.
func (c *Client) Exchange(id string) (Exchange, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ex := range c.exchanges {
		if ex.ID == id {
			return cloneExchange(ex), true
		}
	}
	return Exchange{}, false
}

// Requests returns how many requests have been sent, counting every
// redirect hop.
func (c *Client) Requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests
}

// remaining returns how many more requests the cap allows.
func (c *Client) remaining() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxRequests - c.requests
}

func cloneExchange(ex Exchange) Exchange {
	ex.ReqHeaders = maps.Clone(ex.ReqHeaders)
	ex.RespHeaders = maps.Clone(ex.RespHeaders)
	return ex
}

// cleanHeaders validates caller-supplied headers and returns them under
// canonical names, without the ones a caller must not control.
func cleanHeaders(in map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(in))
	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := in[name]
		if !validHeaderName(name) {
			return nil, fmt.Errorf("header name %s is refused because a header name may hold only letters, digits and - _ . characters, with no spaces or line breaks. Fix the name", show(name, 60))
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("the value of header %s is refused because it contains a line break or NUL, which would inject another header. Send a single-line value", show(name, 60))
		}
		if transportHeader(name) {
			continue
		}
		out[http.CanonicalHeaderKey(name)] = value
	}
	return out, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0:
		default:
			return false
		}
	}
	return true
}

// transportHeader reports headers that describe the connection or the
// message framing. Those belong to the transport: a caller that sets them
// could aim the request at another virtual host or smuggle a second request.
func transportHeader(name string) bool {
	low := strings.ToLower(name)
	switch low {
	case "host", "content-length", "transfer-encoding", "connection", "upgrade", "keep-alive", "te", "trailer":
		return true
	}
	return strings.HasPrefix(low, "proxy-")
}

// credentialHeader reports request headers whose value is a credential.
func credentialHeader(name string) bool {
	low := strings.ToLower(name)
	for _, part := range []string{"authorization", "cookie", "api-key", "apikey", "token", "secret", "password", "session", "auth"} {
		if strings.Contains(low, part) {
			return true
		}
	}
	return false
}

func maskRequestHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for name, value := range h {
		if credentialHeader(name) {
			out[name] = masked
			continue
		}
		out[name] = redacted(value)
	}
	return out
}

func maskResponseHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		if name == "Set-Cookie" {
			lines := make([]string, len(values))
			for i, v := range values {
				lines[i] = maskSetCookie(v)
			}
			// One cookie per line: a comma cannot separate them because
			// the Expires attribute contains one.
			out[name] = strings.Join(lines, "\n")
			continue
		}
		out[name] = redacted(strings.ToValidUTF8(strings.Join(values, ", "), "\uFFFD"))
	}
	return out
}

// maskSetCookie keeps the cookie name and attributes and drops the value.
func maskSetCookie(v string) string {
	v = strings.ToValidUTF8(v, "\uFFFD")
	pair, attrs, hasAttrs := strings.Cut(v, ";")
	name, _, hasValue := strings.Cut(pair, "=")
	if !hasValue {
		// A nameless cookie: the whole first part is the value.
		name = ""
	}
	out := strings.TrimSpace(name) + "=" + masked
	if hasAttrs {
		out += ";" + attrs
	}
	return out
}

// redacted replaces secrets that the redaction rules recognize.
func redacted(s string) string {
	out, _ := redact.Apply(s)
	return out
}

// storable turns raw bytes into the text kept in an exchange: valid UTF-8,
// secrets replaced, at most limit bytes. Redaction runs on the whole text
// before the cut, because half a secret matches no rule.
func storable(raw []byte, limit int) string {
	if len(raw) == 0 {
		return ""
	}
	s := redacted(strings.ToValidUTF8(string(raw), "\uFFFD"))
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// show renders untrusted text for a message: one line, no control
// characters, at most n characters.
func show(s string, n int) string {
	var b strings.Builder
	count := 0
	for _, r := range strings.ToValidUTF8(s, "?") {
		if count == n {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
