package dast

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/TMHSDigital/spackle/internal/authz"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/seed"
)

const (
	defaultMaxPages = 40
	// probeReserve is how close to the request cap the parameter probes
	// may get. Starting a parameter with fewer requests left would leave
	// its checks half done.
	probeReserve = 10
)

// Result is what a baseline run found.
type Result struct {
	Leads     []seed.Lead
	Endpoints []Endpoint
	Notes     []string // what was skipped and why (cap reached, unsafe methods not allowed, ...)
}

// Options configure Baseline.
type Options struct {
	// MaxPages bounds how many pages the crawl fetches. Zero means 40.
	MaxPages int
}

// scanner holds the state of one baseline run.
type scanner struct {
	ctx   context.Context
	c     *Client
	leads []seed.Lead
	seen  map[string]bool // lead keys already reported
	notes []string

	targets []*target
	known   map[string]bool // target keys already discovered

	headersChecked bool
	capped         bool
	failed         int
	outOfScope     int
	logoutSkipped  int
	nonceFallback  int
}

// Baseline crawls from start within scope and runs the passive and active checks. It never
// returns an error for a finding-level problem; errors are for "could not reach the target at
// all" and for a cancelled run, which also returns what was found so far.
func Baseline(ctx context.Context, c *Client, start *url.URL, opts Options) (Result, error) {
	if c == nil {
		return Result{}, errors.New("the baseline needs a scope-bound client and none was given. Build one with NewClient from a grant")
	}
	if start == nil {
		return Result{}, errors.New("the baseline needs a start URL and none was given. Pass the URL of the running target")
	}
	maxPages := opts.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	start = sendable(start)
	s := &scanner{ctx: ctx, c: c, seen: map[string]bool{}, known: map[string]bool{}}

	first, err := c.roundTrips(ctx, "GET", start.String(), nil, nil)
	if err != nil {
		return Result{}, fmt.Errorf("the baseline could not reach %s: %w", show(start.Host, 100), err)
	}
	for _, h := range first {
		s.observe(h)
	}

	root := newTarget("GET", start, nil, "start")
	s.known[root.key()] = true
	s.targets = append(s.targets, root)
	s.crawl(first, maxPages)

	if s.usable() {
		s.checkCORS(start)
	}
	if s.usable() {
		s.checkExposedFiles(start)
	}
	s.probeAll()
	s.finish()

	res := Result{Leads: s.leads, Notes: s.notes}
	for _, t := range s.targets {
		res.Endpoints = append(res.Endpoints, t.ep)
	}
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("the baseline was stopped before it finished: %w. The result holds what was found until then", err)
	}
	return res, nil
}

// usable reports whether more requests can be sent.
func (s *scanner) usable() bool { return !s.capped && s.ctx.Err() == nil }

// fetch sends one request and runs the passive checks on every hop. It
// returns false when there is no response to look at.
func (s *scanner) fetch(method, rawURL string, headers map[string]string, body []byte) ([]hop, bool) {
	if !s.usable() {
		return nil, false
	}
	hops, err := s.c.roundTrips(s.ctx, method, rawURL, headers, body)
	for _, h := range hops {
		s.observe(h)
	}
	switch {
	case err == nil:
		return hops, len(hops) > 0
	case errors.Is(err, ErrRequestCap):
		s.capped = true
		s.notes = append(s.notes, fmt.Sprintf("The request cap of %d was reached, so the remaining pages and checks were skipped. Raise max_requests in the scope to cover more.", s.c.maxRequests))
	case errors.Is(err, authz.ErrNotAuthorized):
		// Outside the scope (for example a well-known path outside the
		// path prefixes): not sent, and nothing to report.
	case s.ctx.Err() != nil:
	default:
		s.failed++
	}
	return nil, false
}

// add records a lead once per key.
func (s *scanner) add(key string, l seed.Lead) {
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	l.Surface = finding.SurfaceDAST
	s.leads = append(s.leads, l)
}

// nonce returns random hex that makes each probe marker unique, so a
// reflection can be tied to the request that caused it.
func (s *scanner) nonce() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Uniqueness within the run is what matters; a counter gives that.
		s.nonceFallback++
		return fmt.Sprintf("%012x", s.nonceFallback)
	}
	return hex.EncodeToString(b[:])
}

// discover adds a target unless it is out of scope, already known or
// something the crawl must leave alone.
func (s *scanner) discover(t *target) bool {
	if len(s.targets) >= maxTargets {
		return false
	}
	if err := s.c.grant.Permits(t.u, "GET"); err != nil {
		s.outOfScope++
		return false
	}
	if logoutLike(t.u.Path) || logoutLike(t.u.RawQuery) || logoutLike(t.values.Encode()) {
		s.logoutSkipped++
		return false
	}
	if t.ep.Method == http.MethodGet && len(t.values) == 0 && staticAsset(t.u) {
		return false
	}
	if s.known[t.key()] {
		return false
	}
	s.known[t.key()] = true
	s.targets = append(s.targets, t)
	return true
}

// crawl walks the in-scope pages breadth first. first holds the response
// to the start URL, which has been fetched already.
func (s *scanner) crawl(first []hop, maxPages int) {
	queue := []*target{s.targets[0]}
	pages := 0
	for len(queue) > 0 && s.usable() {
		if pages >= maxPages {
			s.notes = append(s.notes, fmt.Sprintf("The crawl stopped at MaxPages (%d) with %d discovered URLs not fetched; those were not probed.", maxPages, len(queue)))
			return
		}
		t := queue[0]
		queue = queue[1:]
		hops := first
		if pages > 0 {
			rawURL, _, _ := t.request(t.values)
			var ok bool
			if hops, ok = s.fetch("GET", rawURL, nil, nil); !ok {
				pages++
				continue
			}
		}
		pages++
		page := hops[len(hops)-1]
		t.fetched = true
		t.baseErrors = map[string]bool{}
		for _, name := range sqlErrors(string(page.body)) {
			t.baseErrors[name] = true
		}
		if !isHTML(page) {
			continue
		}
		links, forms := extract(page.body, page.url)
		for _, u := range links {
			if nt := newTarget("GET", u, nil, "link"); s.discover(nt) {
				queue = append(queue, nt)
			}
		}
		for _, f := range forms {
			nt := newTarget(f.method, f.action, f.values, "form")
			if s.discover(nt) && f.method == "GET" {
				queue = append(queue, nt)
			}
		}
	}
}

// probeAll runs the active checks: GET parameters always, POST form fields
// only when the scope allows state-changing methods.
func (s *scanner) probeAll() {
	skipped := 0
	nearCap := func() bool {
		if s.c.remaining() <= probeReserve {
			skipped++
			return true
		}
		return false
	}
	var forms []*target
	for _, t := range s.targets {
		if t.ep.Method != http.MethodGet {
			forms = append(forms, t)
			continue
		}
		if !t.fetched {
			continue
		}
		for _, param := range t.ep.Params {
			if !s.usable() {
				break
			}
			if nearCap() {
				continue
			}
			s.probeParam(t, param)
		}
	}

	if len(forms) > 0 && !s.c.grant.Scope().AllowUnsafeMethods {
		s.notes = append(s.notes, fmt.Sprintf("%d POST form(s) were found and not probed, because the scope allows safe methods only. Set allow_unsafe_methods = true in the scope file to probe them if you are authorized to send state-changing requests.", len(forms)))
		forms = nil
	}
	for _, t := range forms {
		if !s.usable() {
			break
		}
		if len(t.ep.Params) == 0 {
			continue
		}
		if nearCap() {
			skipped += len(t.ep.Params) - 1
			continue
		}
		// The unmodified submission is the comparison for the SQL check.
		rawURL, body, headers := t.request(t.values)
		hops, ok := s.fetch(t.ep.Method, rawURL, headers, body)
		if !ok {
			continue
		}
		t.fetched = true
		t.baseErrors = map[string]bool{}
		for _, name := range sqlErrors(string(hops[len(hops)-1].body)) {
			t.baseErrors[name] = true
		}
		for _, param := range t.ep.Params {
			if !s.usable() {
				break
			}
			if nearCap() {
				continue
			}
			s.probeParam(t, param)
		}
	}
	if skipped > 0 {
		s.notes = append(s.notes, fmt.Sprintf("%d parameter(s) were not probed because the run was within %d requests of the request cap (%d). Raise max_requests in the scope to cover them.", skipped, probeReserve, s.c.maxRequests))
	}
}

// finish adds the notes that summarize what the run left out.
func (s *scanner) finish() {
	if s.logoutSkipped > 0 {
		s.notes = append(s.notes, fmt.Sprintf("%d link(s) or form(s) that look like they end a session or delete data (%s) were skipped on purpose.", s.logoutSkipped, strings.Join(logoutWords, ", ")))
	}
	if s.outOfScope > 0 {
		s.notes = append(s.notes, fmt.Sprintf("%d URL(s) were outside the authorized scope and were not requested.", s.outOfScope))
	}
	if s.failed > 0 {
		s.notes = append(s.notes, fmt.Sprintf("%d request(s) got no response; the checks that depended on them were skipped. See the exchanges with an error for details.", s.failed))
	}
	if s.ctx.Err() != nil {
		s.notes = append(s.notes, "The run was cancelled before every check had run.")
	}
}
