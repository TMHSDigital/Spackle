package llm

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IsLoopbackHost reports whether host (without a port) names this machine.
// Only loopback counts as local. A private LAN address does not: offline
// mode promises that nothing leaves the machine, and a LAN host is another
// machine.
func IsLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsLoopbackURL reports whether a URL points at this machine.
func IsLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return IsLoopbackHost(u.Hostname())
}

// loopbackOnlyDial refuses to connect to anything but a loopback address.
// It checks the resolved IP, not the name, so a hostname that resolves to a
// remote address is refused even if it looks local.
func loopbackOnlyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrOffline, addr)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot resolve %s", ErrOffline, host)
	}
	for _, ip := range ips {
		if !ip.IP.IsLoopback() {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrOffline, host, ip.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s has no address", ErrOffline, host)
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// NewHTTPClient returns the client providers use. In offline mode its
// dialer refuses every non-loopback address and proxies are ignored, so the
// guarantee holds even if a base URL check is bypassed or a server
// redirects elsewhere.
func NewHTTPClient(offline bool) *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 10 * time.Minute, // long completions without streaming
	}
	if offline {
		tr.Proxy = nil
		tr.DialContext = loopbackOnlyDial
	} else {
		tr.DialContext = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	return &http.Client{
		Transport: tr,
		Timeout:   12 * time.Minute,
		// A provider API has no reason to redirect. Refusing redirects keeps
		// an API key from being replayed to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
