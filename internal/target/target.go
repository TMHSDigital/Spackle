// Package target classifies what the operator pointed Spackle at. The
// classification decides whether the authorized-scope gate applies: local
// source does not need it, a live URL always does.
package target

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Kind is the type of a target.
type Kind string

// Target kinds.
const (
	KindPath Kind = "path" // a directory on this machine
	KindGit  Kind = "git"  // a repository to clone, then treated as a path
	KindURL  Kind = "url"  // a live application: requires an authorized scope
)

// Target is a classified target.
type Target struct {
	Kind Kind
	// Raw is the argument as given.
	Raw string
	// Display is Raw with any embedded credentials removed. It is what goes
	// into the ledger and reports.
	Display string
	// URL is set for KindURL and for KindGit when the remote is a URL.
	URL *url.URL
}

// Live reports whether the target is a running system that needs the
// authorized-scope gate.
func (t Target) Live() bool { return t.Kind == KindURL }

// Classify decides what arg is. An empty arg means the current directory.
func Classify(arg string) (Target, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		arg = "."
	}
	lower := strings.ToLower(arg)

	// scp-style git remotes: git@host:owner/repo(.git)
	if strings.HasPrefix(lower, "git@") || strings.HasPrefix(lower, "ssh://") || strings.HasPrefix(lower, "git://") {
		return Target{Kind: KindGit, Raw: arg, Display: stripCreds(arg)}, nil
	}

	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		u, err := url.Parse(arg)
		if err != nil || u.Host == "" {
			return Target{}, fmt.Errorf("target %q is not a valid URL: give a full URL such as https://staging.example.test", stripCreds(arg))
		}
		t := Target{Raw: arg, Display: stripCreds(arg), URL: u}
		if looksLikeGitRemote(u) {
			t.Kind = KindGit
		} else {
			t.Kind = KindURL
		}
		return t, nil
	}

	if strings.Contains(arg, "://") {
		scheme, _, _ := strings.Cut(arg, "://")
		return Target{}, fmt.Errorf("target scheme %q is not supported: use a local path, a git URL, or an http(s) URL", scheme)
	}

	// A local path. An existing path always wins, so a directory that
	// happens to be named like a host is still scanned as a directory.
	if _, err := os.Stat(arg); err == nil {
		return Target{Kind: KindPath, Raw: arg, Display: arg}, nil
	}

	// A bare host or host:port is ambiguous with a mistyped path. Refuse to
	// guess: guessing "live host" here could send traffic to a system the
	// operator did not mean to test.
	if looksLikeHost(arg) {
		return Target{}, fmt.Errorf("target %q is not an existing path and looks like a host: to test a running application give the full URL (for example http://%s) so the authorized-scope check applies", arg, arg)
	}
	return Target{}, fmt.Errorf("target %q does not exist: give a directory, a git URL, or an http(s) URL", arg)
}

// looksLikeGitRemote recognizes clone URLs: an explicit .git suffix, or an
// owner/repo path on a well-known forge.
func looksLikeGitRemote(u *url.URL) bool {
	path := strings.TrimSuffix(u.Path, "/")
	if strings.HasSuffix(strings.ToLower(path), ".git") {
		return true
	}
	if !KnownForge(u.Hostname()) {
		return false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for _, p := range parts {
		// "-" separates a GitLab project from its pages (/-/issues): that
		// is a page of the forge, not a repository.
		if p == "" || p == "-" {
			return false
		}
	}
	if strings.EqualFold(u.Hostname(), "gitlab.com") {
		// GitLab projects can sit in nested groups: group/subgroup/project.
		return len(parts) >= 2
	}
	return len(parts) == 2
}

// KnownForge reports whether host is a code hosting site whose repository
// URLs Spackle recognizes without a .git suffix.
func KnownForge(host string) bool {
	switch strings.ToLower(host) {
	case "github.com", "gitlab.com", "bitbucket.org", "codeberg.org":
		return true
	}
	return false
}

func looksLikeHost(s string) bool {
	if strings.ContainsAny(s, `/\ `) {
		return false
	}
	host := s
	if h, _, ok := strings.Cut(s, ":"); ok {
		host = h
	}
	return host == "localhost" || strings.Contains(host, ".")
}

// stripCreds removes user:password@ from a URL-like string.
func stripCreds(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}
