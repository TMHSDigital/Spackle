package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/textx"
)

const (
	defaultLogEntries = 15
	maxLogEntries     = 50
)

// commitHash is the only revision syntax git_show accepts. Refs, ranges
// ("a..b"), reflog and path syntax ("HEAD@{1}", "rev:path") and anything
// starting with "-" are all excluded by construction.
var commitHash = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// gitPath validates a model-supplied path for use as a git pathspec and
// returns it in forward-slash form. It is checked lexically, not with
// walk.Resolve, because history legitimately names files that no longer
// exist. The result always stays under the target root: git runs with the
// root as its working directory and a relative pathspec cannot leave it.
func gitPath(p string) (string, error) {
	if p == "" {
		// "." keeps history limited to the target even when the target is
		// a subdirectory of a larger repository.
		return ".", nil
	}
	fix := "; pass a path relative to the target root, such as src/app.py"
	s := strings.ReplaceAll(p, `\`, "/")
	switch {
	case strings.ContainsRune(s, 0):
		return "", errors.New("path contains a NUL byte" + fix)
	case strings.HasPrefix(s, "/") || (len(s) >= 2 && s[1] == ':'):
		return "", fmt.Errorf("path %s is absolute%s", quote(p), fix)
	case strings.HasPrefix(s, ":"):
		// ":/", ":(top)" and friends are pathspec magic that can address
		// the repository root above the target.
		return "", fmt.Errorf("path %s starts with a colon, which git treats as special syntax%s", quote(p), fix)
	}
	clean := path.Clean(s)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path %s leaves the target%s", quote(p), fix)
	}
	if strings.HasPrefix(clean, ":") {
		return "", fmt.Errorf("path %s starts with a colon, which git treats as special syntax%s", quote(p), fix)
	}
	return clean, nil
}

// gitError turns a gitx failure into advice. gitx errors repeat the
// arguments and git's own message, so the text is clipped as a whole.
func gitError(err error) error {
	if errors.Is(err, gitx.ErrNotRepo) {
		return errors.New("history is unavailable: the target is not a git repository; continue with read_file and grep")
	}
	return fmt.Errorf("git failed (%s); check the arguments, or continue without history", textx.Clip(err.Error(), 200))
}

func gitReady() error {
	if !gitx.Available() {
		return errors.New("history is unavailable: git is not installed on this machine; continue with read_file and grep")
	}
	return nil
}

type gitLogArgs struct {
	Path string `json:"path"`
	Max  int    `json:"max"`
}

func (r *Registry) gitLogTool() builtin {
	return builtin{
		def: llm.ToolDef{
			Name:        "git_log",
			Description: "Show recent commits of the target, one per line (short hash, date, author, subject), optionally limited to a path.",
			Schema: schema(`"path":{"type":"string","description":"File or directory relative to the target root. Default: the whole target."},` +
				`"max":{"type":"integer","minimum":1,"maximum":50,"description":"Commits to return. Default 15, at most 50."}`),
		},
		fn: func(ctx context.Context, raw json.RawMessage) (string, string, error) {
			var a gitLogArgs
			if err := decode(raw, &a); err != nil {
				return "", "", err
			}
			spec, err := gitPath(a.Path)
			if err != nil {
				return "", "", err
			}
			if r.rootErr != nil {
				return "", "", r.rootErr
			}
			if err := gitReady(); err != nil {
				return "", "", err
			}
			n := a.Max
			if n <= 0 {
				n = defaultLogEntries
			}
			out, err := gitx.Log(ctx, r.realRoot, spec, min(n, maxLogEntries))
			if err != nil {
				return "", "", gitError(err)
			}
			if out == "" {
				out = "[no commits found for this path]"
			}
			return "git_log " + spec, out + "\n", nil
		},
	}
}

type gitShowArgs struct {
	Rev  string `json:"rev"`
	Path string `json:"path"`
}

func (r *Registry) gitShowTool() builtin {
	return builtin{
		def: llm.ToolDef{
			Name:        "git_show",
			Description: "Show one commit of the target (message, stat and patch), optionally limited to a path. The commit is named by its hash, as printed by git_log.",
			Schema: schema(`"rev":{"type":"string","pattern":"^[0-9a-fA-F]{7,40}$","description":"Commit hash, 7 to 40 hex digits. Branch names, HEAD and ranges are not accepted."},`+
				`"path":{"type":"string","description":"File or directory relative to the target root. Default: the whole target."}`, "rev"),
		},
		fn: func(ctx context.Context, raw json.RawMessage) (string, string, error) {
			var a gitShowArgs
			if err := decode(raw, &a); err != nil {
				return "", "", err
			}
			if !commitHash.MatchString(a.Rev) {
				return "", "", fmt.Errorf("rev %s is not a commit hash; pass 7 to 40 hex digits copied from git_log (branch names, HEAD, ranges and options are not accepted)", quote(a.Rev))
			}
			spec, err := gitPath(a.Path)
			if err != nil {
				return "", "", err
			}
			if r.rootErr != nil {
				return "", "", r.rootErr
			}
			if err := gitReady(); err != nil {
				return "", "", err
			}
			out, err := gitx.Show(ctx, r.realRoot, a.Rev, spec)
			if err != nil {
				return "", "", gitError(err)
			}
			if out == "" {
				out = "[the commit has no changes under this path]"
			}
			return "git_show " + a.Rev + " " + spec, out + "\n", nil
		},
	}
}
