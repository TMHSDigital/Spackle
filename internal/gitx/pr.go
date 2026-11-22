package gitx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// PRRequest describes a pull request to open for a fix branch.
type PRRequest struct {
	// Dir is the worktree that holds the branch.
	Dir    string
	Branch string
	Title  string
	Body   string
}

// OpenPR pushes the branch to the "origin" remote and opens a pull request
// with the GitHub CLI. It is only called when the operator passed --pr: it
// is the one place Spackle writes anywhere other than the local machine.
//
// The pull request is opened as a draft. A patch written by a model should
// be read by a person before it is merged, and a draft says so.
func OpenPR(ctx context.Context, req PRRequest) (string, error) {
	if strings.HasPrefix(req.Branch, "-") || req.Branch == "" {
		return "", fmt.Errorf("branch %q is not valid", req.Branch)
	}
	if _, err := exec.LookPath("gh"); err != nil {
		return "", errors.New("the GitHub CLI (gh) is not installed: install it and run \"gh auth login\", or push the branch and open the pull request yourself")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if _, err := run(ctx, req.Dir, "push", "--set-upstream", "origin", req.Branch); err != nil {
		return "", fmt.Errorf("push %s to origin: %w. Check that the remote exists and that you may push to it", req.Branch, err)
	}
	body, err := os.CreateTemp("", "spackle-pr-*.md")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(body.Name()) }()
	if _, err := body.WriteString(req.Body); err != nil {
		_ = body.Close()
		return "", err
	}
	if err := body.Close(); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "gh", "pr", "create", "--draft", "--head", req.Branch, "--title", req.Title, "--body-file", body.Name()) //nolint:gosec // fixed program, argument vector, no shell
	cmd.Dir = req.Dir
	cmd.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1", "GIT_TERMINAL_PROMPT=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gh pr create failed: %s. The branch %s was pushed; open the pull request by hand", firstLine(strings.TrimSpace(stderr.String())), req.Branch)
	}
	return strings.TrimSpace(stdout.String()), nil
}
