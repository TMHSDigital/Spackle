// Package gitx wraps the git command line for the few operations Spackle
// needs: reading the commit, cloning a target, creating a worktree for
// fixes, reading history, and bisecting.
//
// Every call passes arguments as a vector, never through a shell, and
// disables hooks and prompts so a hostile repository cannot run code or
// block the run by asking for credentials.
package gitx

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotRepo is returned when a directory is not inside a git work tree.
var ErrNotRepo = errors.New("not a git repository")

// Available reports whether git is on PATH.
func Available() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// run executes git in dir and returns trimmed stdout.
func run(ctx context.Context, dir string, args ...string) (string, error) {
	// core.hooksPath to an empty location and protocol restrictions keep a
	// target repository from executing code through git itself.
	base := []string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.fsmonitor=false",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=user",
	}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...) //nolint:gosec // fixed program, argument vector, no shell
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_OPTIONAL_LOCKS=0",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(msg, "not a git repository") {
			return "", ErrNotRepo
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), firstLine(msg))
	}
	return strings.TrimRight(stdout.String(), "\r\n"), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// HeadSHA returns the full commit hash of HEAD, or ErrNotRepo.
func HeadSHA(ctx context.Context, dir string) (string, error) {
	if !Available() {
		return "", ErrNotRepo
	}
	return run(ctx, dir, "rev-parse", "HEAD")
}

// TopLevel returns the root of the work tree containing dir.
func TopLevel(ctx context.Context, dir string) (string, error) {
	if !Available() {
		return "", ErrNotRepo
	}
	return run(ctx, dir, "rev-parse", "--show-toplevel")
}

// Status returns `git status --porcelain` output. An empty string means the
// work tree is clean.
func Status(ctx context.Context, dir string) (string, error) {
	return run(ctx, dir, "status", "--porcelain")
}

// IsClean reports whether the work tree has no uncommitted changes.
func IsClean(ctx context.Context, dir string) (bool, error) {
	out, err := Status(ctx, dir)
	return out == "", err
}

// Clone makes a shallow clone of remote into dest. Submodules are not
// fetched: they are separate code the operator did not name as the target.
func Clone(ctx context.Context, remote, dest string) error {
	if !Available() {
		return errors.New("git is not installed: install git to scan a repository URL, or clone it yourself and pass the directory")
	}
	if strings.HasPrefix(remote, "-") {
		return fmt.Errorf("refusing git remote %q: it starts with a dash", remote)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	_, err := run(ctx, "", "clone", "--depth", "1", "--no-tags", "--single-branch", "--", remote, dest)
	if err != nil {
		return fmt.Errorf("clone %s: %w. Check the URL and your access, or clone it yourself and pass the directory", remote, err)
	}
	return nil
}

// Log returns up to n one-line history entries for path (or the whole
// repository when path is empty).
func Log(ctx context.Context, dir, path string, n int) (string, error) {
	args := []string{"log", fmt.Sprintf("-n%d", n), "--date=short", "--pretty=format:%h %ad %an: %s"}
	if path != "" {
		args = append(args, "--", path)
	}
	return run(ctx, dir, args...)
}

// Show returns the patch of one commit, limited to path when given.
func Show(ctx context.Context, dir, rev, path string) (string, error) {
	if strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("revision %q is not valid", rev)
	}
	args := []string{"show", "--no-color", "--stat", "--patch", rev}
	if path != "" {
		args = append(args, "--", path)
	}
	return run(ctx, dir, args...)
}

// AddWorktree creates a new branch at HEAD checked out in a new worktree
// at path. The caller's working tree and index are not touched.
func AddWorktree(ctx context.Context, repo, path, branch string) error {
	if strings.HasPrefix(branch, "-") {
		return fmt.Errorf("branch %q is not valid", branch)
	}
	_, err := run(ctx, repo, "worktree", "add", "-b", branch, "--", path, "HEAD")
	if err != nil {
		return fmt.Errorf("create worktree for branch %s: %w", branch, err)
	}
	return nil
}

// ApplyCheck reports whether a unified diff applies cleanly in dir.
func ApplyCheck(ctx context.Context, dir, patchFile string) error {
	_, err := run(ctx, dir, "apply", "--check", "--whitespace=nowarn", "--", patchFile)
	return err
}

// Apply applies a unified diff in dir. It works in a plain directory too,
// not only inside a repository.
func Apply(ctx context.Context, dir, patchFile string) error {
	_, err := run(ctx, dir, "apply", "--whitespace=nowarn", "--", patchFile)
	return err
}

// CommitAll stages everything in dir and commits with the given message.
// It is only ever called inside a Spackle worktree, never the operator's
// working tree.
func CommitAll(ctx context.Context, dir, message string) error {
	if _, err := run(ctx, dir, "add", "-A"); err != nil {
		return err
	}
	_, err := run(ctx, dir,
		"-c", "user.name=Spackle", "-c", "user.email=spackle@localhost", "-c", "commit.gpgsign=false",
		"commit", "--no-verify", "-m", message)
	return err
}

// RevList returns the commits from good (exclusive) to bad (inclusive),
// oldest first.
func RevList(ctx context.Context, dir, good, bad string) ([]string, error) {
	for _, r := range []string{good, bad} {
		if strings.HasPrefix(r, "-") || r == "" {
			return nil, fmt.Errorf("revision %q is not valid", r)
		}
	}
	out, err := run(ctx, dir, "rev-list", "--reverse", "--first-parent", good+".."+bad)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n"), nil
}

// Archive exports the tree at rev into dest (which must exist), without any
// .git directory. It is how a specific commit is handed to the sandbox.
func Archive(ctx context.Context, dir, rev, dest string) error {
	if strings.HasPrefix(rev, "-") {
		return fmt.Errorf("revision %q is not valid", rev)
	}
	// git archive only reads the object database: it does not touch the
	// operator's index or working tree, unlike a checkout with --work-tree.
	cmd := exec.CommandContext(ctx, "git", "archive", "--format=tar", rev) //nolint:gosec // fixed program, argument vector, no shell
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("export %s: %w", rev, err)
	}
	uerr := untar(stdout, dest)
	// git pads the archive after the end-of-archive marker. Drain it, or
	// git blocks on a full pipe and Wait never returns.
	_, _ = io.Copy(io.Discard, stdout)
	werr := cmd.Wait()
	if uerr != nil {
		return fmt.Errorf("export %s: %w", rev, uerr)
	}
	if werr != nil {
		return fmt.Errorf("export %s: %s", rev, firstLine(strings.TrimSpace(stderr.String())))
	}
	return nil
}

// untar extracts a tar stream into dest. Entries that would land outside
// dest, and anything that is not a regular file or directory, are skipped:
// symlinks in a commit must not become a way out of the export directory.
func untar(r io.Reader, dest string) error {
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(root, filepath.FromSlash(hdr.Name))
		if rel, rerr := filepath.Rel(root, target); rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			mode := os.FileMode(0o640)
			if hdr.Mode&0o111 != 0 {
				mode = 0o750
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) //nolint:gosec // target is confined to dest above
			if err != nil {
				return err
			}
			// Cap each file so a crafted archive cannot fill the disk.
			_, cerr := io.Copy(f, io.LimitReader(tr, 64<<20))
			if clerr := f.Close(); cerr == nil {
				cerr = clerr
			}
			if cerr != nil {
				return cerr
			}
		}
	}
}
