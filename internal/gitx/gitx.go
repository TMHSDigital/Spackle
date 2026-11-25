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
	"runtime"
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

// Prefix returns the path of dir relative to the top of its work tree, with
// forward slashes and no trailing slash ("" at the top). Asking git avoids
// comparing path spellings, which differ on Windows (short names, case).
func Prefix(ctx context.Context, dir string) (string, error) {
	if !Available() {
		return "", ErrNotRepo
	}
	out, err := run(ctx, dir, "rev-parse", "--show-prefix")
	return strings.TrimSuffix(out, "/"), err
}

// Tracked reports whether every given path (relative to dir) is tracked by
// git. A directory can sit inside some unrelated repository without being
// part of it (a temp folder under a home directory that is itself a
// repository, for example). Spackle only treats a target as "in git" when
// its files are tracked.
func Tracked(ctx context.Context, dir string, paths ...string) bool {
	if !Available() || len(paths) == 0 {
		return false
	}
	args := append([]string{"ls-files", "--error-unmatch", "--"}, paths...)
	_, err := run(ctx, dir, args...)
	return err == nil
}

// HasTracked reports whether dir contains at least one tracked file.
func HasTracked(ctx context.Context, dir string) bool {
	if !Available() {
		return false
	}
	out, err := run(ctx, dir, "ls-files", "--", ".")
	return err == nil && strings.TrimSpace(out) != ""
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

// IsCleanExcept reports whether the work tree has no uncommitted changes
// outside the named top-level directory. dir must be the top of the work
// tree.
func IsCleanExcept(ctx context.Context, dir, except string) (bool, error) {
	out, err := run(ctx, dir, "status", "--porcelain", "--", ".", ":(exclude)"+except)
	return strings.TrimSpace(out) == "", err
}

// Dirty reports whether any of the given paths (relative to dir) differs
// from HEAD: modified, staged, deleted or untracked.
func Dirty(ctx context.Context, dir string, paths ...string) (bool, error) {
	if len(paths) == 0 {
		return false, nil
	}
	out, err := run(ctx, dir, append([]string{"status", "--porcelain", "--"}, paths...)...)
	return strings.TrimSpace(out) != "", err
}

// Clone makes a shallow clone of remote into dest. Submodules are not
// fetched: they are separate code the operator did not name as the target.
func Clone(ctx context.Context, remote, dest string) error {
	return CloneRef(ctx, remote, dest, "")
}

// CloneRef is Clone for a named branch or tag instead of the remote's
// default branch. An empty ref means the default branch.
func CloneRef(ctx context.Context, remote, dest, ref string) error {
	if !Available() {
		return errors.New("git is not installed: install git to scan a repository URL, or clone it yourself and pass the directory")
	}
	if strings.HasPrefix(remote, "-") {
		return fmt.Errorf("refusing git remote %q: it starts with a dash", remote)
	}
	if strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, " \t\n") {
		return fmt.Errorf("refusing git ref %q: a branch or tag name cannot start with a dash or contain spaces", ref)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	args := []string{"clone", "--depth", "1", "--no-tags", "--single-branch"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	_, err := run(ctx, "", append(args, "--", remote, dest)...)
	if err != nil {
		if ref != "" {
			return fmt.Errorf("clone %s at %s: %w. Check the URL, that the branch or tag exists, and your access; a commit hash is not accepted here", remote, ref, err)
		}
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
	// --no-textconv and --no-ext-diff matter: a repository can configure a
	// text conversion or external diff program in .git/config, and showing a
	// patch would run it.
	args := []string{"show", "--no-color", "--no-textconv", "--no-ext-diff", "--stat", "--patch", rev}
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

// RemoveWorktree removes a disposable fix worktree and its registration, even
// when a failed fix left untracked files behind.
func RemoveWorktree(ctx context.Context, repo, path string) error {
	_, err := run(ctx, repo, "worktree", "remove", "--force", "--", path)
	return err
}

// DeleteBranch removes a disposable fix branch after its worktree is gone.
func DeleteBranch(ctx context.Context, repo, branch string) error {
	_, err := run(ctx, repo, "branch", "-D", "--", branch)
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

// ResetWorktree throws away every uncommitted change in dir. It is only
// ever called inside a Spackle worktree, never the operator's working tree.
func ResetWorktree(ctx context.Context, dir string) error {
	if _, err := run(ctx, dir, "reset", "-q", "--hard", "HEAD"); err != nil {
		return err
	}
	_, err := run(ctx, dir, "clean", "-q", "-fd")
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

// ChangedSince lists the files under dir that were added, copied, modified
// or renamed between the merge base of rev and HEAD, and HEAD. It is the
// set of files a pull request against rev changes. Paths use forward
// slashes and are relative to dir; a change outside dir is not listed, and
// neither is a deleted file or a change that is not committed.
func ChangedSince(ctx context.Context, dir, rev string) ([]string, error) {
	if rev == "" || strings.HasPrefix(rev, "-") {
		return nil, fmt.Errorf("revision %q is not valid", rev)
	}
	return changedFiles(ctx, dir, rev+"...HEAD")
}

// ChangedUncommitted returns the files under dir, relative to it, that
// differ from HEAD (staged or not) plus the untracked files git does not
// ignore: what a commit made now could add. Deleted files are left out.
// Before the first commit every file in the index counts as changed.
// exclude names directories under dir, relative to it, that are left out,
// such as the state directory.
func ChangedUncommitted(ctx context.Context, dir string, exclude ...string) ([]string, error) {
	pathspec := []string{"--", "."}
	for _, e := range exclude {
		pathspec = append(pathspec, ":(exclude)"+filepath.ToSlash(e))
	}
	var files []string
	if _, err := run(ctx, dir, "rev-parse", "--verify", "-q", "HEAD"); err == nil {
		if files, err = changedFiles(ctx, dir, "HEAD", pathspec...); err != nil {
			return nil, err
		}
	} else {
		if errors.Is(err, ErrNotRepo) {
			return nil, err
		}
		out, err := run(ctx, dir, append([]string{"ls-files", "-z"}, pathspec...)...)
		if err != nil {
			return nil, err
		}
		files = splitNUL(out)
	}
	out, err := run(ctx, dir, append([]string{"ls-files", "-z", "--others", "--exclude-standard"}, pathspec...)...)
	if err != nil {
		return nil, err
	}
	return append(files, splitNUL(out)...), nil
}

// splitNUL splits git -z output into its non-empty entries.
func splitNUL(out string) []string {
	var entries []string
	for _, f := range strings.Split(out, "\x00") {
		if f != "" {
			entries = append(entries, f)
		}
	}
	return entries
}

// changedFiles lists the files under dir that git diff against spec reports
// as added, copied, modified or renamed.
func changedFiles(ctx context.Context, dir, spec string, pathspec ...string) ([]string, error) {
	if len(pathspec) == 0 {
		pathspec = []string{"--"}
	}
	// -z keeps a file name with a quote, a newline or a non-ASCII character
	// intact. --no-textconv and --no-ext-diff keep the repository's own
	// configuration from starting a program.
	args := append([]string{"diff", "--name-only", "-z", "--relative", "--no-textconv", "--no-ext-diff", "--diff-filter=ACMR", spec}, pathspec...)
	out, err := run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	return splitNUL(out), nil
}

// Archive exports the tree at rev into dest (which must exist), without any
// .git directory. It is how a specific commit is handed to the sandbox.
func Archive(ctx context.Context, dir, rev, dest string) error {
	if strings.HasPrefix(rev, "-") {
		return fmt.Errorf("revision %q is not valid", rev)
	}
	// git archive only reads the object database: it does not touch the
	// operator's index or working tree, unlike a checkout with --work-tree.
	// autocrlf is forced off so the export holds the bytes that were
	// committed, whatever the machine-wide git configuration says.
	cmd := exec.CommandContext(ctx, "git", "-c", "core.autocrlf=false", "archive", "--format=tar", rev) //nolint:gosec // fixed program, argument vector, no shell
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
		// The export is mounted read-only into the sandbox, whose user is
		// neither the owner nor in the group, so everything is made
		// world-readable. The modes are set explicitly afterwards because a
		// strict umask would otherwise strip them.
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAllReadable(root, target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := mkdirAllReadable(root, filepath.Dir(target)); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) //nolint:gosec // target is confined to dest above; world-readable for the sandbox user by design
			if err != nil {
				return err
			}
			if err := f.Chmod(mode); err != nil && runtime.GOOS != "windows" {
				_ = f.Close()
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

// mkdirAllReadable creates dir and any missing parents below root with mode
// 0755, whatever the umask is.
func mkdirAllReadable(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	cur := root
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "." || seg == "" {
			continue
		}
		cur = filepath.Join(cur, seg)
		err := os.Mkdir(cur, 0o755) //nolint:gosec // G301: readable by the unprivileged sandbox user by design
		if err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err == nil {
			if cerr := os.Chmod(cur, 0o755); cerr != nil && runtime.GOOS != "windows" { //nolint:gosec // G302: see above
				return cerr
			}
		}
	}
	return nil
}

// ExportDir creates a world-readable directory named "src" inside parent
// (which stays private to the operator) for Archive to export into. The
// sandbox user must be able to traverse and read the export, and a
// directory made by os.MkdirTemp is mode 0700.
func ExportDir(parent string) (string, error) {
	dir := filepath.Join(parent, "src")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // G301: readable by the unprivileged sandbox user by design
		return "", err
	}
	if err := os.Chmod(dir, 0o755); err != nil && runtime.GOOS != "windows" { //nolint:gosec // G302: see above
		return "", err
	}
	return dir, nil
}
