// Package walk lists the files of a target safely. It is the only way
// Spackle enumerates target source, so the safety rules live in one place:
// never follow a symlink out of the root, never read huge or binary files,
// and skip dependency and VCS directories.
package walk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxFileSize is the largest file Spackle reads as source. Larger files are
// reported as skipped, not silently ignored.
const MaxFileSize = 1 << 20

// File is one readable text file in the target.
type File struct {
	Rel  string // forward-slash path relative to the root
	Abs  string // absolute path on this machine
	Size int64
	Lang string // see LangOf; empty when not recognized
}

// Skip records a path that was not listed, and why.
type Skip struct {
	Rel    string
	Reason string
}

// skipDirs are never descended into.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".spackle": true,
	"node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true,
	"dist": true, "build": true, "target": true, ".next": true, ".nuxt": true,
	".terraform": true, ".idea": true, ".vscode": true, "coverage": true,
}

var langByExt = map[string]string{
	".go": "go", ".py": "python", ".pyw": "python",
	".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
	".java": "java", ".kt": "kotlin", ".cs": "csharp", ".rb": "ruby", ".php": "php",
	".rs": "rust", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
	".swift": "swift", ".scala": "scala", ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
	".tf": "terraform", ".tfvars": "terraform", ".hcl": "terraform",
	".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml",
	".html": "html", ".htm": "html", ".sql": "sql", ".env": "dotenv",
	".xml": "xml", ".ini": "ini", ".cfg": "ini", ".conf": "ini", ".properties": "ini",
}

// LangOf returns the language of a path by name and extension. It
// recognizes Dockerfiles ("dockerfile") and dotenv files ("dotenv") by name.
func LangOf(rel string) string {
	base := strings.ToLower(filepath.Base(filepath.FromSlash(rel)))
	switch {
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") || base == "containerfile":
		return "dockerfile"
	case base == ".env" || strings.HasPrefix(base, ".env."):
		return "dotenv"
	}
	return langByExt[filepath.Ext(base)]
}

// Result is the outcome of listing a target.
type Result struct {
	Files   []File
	Skipped []Skip
}

// List returns every readable text file under root, sorted by relative path.
// Problems with individual files are recorded in Skipped; only a problem with
// root itself is an error.
func List(root string) (Result, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Result{}, fmt.Errorf("resolve target %s: %w", root, err)
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return Result{}, fmt.Errorf("target %s cannot be read: %w", root, err)
	}
	info, err := os.Stat(realRoot)
	if err != nil {
		return Result{}, fmt.Errorf("target %s cannot be read: %w", root, err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("target %s is a file; pass the directory that contains it", root)
	}

	var res Result
	skip := func(rel, reason string) { res.Skipped = append(res.Skipped, Skip{Rel: rel, Reason: reason}) }

	err = filepath.WalkDir(realRoot, func(path string, d fs.DirEntry, werr error) error {
		rel := "."
		if path != realRoot {
			r, rerr := filepath.Rel(realRoot, path)
			if rerr != nil {
				return rerr
			}
			rel = filepath.ToSlash(r)
		}
		if werr != nil {
			skip(rel, "unreadable: "+werr.Error())
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != realRoot && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// WalkDir does not follow symlinks. Resolve it ourselves and
			// accept only regular files that stay inside the root.
			resolved, rerr := filepath.EvalSymlinks(path)
			if rerr != nil {
				skip(rel, "broken symlink")
				return nil
			}
			if !Inside(realRoot, resolved) {
				skip(rel, "symlink points outside the target")
				return nil
			}
			st, serr := os.Stat(resolved)
			if serr != nil || !st.Mode().IsRegular() {
				skip(rel, "symlink to a directory or special file")
				return nil
			}
		} else if !d.Type().IsRegular() {
			skip(rel, "not a regular file")
			return nil
		}
		fi, ierr := os.Stat(path)
		if ierr != nil {
			skip(rel, "unreadable: "+ierr.Error())
			return nil
		}
		if fi.Size() > MaxFileSize {
			skip(rel, fmt.Sprintf("larger than %d bytes", MaxFileSize))
			return nil
		}
		binary, berr := looksBinary(path)
		if berr != nil {
			skip(rel, "unreadable: "+berr.Error())
			return nil
		}
		if binary {
			return nil // binaries are expected and not worth a note
		}
		res.Files = append(res.Files, File{Rel: rel, Abs: path, Size: fi.Size(), Lang: LangOf(rel)})
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("walk target %s: %w", root, err)
	}
	sort.Slice(res.Files, func(i, j int) bool { return res.Files[i].Rel < res.Files[j].Rel })
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].Rel < res.Skipped[j].Rel })
	return res, nil
}

// Inside reports whether path is root or lies beneath it. Both must be
// absolute and already cleaned of symlinks by the caller.
func Inside(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

// Resolve turns a path supplied by an untrusted party (a model, a scanner)
// into an absolute path inside root, or returns an error. It rejects
// absolute paths, parent traversal, and symlinks that leave the root.
func Resolve(root, untrusted string) (string, error) {
	if untrusted == "" {
		return "", fmt.Errorf("path is empty")
	}
	clean := filepath.FromSlash(strings.ReplaceAll(untrusted, `\`, "/"))
	if filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" || strings.HasPrefix(clean, string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is absolute; only paths relative to the target are allowed", untrusted)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("target root: %w", err)
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return "", fmt.Errorf("target root: %w", err)
	}
	joined := filepath.Join(realRoot, clean)
	if !Inside(realRoot, joined) {
		return "", fmt.Errorf("path %q leaves the target", untrusted)
	}
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path %q does not exist in the target", untrusted)
		}
		return "", fmt.Errorf("path %q: %w", untrusted, err)
	}
	if !Inside(realRoot, resolved) {
		return "", fmt.Errorf("path %q resolves outside the target through a symlink", untrusted)
	}
	return resolved, nil
}

// ReadText reads a listed file and normalizes CRLF to LF so that line
// numbers and quoted lines are the same on every platform.
func ReadText(abs string) (string, error) {
	fi, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if fi.Size() > MaxFileSize {
		return "", fmt.Errorf("%s is larger than %d bytes", abs, MaxFileSize)
	}
	b, err := os.ReadFile(abs) //nolint:gosec // callers pass paths from List or Resolve
	if err != nil {
		return "", err
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	return strings.ReplaceAll(string(b), "\r\n", "\n"), nil
}

func looksBinary(path string) (bool, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from walking the target root
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 8000)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	return bytes.IndexByte(buf[:n], 0) >= 0, nil
}
