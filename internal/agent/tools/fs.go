package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/walk"
)

const (
	maxReadLines   = 400
	maxDirEntries  = 500
	binarySniffLen = 8000
)

// hiddenDirs mirrors the directories walk.List never descends into
// (walk keeps its own list unexported). list_dir hides them so the model
// does not spend its budget in version control and dependency trees. A test
// checks that walk.List skips every name here.
var hiddenDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".spackle": true,
	"node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true,
	"dist": true, "build": true, "target": true, ".next": true, ".nuxt": true,
	".terraform": true, ".idea": true, ".vscode": true, "coverage": true,
}

type readFileArgs struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func (r *Registry) readFileTool() builtin {
	return builtin{
		def: llm.ToolDef{
			Name:        "read_file",
			Description: "Read a text file in the target with line numbers. Returns at most 400 lines per call (default lines 1 to 400); use start_line and end_line to read further.",
			Schema: schema(`"path":{"type":"string","description":"File path relative to the target root, for example app/db.py"},`+
				`"start_line":{"type":"integer","minimum":1,"description":"First line to return, 1-based. Default 1."},`+
				`"end_line":{"type":"integer","minimum":1,"description":"Last line to return. Default start_line + 399."}`, "path"),
		},
		fn: r.readFile,
	}
}

func (r *Registry) readFile(_ context.Context, raw json.RawMessage) (label, text string, err error) {
	var a readFileArgs
	if err := decode(raw, &a); err != nil {
		return "", "", err
	}
	if a.Path == "" {
		return "", "", errors.New("path is required; pass a file path relative to the target root, such as src/app.py")
	}
	abs, rel, err := r.resolve(a.Path)
	if err != nil {
		return "", "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", "", fmt.Errorf("%s cannot be read (%s); check the path with list_dir", rel, reason(err))
	}
	switch {
	case fi.IsDir():
		return "", "", fmt.Errorf("%s is a directory, not a file; use list_dir to see what it contains", rel)
	case !fi.Mode().IsRegular():
		// Devices and pipes can block forever or return unbounded data.
		return "", "", fmt.Errorf("%s is not a regular file and cannot be read; choose another file", rel)
	case fi.Size() > walk.MaxFileSize:
		return "", "", fmt.Errorf("%s is %d bytes, over the %d byte limit for reading; it is probably generated or data, choose another file", rel, fi.Size(), walk.MaxFileSize)
	}
	content, err := r.text(abs)
	if err != nil {
		return "", "", fmt.Errorf("%s cannot be read (%w); check the path with list_dir", rel, err)
	}
	if strings.IndexByte(content[:min(len(content), binarySniffLen)], 0) >= 0 {
		return "", "", fmt.Errorf("%s is a binary file and is not shown; read source or configuration files instead", rel)
	}
	label = "read_file " + rel
	if content == "" {
		return label, "[empty file]\n", nil
	}
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	total := len(lines)

	start := max(a.StartLine, 1)
	if start > total {
		return "", "", fmt.Errorf("start_line %d is past the end of %s, which has %d lines; choose a start_line from 1 to %d", start, rel, total, total)
	}
	end := a.EndLine
	if end == 0 {
		end = start + maxReadLines - 1
	}
	if end < start {
		return "", "", fmt.Errorf("end_line %d is before start_line %d; pass end_line >= start_line, or leave it out", a.EndLine, start)
	}
	end = min(end, start+maxReadLines-1, total)

	var b strings.Builder
	fmt.Fprintf(&b, "[lines %d-%d of %d]\n", start, end, total)
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%4d\t%s\n", i, lines[i-1])
	}
	return label, b.String(), nil
}

type listDirArgs struct {
	Path string `json:"path"`
}

func (r *Registry) listDirTool() builtin {
	return builtin{
		def: llm.ToolDef{
			Name:        "list_dir",
			Description: "List one directory of the target (not recursive). Directories end with /, files show their size. Version control and dependency directories are hidden. At most 500 entries.",
			Schema:      schema(`"path":{"type":"string","description":"Directory path relative to the target root. Default \".\" (the root)."}`),
		},
		fn: r.listDir,
	}
}

func (r *Registry) listDir(_ context.Context, raw json.RawMessage) (label, text string, err error) {
	var a listDirArgs
	if err := decode(raw, &a); err != nil {
		return "", "", err
	}
	if a.Path == "" {
		a.Path = "."
	}
	abs, rel, err := r.resolve(a.Path)
	if err != nil {
		return "", "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", "", fmt.Errorf("%s cannot be read (%s); list the parent directory to check the name", rel, reason(err))
	}
	if !fi.IsDir() {
		return "", "", fmt.Errorf("%s is a file, not a directory; use read_file to read it", rel)
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return "", "", fmt.Errorf("%s cannot be listed (%s); try another directory", rel, reason(err))
	}

	var out []string
	for _, e := range entries {
		name := e.Name()
		line, show := r.describeEntry(rel, e)
		if !show {
			continue
		}
		out = append(out, printable(name)+line)
	}
	shown := rel + "/"
	if rel == "." {
		shown = "./"
	}
	label = "list_dir " + rel
	if len(out) == 0 {
		return label, fmt.Sprintf("[no entries in %s]\n", shown), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%d entries in %s]\n", len(out), shown)
	for i, line := range out {
		if i == maxDirEntries {
			fmt.Fprintf(&b, "[%d more entries not shown; list a subdirectory instead]\n", len(out)-maxDirEntries)
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return label, b.String(), nil
}

// describeEntry returns the text that follows an entry's name, and whether
// the entry is shown at all.
func (r *Registry) describeEntry(dirRel string, e fs.DirEntry) (suffix string, show bool) {
	name := e.Name()
	if e.Type()&fs.ModeSymlink != 0 {
		// Follow a link only through walk.Resolve, so a link that leaves
		// the target is named but never opened or measured.
		child := name
		if dirRel != "." {
			child = dirRel + "/" + name
		}
		abs, err := walk.Resolve(r.env.Root, child)
		if err != nil {
			return " (link that is broken or leaves the target; not readable)", true
		}
		fi, err := os.Stat(abs)
		if err != nil {
			return " (unreadable)", true
		}
		return describeInfo(name, fi)
	}
	fi, err := e.Info()
	if err != nil {
		return " (unreadable)", true
	}
	return describeInfo(name, fi)
}

func describeInfo(name string, fi fs.FileInfo) (suffix string, show bool) {
	switch {
	case fi.IsDir():
		return "/", !hiddenDirs[name]
	case fi.Mode().IsRegular():
		return fmt.Sprintf(" (%d bytes)", fi.Size()), true
	default:
		return " (special file; not readable)", true
	}
}

// printable keeps a file name on one line. Names are target content: on
// some systems they may hold newlines, which would forge extra entries.
func printable(name string) string {
	return strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return '?'
		}
		return c
	}, name)
}
