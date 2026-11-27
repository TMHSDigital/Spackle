package gitx

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// LineRange is an inclusive range of line numbers, counted from 1.
type LineRange struct {
	Start, End int
}

// WholeFile is the range of a file that has no earlier version to compare
// with, such as an untracked file: every line of it is new.
var WholeFile = LineRange{Start: 1, End: math.MaxInt}

// Overlaps reports whether the lines start to end (inclusive) meet r.
func (r LineRange) Overlaps(start, end int) bool {
	if end < start {
		end = start
	}
	return start <= r.End && end >= r.Start
}

// ChangedLinesSince returns, for the files ChangedSince lists, the lines of
// their current version that were added or changed between the merge base
// of rev and HEAD. A pure deletion marks the two lines it sits between, so
// code next to removed code still counts as touched. A file whose change
// has no lines (a binary file, or a rename with no edit) has no entry.
func ChangedLinesSince(ctx context.Context, dir, rev string) (map[string][]LineRange, error) {
	if rev == "" || strings.HasPrefix(rev, "-") {
		return nil, fmt.Errorf("revision %q is not valid", rev)
	}
	return changedLines(ctx, dir, rev+"...HEAD")
}

// ChangedLinesUncommitted is ChangedLinesSince for the files
// ChangedUncommitted lists: the lines that differ from HEAD, staged or not.
// An untracked file, and every file before the first commit, is WholeFile.
func ChangedLinesUncommitted(ctx context.Context, dir string, exclude ...string) (map[string][]LineRange, error) {
	pathspec := []string{"--", "."}
	for _, e := range exclude {
		pathspec = append(pathspec, ":(exclude)"+filepath.ToSlash(e))
	}
	if _, err := run(ctx, dir, "rev-parse", "--verify", "-q", "HEAD"); err != nil {
		if errors.Is(err, ErrNotRepo) {
			return nil, err
		}
		files, err := ChangedUncommitted(ctx, dir, exclude...)
		if err != nil {
			return nil, err
		}
		out := make(map[string][]LineRange, len(files))
		for _, f := range files {
			out[f] = []LineRange{WholeFile}
		}
		return out, nil
	}
	out, err := changedLines(ctx, dir, "HEAD", pathspec...)
	if err != nil {
		return nil, err
	}
	untracked, err := run(ctx, dir, append([]string{"ls-files", "-z", "--others", "--exclude-standard"}, pathspec...)...)
	if err != nil {
		return nil, err
	}
	for _, f := range splitNUL(untracked) {
		out[f] = []LineRange{WholeFile}
	}
	return out, nil
}

// ChangedLinesStaged is ChangedLinesSince for the files ChangedStaged
// lists: the lines of their staged version that differ from HEAD.
func ChangedLinesStaged(ctx context.Context, dir string, exclude ...string) (map[string][]LineRange, error) {
	return changedLines(ctx, dir, "--cached", excludeSpec(exclude)...)
}

// changedLines runs git diff against spec with no context lines and reads
// the changed line ranges of each file from its hunk headers.
func changedLines(ctx context.Context, dir, spec string, pathspec ...string) (map[string][]LineRange, error) {
	if len(pathspec) == 0 {
		pathspec = []string{"--"}
	}
	// The prefixes and quotePath are set so the repository's configuration
	// cannot change how file names are written. --no-textconv and
	// --no-ext-diff keep it from starting a program, as in changedFiles.
	args := append([]string{"-c", "core.quotePath=false", "diff", "-U0", "--no-color", "--relative", "--no-textconv", "--no-ext-diff",
		"--src-prefix=a/", "--dst-prefix=b/", "--diff-filter=ACMR", spec}, pathspec...)
	out, err := run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	return parseChangedLines(out), nil
}

// hunkHeader matches "@@ -a,b +c,d @@"; a count left out is 1.
var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// parseChangedLines reads the output of git diff -U0. The content lines
// of a hunk are skipped by the counts in its header, never by their first
// characters, so an added line that reads "+++ b/x" or "@@ ..." cannot be
// taken for a header.
func parseChangedLines(out string) map[string][]LineRange {
	res := map[string][]LineRange{}
	lines := strings.Split(out, "\n")
	file := ""
	for i := 0; i < len(lines); i++ {
		ln := strings.TrimSuffix(lines[i], "\r")
		switch {
		case strings.HasPrefix(ln, "diff --git "):
			file = ""
		case file == "" && strings.HasPrefix(ln, "+++ "):
			file = diffPath(ln[len("+++ "):])
		case strings.HasPrefix(ln, "@@ "):
			m := hunkHeader.FindStringSubmatch(ln)
			if m == nil {
				continue
			}
			oldCount, start, newCount := hunkCount(m[2]), atoi(m[3]), hunkCount(m[4])
			if file != "" {
				if newCount > 0 {
					res[file] = append(res[file], LineRange{Start: start, End: start + newCount - 1})
				} else {
					// Lines were only removed, after line start of the new
					// version (0: at the top).
					res[file] = append(res[file], LineRange{Start: max(start, 1), End: start + 1})
				}
			}
			for left := oldCount + newCount; left > 0 && i+1 < len(lines); {
				i++
				if !strings.HasPrefix(lines[i], `\`) { // "\ No newline at end of file"
					left--
				}
			}
		}
	}
	return res
}

// diffPath turns the name on a "+++ " line into a path relative to the
// diff, or "" for /dev/null. git quotes a name with unusual characters in
// C style, prefix included.
func diffPath(name string) string {
	if strings.HasPrefix(name, `"`) {
		if u, err := strconv.Unquote(name); err == nil {
			name = u
		}
	}
	rest, ok := strings.CutPrefix(name, "b/")
	if !ok {
		return ""
	}
	return rest
}

func hunkCount(s string) int {
	if s == "" {
		return 1
	}
	return atoi(s)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
