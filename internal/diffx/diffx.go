// Package diffx produces unified diffs. The fixer asks a model for the new
// content of a file and Spackle computes the patch itself, because patches
// written by a model are frequently malformed (wrong hunk counts, invented
// context) while a computed diff always applies.
package diffx

import (
	"fmt"
	"strings"
)

// contextLines is how many unchanged lines surround each change.
const contextLines = 3

// Unified returns a git-style unified diff that turns before into after for
// the file at path (forward slashes, relative to the repository root). It
// returns "" when the contents are equal. The diff is accepted by
// "git apply".
func Unified(path, before, after string) string {
	if before == after {
		return ""
	}
	a, aNoEOL := splitLines(before)
	b, bNoEOL := splitLines(after)
	// A last line with and without a trailing newline is a different line
	// to a patch tool even though its text is the same. Mark it so the diff
	// algorithm sees the difference; printing uses the unmarked text.
	ops := diffLines(markNoEOL(a, aNoEOL), markNoEOL(b, bNoEOL))

	var out strings.Builder
	fmt.Fprintf(&out, "diff --git a/%s b/%s\n", path, path)
	switch {
	case before == "":
		out.WriteString("new file mode 100644\n")
		fmt.Fprintf(&out, "--- /dev/null\n+++ b/%s\n", path)
	case after == "":
		out.WriteString("deleted file mode 100644\n")
		fmt.Fprintf(&out, "--- a/%s\n+++ /dev/null\n", path)
	default:
		fmt.Fprintf(&out, "--- a/%s\n+++ b/%s\n", path, path)
	}

	for _, h := range hunks(ops) {
		aStart, bStart := h.aStart+1, h.bStart+1
		// Unified format: a zero-length side is written with the line
		// before it, and line 0 when the file is empty.
		if h.aLen == 0 {
			aStart = h.aStart
		}
		if h.bLen == 0 {
			bStart = h.bStart
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", aStart, h.aLen, bStart, h.bLen)
		for _, op := range h.ops {
			switch op.kind {
			case opEqual:
				out.WriteString(" " + a[op.ai] + "\n")
				if aNoEOL && op.ai == len(a)-1 && bNoEOL && op.bi == len(b)-1 {
					out.WriteString("\\ No newline at end of file\n")
				}
			case opDelete:
				out.WriteString("-" + a[op.ai] + "\n")
				if aNoEOL && op.ai == len(a)-1 {
					out.WriteString("\\ No newline at end of file\n")
				}
			case opInsert:
				out.WriteString("+" + b[op.bi] + "\n")
				if bNoEOL && op.bi == len(b)-1 {
					out.WriteString("\\ No newline at end of file\n")
				}
			}
		}
	}
	return out.String()
}

func markNoEOL(lines []string, noEOL bool) []string {
	if !noEOL || len(lines) == 0 {
		return lines
	}
	marked := make([]string, len(lines))
	copy(marked, lines)
	marked[len(marked)-1] += "\x00no-eol"
	return marked
}

// Stat counts added and removed lines in a unified diff.
func Stat(diff string) (added, removed int) {
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
		case strings.HasPrefix(line, "+"):
			added++
		case strings.HasPrefix(line, "-"):
			removed++
		}
	}
	return added, removed
}

// splitLines splits text into lines without their terminators and reports
// whether the last line lacked a trailing newline.
func splitLines(s string) (lines []string, noEOL bool) {
	if s == "" {
		return nil, false
	}
	noEOL = !strings.HasSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n"), noEOL
}

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type op struct {
	kind   opKind
	ai, bi int // index into a for equal and delete; into b for equal and insert
}

// diffLines computes an edit script with a longest-common-subsequence
// table, after trimming the common prefix and suffix. Source files handled
// here are capped at 1 MiB by the file walker, so the table stays small.
func diffLines(a, b []string) []op {
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	am, bm := a[prefix:len(a)-suffix], b[prefix:len(b)-suffix]

	var ops []op
	for i := 0; i < prefix; i++ {
		ops = append(ops, op{opEqual, i, i})
	}

	n, m := len(am), len(bm)
	// lcs[i][j] is the LCS length of am[i:] and bm[j:].
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case am[i] == bm[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case am[i] == bm[j]:
			ops = append(ops, op{opEqual, prefix + i, prefix + j})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, op{opDelete, prefix + i, 0})
			i++
		default:
			ops = append(ops, op{opInsert, 0, prefix + j})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{opDelete, prefix + i, 0})
	}
	for ; j < m; j++ {
		ops = append(ops, op{opInsert, 0, prefix + j})
	}
	for k := 0; k < suffix; k++ {
		ops = append(ops, op{opEqual, len(a) - suffix + k, len(b) - suffix + k})
	}
	return ops
}

type hunk struct {
	aStart, bStart int // 0-based index of the first line on each side
	aLen, bLen     int
	ops            []op
}

// hunks groups an edit script into hunks with context, merging changes
// whose context would overlap.
func hunks(ops []op) []hunk {
	var out []hunk
	i := 0
	for i < len(ops) {
		if ops[i].kind == opEqual {
			i++
			continue
		}
		start := i - contextLines
		if start < 0 {
			start = 0
		}
		end := i
		last := i // index of the last change in this hunk
		for end < len(ops) {
			if ops[end].kind != opEqual {
				last = end
			} else if end-last > 2*contextLines {
				break
			}
			end++
		}
		stop := last + contextLines + 1
		if stop > len(ops) {
			stop = len(ops)
		}
		h := hunk{ops: ops[start:stop]}
		// Position: count lines on each side that precede the hunk.
		for _, o := range ops[:start] {
			if o.kind != opInsert {
				h.aStart++
			}
			if o.kind != opDelete {
				h.bStart++
			}
		}
		for _, o := range h.ops {
			if o.kind != opInsert {
				h.aLen++
			}
			if o.kind != opDelete {
				h.bLen++
			}
		}
		out = append(out, h)
		i = stop
	}
	return out
}
