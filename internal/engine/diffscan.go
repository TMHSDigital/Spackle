package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
)

// The values of Options.DiffScope.
const (
	DiffScopeFile  = "file"
	DiffScopeLines = "lines"
)

// linesScope reports whether a diff scope asks for the changed lines only.
func linesScope(scope string) bool { return scope == DiffScopeLines }

// checkDiffScope refuses a diff scope that is not one of the values, or
// that asks for lines of a scan that is not a diff scan.
func checkDiffScope(opts Options) error {
	switch opts.DiffScope {
	case "", DiffScopeFile, DiffScopeLines:
	default:
		return fmt.Errorf("--diff-scope is %q or %q, not %q", DiffScopeFile, DiffScopeLines, opts.DiffScope)
	}
	if linesScope(opts.DiffScope) && diffBase(opts) == nil {
		return fmt.Errorf("--diff-scope %s narrows a diff scan to the changed lines; give --since, --changed or --staged with it", DiffScopeLines)
	}
	return nil
}

// describeDiffScope names a stored diff scope for a refusal.
func describeDiffScope(scope string) string {
	if linesScope(scope) {
		return "only the changed lines (--diff-scope " + DiffScopeLines + ")"
	}
	return "whole changed files (--diff-scope " + DiffScopeFile + ")"
}

// changedLines returns the changed line ranges of each changed file of a
// diff scan, for --diff-scope lines.
func changedLines(ctx context.Context, root string, d *diffScan, stateDir string) (map[string][]gitx.LineRange, error) {
	var lines map[string][]gitx.LineRange
	var err error
	switch {
	case d.changed:
		lines, err = gitx.ChangedLinesUncommitted(ctx, root, stateDirUnder(root, stateDir)...)
	case d.staged:
		lines, err = gitx.ChangedLinesStaged(ctx, root, stateDirUnder(root, stateDir)...)
	default:
		lines, err = gitx.ChangedLinesSince(ctx, root, d.rev)
	}
	if err != nil {
		return nil, fmt.Errorf("%s with --diff-scope %s: git could not list the changed lines (%w)", d.flag, DiffScopeLines, err)
	}
	return lines, nil
}

// onChangedLines returns the lead filter of --diff-scope lines: a lead is
// kept when its lines meet a changed line of its file. A lead with no line
// is about its file as a whole (a vulnerable dependency in a lockfile, for
// example) and is kept, as in a scan by file.
func onChangedLines(lines map[string][]gitx.LineRange) func(seed.Lead) bool {
	return func(l seed.Lead) bool {
		if l.Line <= 0 {
			return true
		}
		for _, r := range lines[l.File] {
			if r.Overlaps(l.Line, l.EndLine) {
				return true
			}
		}
		return false
	}
}

// diffLinesNote says how many leads in the changed files a scan limited to
// the changed lines left out.
func diffLinesNote(outside int) string {
	return fmt.Sprintf("Only leads on the changed lines are reported (--diff-scope %s): %d leads elsewhere in the changed files were left out.", DiffScopeLines, outside)
}

// diffScan is what a diff scan compares against, built from the options.
type diffScan struct {
	// flag is the option that asked for it: --since or --changed.
	flag string
	// changed is true for --changed, which lists uncommitted work. rev is
	// the --since revision otherwise.
	changed bool
	// staged is true for --staged, which lists what the next commit
	// would contain.
	staged bool
	rev    string
	// label is what the report says the scan compared against.
	label string
}

// diffBase returns the diff scan the options ask for, or nil for a full
// scan.
func diffBase(opts Options) *diffScan {
	switch {
	case opts.Changed:
		return &diffScan{flag: "--changed", changed: true, label: "the last commit (uncommitted changes)"}
	case opts.Staged:
		return &diffScan{flag: "--staged", staged: true, label: "the last commit (staged changes)"}
	case opts.Since != "":
		return &diffScan{flag: "--since", rev: opts.Since, label: opts.Since}
	}
	return nil
}

// notLocal is the refusal of a diff scan of something that is not a
// directory, in the words of the flag that asked for it.
func (d *diffScan) notLocal(display string) string {
	if d.changed || d.staged {
		return fmt.Sprintf("%s lists the uncommitted work of a local checkout, and %s is not a directory. Scan the directory of your checkout", d.flag, display)
	}
	return fmt.Sprintf("--since compares a checkout with a base revision, and %s is not a directory. Clone the repository with the history you need and scan the directory", display)
}

// changedSince returns the set of files a diff scan covers: the files under
// root that were added or changed since the diff base. The error says what
// to do, because the usual cause is a CI checkout that did not fetch the
// base. The state directory, when it is inside root, is never a changed
// file.
func changedSince(ctx context.Context, root string, d *diffScan, stateDir string) (map[string]bool, error) {
	switch {
	case !gitx.Available():
		return nil, fmt.Errorf("%s needs a git repository, and git is not installed", d.flag)
	case !d.changed && !d.staged && !gitx.HasTracked(ctx, root):
		// Uncommitted work needs no tracked file: before the first commit,
		// every file is uncommitted.
		return nil, fmt.Errorf("%s needs a git repository, and %s has no tracked files", d.flag, root)
	}
	var files []string
	var err error
	switch {
	case d.changed:
		files, err = gitx.ChangedUncommitted(ctx, root, stateDirUnder(root, stateDir)...)
	case d.staged:
		files, err = gitx.ChangedStaged(ctx, root, stateDirUnder(root, stateDir)...)
	default:
		files, err = gitx.ChangedSince(ctx, root, d.rev)
	}
	if err != nil {
		if errors.Is(err, gitx.ErrNotRepo) {
			return nil, fmt.Errorf("%s needs a git repository, and %s is not inside one", d.flag, root)
		}
		if d.changed || d.staged {
			return nil, fmt.Errorf("%s: git could not list the changes against HEAD (%w)", d.flag, err)
		}
		return nil, fmt.Errorf("--since %s: git could not compare that revision with HEAD (%w). Check the name, and in CI fetch the base commit first, for example with fetch-depth: 0", d.rev, err)
	}
	changed := make(map[string]bool, len(files))
	for _, f := range files {
		changed[f] = true
	}
	return changed, nil
}

// stateDirUnder returns the state directory relative to root when it is
// inside root, as the one path a listing of root's files leaves out, and
// nothing otherwise.
func stateDirUnder(root, stateDir string) []string {
	abs, err := filepath.Abs(stateDir)
	if err != nil {
		return nil
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil
	}
	return []string{rel}
}

// diffNote says what a diff scan covered and how much it left out, so the
// report does not read as a scan of the whole target. leftOut counts the
// leads the external scanners found in other files; the built-in rules
// read only the changed files, so theirs are never found.
func diffNote(label string, changed, leftOut int) string {
	return fmt.Sprintf("Diff scan against %s: %d changed files. Only leads in those files are reported; %d leads in other files were left out. The built-in rules read only the changed files.", label, changed, leftOut)
}

// changedMap returns the map as the planner of a diff scan sees it: the
// same target, with the files, entry points, trust boundaries and
// infrastructure files narrowed to the changed ones. Intents are checked
// against the file list, so the planner cannot plan for an unchanged file.
func changedMap(m mapper.Map, changed map[string]bool) mapper.Map {
	out := m
	out.Files, out.Entry, out.Boundaries, out.InfraFiles = nil, nil, nil, nil
	for _, f := range m.Files {
		if changed[f.Rel] {
			out.Files = append(out.Files, f)
		}
	}
	for _, e := range m.Entry {
		if changed[e.File] {
			out.Entry = append(out.Entry, e)
		}
	}
	for _, b := range m.Boundaries {
		if changed[b.File] {
			out.Boundaries = append(out.Boundaries, b)
		}
	}
	for _, f := range m.InfraFiles {
		if changed[f] {
			out.InfraFiles = append(out.InfraFiles, f)
		}
	}
	return out
}

// stagedNote says that a --staged scan read the staged files from the
// working tree, and how many of them have unstaged edits that were read
// with them.
func stagedNote(ctx context.Context, root, stateDir string, changed map[string]bool) string {
	note := "The staged files were read from the working tree, not from the index."
	unstaged, err := gitx.UnstagedFiles(ctx, root, stateDirUnder(root, stateDir)...)
	if err != nil {
		return note + " Whether they also have unstaged edits could not be checked."
	}
	n := 0
	for _, f := range unstaged {
		if changed[f] {
			n++
		}
	}
	if n == 0 {
		return note + " None of them has unstaged edits, so what was read is what the commit will contain."
	}
	return fmt.Sprintf("%s %d of them also have unstaged edits, which were read too: stage or stash those edits for a scan of exactly what the commit will contain.", note, n)
}
