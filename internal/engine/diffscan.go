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

// diffScan is what a diff scan compares against, built from the options.
type diffScan struct {
	// flag is the option that asked for it: --since or --changed.
	flag string
	// changed is true for --changed, which lists uncommitted work. rev is
	// the --since revision otherwise.
	changed bool
	rev     string
	// label is what the report says the scan compared against.
	label string
}

// diffBase returns the diff scan the options ask for, or nil for a full
// scan.
func diffBase(opts Options) *diffScan {
	switch {
	case opts.Changed:
		return &diffScan{flag: "--changed", changed: true, label: "the last commit (uncommitted changes)"}
	case opts.Since != "":
		return &diffScan{flag: "--since", rev: opts.Since, label: opts.Since}
	}
	return nil
}

// notLocal is the refusal of a diff scan of something that is not a
// directory, in the words of the flag that asked for it.
func (d *diffScan) notLocal(display string) string {
	if d.changed {
		return fmt.Sprintf("--changed lists the uncommitted work of a local checkout, and %s is not a directory. Scan the directory of your checkout", display)
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
	case !d.changed && !gitx.HasTracked(ctx, root):
		// Uncommitted work needs no tracked file: before the first commit,
		// every file is uncommitted.
		return nil, fmt.Errorf("%s needs a git repository, and %s has no tracked files", d.flag, root)
	}
	var files []string
	var err error
	if d.changed {
		files, err = gitx.ChangedUncommitted(ctx, root, stateDirUnder(root, stateDir)...)
	} else {
		files, err = gitx.ChangedSince(ctx, root, d.rev)
	}
	if err != nil {
		if errors.Is(err, gitx.ErrNotRepo) {
			return nil, fmt.Errorf("%s needs a git repository, and %s is not inside one", d.flag, root)
		}
		if d.changed {
			return nil, fmt.Errorf("--changed: git could not list the changes against HEAD (%w)", err)
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

// keepChanged drops the leads that are not in a changed file. A lead with
// no file cannot be tied to the change and is dropped as well. The note
// says what the diff scan covered and how much it left out, so the report
// does not read as a scan of the whole target.
func keepChanged(leads []seed.Lead, changed map[string]bool, rev string) ([]seed.Lead, string) {
	kept := leads[:0:0]
	for _, l := range leads {
		if changed[l.File] {
			kept = append(kept, l)
		}
	}
	note := fmt.Sprintf("Diff scan against %s: %d changed files. Only leads in those files are reported; %d leads in other files were left out.", rev, len(changed), len(leads)-len(kept))
	return kept, note
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
