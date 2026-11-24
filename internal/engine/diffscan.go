package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
)

// uncommitted is the diff base of a --changed scan, as the report names it.
const uncommitted = "the last commit (uncommitted changes)"

// diffBase returns what a diff scan compares against: the --since revision,
// uncommitted for --changed, or "" for a full scan.
func diffBase(opts Options) string {
	if opts.Changed {
		return uncommitted
	}
	return opts.Since
}

// changedSince returns the set of files a diff scan covers: the files under
// root that were added or changed since rev. The error says what to do,
// because the usual cause is a CI checkout that did not fetch the base.
func changedSince(ctx context.Context, root, rev string) (map[string]bool, error) {
	flag := "--since"
	if rev == uncommitted {
		flag = "--changed"
	}
	if !gitx.HasTracked(ctx, root) {
		return nil, fmt.Errorf("%s needs a git repository, and %s has no tracked files", flag, root)
	}
	var files []string
	var err error
	if rev == uncommitted {
		files, err = gitx.ChangedUncommitted(ctx, root)
	} else {
		files, err = gitx.ChangedSince(ctx, root, rev)
	}
	if err != nil {
		if errors.Is(err, gitx.ErrNotRepo) {
			return nil, fmt.Errorf("%s needs a git repository, and %s is not inside one", flag, root)
		}
		if rev == uncommitted {
			return nil, fmt.Errorf("--changed: git could not list the changes against HEAD (%w)", err)
		}
		return nil, fmt.Errorf("--since %s: git could not compare that revision with HEAD (%w). Check the name, and in CI fetch the base commit first, for example with fetch-depth: 0", rev, err)
	}
	changed := make(map[string]bool, len(files))
	for _, f := range files {
		changed[f] = true
	}
	return changed, nil
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
