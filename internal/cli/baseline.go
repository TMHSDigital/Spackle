package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/report"
)

// defaultBaselineFile is where spackle baseline writes without --out.
const defaultBaselineFile = ".spackle-baseline.json"

func runBaseline(env Env, args []string) int {
	fs := newFlagSet(env, "baseline", "[run-id]", "Write a baseline file that accepts every unresolved finding of a stored run.\nA scan with --baseline (or [scan] baseline) still reports a finding that matches an entry,\nas accepted, but does not fail on it. Entries match by the finding's fingerprint, so code\nthat only moved stays accepted. The run id may be a unique prefix, or \"latest\" (the default).\nWhen the file exists, the reason and expiry of entries that still match are kept.")
	var g globalFlags
	g.registerGroups(fs, flagsConfig)
	out := fs.String("out", defaultBaselineFile, "`file` to write; - writes to stdout")
	reason := fs.String("reason", "", "`text` recorded as the reason of each new entry")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 1 {
		fmt.Fprintf(env.Stderr, "spackle baseline: expected one run id, got %d.\n", len(pos))
		return ExitUsage
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle baseline: %v\n", err)
		return ExitUsage
	}
	id := "latest"
	if len(pos) == 1 {
		id = pos[0]
	}
	runDir, err := engine.ResolveRun(cfg.StateDir, id)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle baseline: %v\n", err)
		return ExitUsage
	}
	run, err := report.Load(runDir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle baseline: %v\n", err)
		return ExitError
	}
	b := finding.NewBaseline(run.Findings, *reason)
	// A finding the baseline already accepted is accepted in the run, not
	// open, so it is carried over from the existing file below.
	kept := 0
	if *out != "-" {
		old, lerr := finding.LoadBaseline(*out)
		switch {
		case lerr == nil:
			b, kept = mergeBaseline(b, old, run.Findings)
		case !errors.Is(lerr, os.ErrNotExist):
			fmt.Fprintf(env.Stderr, "spackle baseline: %v. Move it away or choose another --out.\n", lerr)
			return ExitUsage
		}
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle baseline: %v\n", err)
		return ExitError
	}
	data = append(data, '\n')
	if *out == "-" {
		_, _ = env.Stdout.Write(data)
		return ExitOK
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // the operator chose the file, and it is meant to be committed
		fmt.Fprintf(env.Stderr, "spackle baseline: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(env.Stdout, "Wrote %d entries from run %s to %s", len(b.Entries), run.ID, filepath.ToSlash(*out))
	if kept > 0 {
		fmt.Fprintf(env.Stdout, " (%d kept their reason and expiry from the existing file)", kept)
	}
	fmt.Fprintf(env.Stdout, ".\nScan with --baseline %s, or set baseline under [scan] in spackle.toml.\n", filepath.ToSlash(*out))
	return ExitOK
}

// mergeBaseline adds to b the entries of old that still accept a finding
// of the run (accepted ones are not in b, which holds only unresolved
// findings), and gives entries of b that old already had old's reason and
// expiry. Entries of old that match nothing in the run are dropped. It
// returns the merged baseline and how many entries came from old.
func mergeBaseline(b, old finding.Baseline, fs []finding.Finding) (finding.Baseline, int) {
	kept := 0
	for i, e := range b.Entries {
		probe := finding.Finding{ID: e.ID, Fingerprint: e.Fingerprint}
		for _, o := range old.Entries {
			if o.Matches(probe) {
				b.Entries[i].Reason, b.Entries[i].Expires = o.Reason, o.Expires
				kept++
				break
			}
		}
	}
	for _, f := range fs {
		if f.Status != finding.StatusAccepted {
			continue
		}
		for _, o := range old.Entries {
			if o.Matches(f) {
				o.ID, o.Fingerprint, o.Title, o.Location = f.ID, f.Fingerprint, f.Title, f.Location.String()
				b.Entries = append(b.Entries, o)
				kept++
				break
			}
		}
	}
	return b, kept
}
