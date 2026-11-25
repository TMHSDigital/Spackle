package cli

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/report"
)

func runReport(env Env, args []string) int {
	fs := newFlagSet(env, "report", "<run-id>", "Render a stored run in any format.\nThe report is rebuilt from the run's ledger alone, so it is the same every time.\nThe run id may be a unique prefix, or \"latest\".")
	var g globalFlags
	g.registerGroups(fs, flagsConfig|flagsOutput)
	var only listFlag
	fs.Var(&only, "finding", "render only the finding with this `id` (SPK-XXXXXXXX); may be repeated")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 1 {
		fmt.Fprintf(env.Stderr, "spackle report: expected one run id, got %d.\n", len(pos))
		return ExitUsage
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle report: %v\n", err)
		return ExitUsage
	}
	id := "latest"
	if len(pos) == 1 {
		id = pos[0]
	}
	runDir, err := engine.ResolveRun(cfg.StateDir, id)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle report: %v\n", err)
		return ExitUsage
	}
	run, err := report.Load(runDir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle report: %v\n", err)
		return ExitError
	}
	if len(only) > 0 {
		if run, err = onlyFindings(run, only); err != nil {
			fmt.Fprintf(env.Stderr, "spackle report: %v\n", err)
			return ExitUsage
		}
		// The stored reports hold every finding, so a selection is printed,
		// or written under --out, and never pointed at the stored files.
		if g.format == "" && cfg.Output.Dir == "" {
			cfg.Output.Formats = []string{"terminal"}
		}
		if cfg.Output.Dir != "" && !writesFile(cfg.Output.Formats) {
			fmt.Fprintln(env.Stderr, "spackle report: --out writes report files, and the formats asked for are only printed. Add --format with a file format: markdown, json, sarif or html.")
			return ExitUsage
		}
		if len(cfg.Output.Formats) > 1 && cfg.Output.Dir == "" {
			fmt.Fprintln(env.Stderr, "spackle report: with --finding, give one --format to print, or --out to write several.")
			return ExitUsage
		}
	}
	if err := emit(env, cfg, run, runDir); err != nil {
		fmt.Fprintf(env.Stderr, "spackle report: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// writesFile reports whether any of the formats is written to a file under
// --out. The terminal format is always printed instead.
func writesFile(formats []string) bool {
	for _, format := range formats {
		if ext, _ := report.Ext(format); ext != "txt" {
			return true
		}
	}
	return false
}

// findingIDRe is the form of a finding id.
var findingIDRe = regexp.MustCompile(`^SPK-[0-9A-F]{8}$`)

// onlyFindings keeps the findings of run named in ids, in report order. An
// id that is malformed or not in the run is an error.
func onlyFindings(run report.Run, ids []string) (report.Run, error) {
	want := map[string]bool{}
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !findingIDRe.MatchString(id) {
			return run, fmt.Errorf("--finding %q is not a finding id: ids look like SPK-1A2B3C4D", id)
		}
		want[id] = true
	}
	var kept []finding.Finding
	for _, f := range run.Findings {
		if want[f.ID] {
			kept = append(kept, f)
			delete(want, f.ID)
		}
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for id := range want {
			missing = append(missing, id)
		}
		sort.Strings(missing)
		return run, fmt.Errorf("run %s has no finding %s", run.ID, strings.Join(missing, ", "))
	}
	run.Findings = kept
	return run, nil
}
