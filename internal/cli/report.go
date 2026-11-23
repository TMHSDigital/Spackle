package cli

import (
	"fmt"

	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/report"
)

func runReport(env Env, args []string) int {
	fs := newFlagSet(env, "report", "<run-id>", "Render a stored run in any format.\nThe report is rebuilt from the run's ledger alone, so it is the same every time.\nThe run id may be a unique prefix, or \"latest\".")
	var g globalFlags
	g.registerGroups(fs, flagsConfig|flagsOutput)
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
	if err := emit(env, cfg, run, runDir); err != nil {
		fmt.Fprintf(env.Stderr, "spackle report: %v\n", err)
		return ExitError
	}
	return ExitOK
}
