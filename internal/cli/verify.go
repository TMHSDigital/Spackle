package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/TMHSDigital/spackle/internal/engine"
)

func runVerify(env Env, args []string) int {
	fs := newFlagSet(env, "verify", "<run-id>", "Re-run a run's stored proofs of concept against the code as it is now.\nA proof that no longer succeeds marks its finding fixed. Proofs run only in the sandbox,\nso a container runtime is required. The run id may be a unique prefix, or \"latest\".\n\nOnly a run of a local directory can be verified, not one of a git URL or a running target.\nProofs run against the directory that was scanned. The stored run is updated: outcomes are\nadded to its ledger and its reports are rewritten. Exit code 1 means a proof still succeeds\nor could not be verified.")
	var g globalFlags
	g.register(fs)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 1 {
		fmt.Fprintf(env.Stderr, "spackle verify: expected one run id, got %d.\n", len(pos))
		return ExitUsage
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle verify: %v\n", err)
		return ExitUsage
	}
	id := "latest"
	if len(pos) == 1 {
		id = pos[0]
	}
	runDir, err := engine.ResolveRun(cfg.StateDir, id)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle verify: %v\n", err)
		return ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	outcomes, err := engine.Verify(ctx, engine.VerifyOptions{Config: cfg, RunDir: runDir, Progress: env.Stderr})
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle verify: %v\n", err)
		if errors.Is(err, engine.ErrRefused) {
			return ExitUsage
		}
		return ExitError
	}
	still, unknown := 0, 0
	for _, o := range outcomes {
		state := "fixed"
		switch {
		case o.Inconclusive:
			state = "NOT VERIFIED"
			unknown++
		case o.Reproduces:
			state = "STILL REPRODUCES"
			still++
		}
		fmt.Fprintf(env.Stdout, "%s  %-17s %s\n    %s\n", o.FindingID, state, o.Title, o.Note)
	}
	fmt.Fprintf(env.Stdout, "\n%d proof(s) re-run: %d still reproduce, %d no longer do, %d could not be verified.\n", len(outcomes), still, len(outcomes)-still-unknown, unknown)
	// A proof that could not be verified is not a pass.
	if still > 0 || unknown > 0 {
		return ExitFindings
	}
	return ExitOK
}
