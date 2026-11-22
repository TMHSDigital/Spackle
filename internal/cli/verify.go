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
	fs := newFlagSet(env, "verify", "<run-id>", "Re-run a run's stored proofs of concept against the code as it is now.\nA proof that no longer succeeds marks its finding fixed. Proofs run only in the sandbox,\nso a container runtime is required. The run id may be a unique prefix, or \"latest\".")
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
	still := 0
	for _, o := range outcomes {
		state := "fixed"
		if o.Reproduces {
			state = "STILL REPRODUCES"
			still++
		}
		fmt.Fprintf(env.Stdout, "%s  %-17s %s\n    %s\n", o.FindingID, state, o.Title, o.Note)
	}
	fmt.Fprintf(env.Stdout, "\n%d proof(s) re-run: %d still reproduce, %d no longer do.\n", len(outcomes), still, len(outcomes)-still)
	if still > 0 {
		return ExitFindings
	}
	return ExitOK
}
