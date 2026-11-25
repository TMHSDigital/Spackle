package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/report"
)

// verifyOutcome is one outcome in the JSON output of verify.
type verifyOutcome struct {
	FindingID string `json:"finding_id"`
	Title     string `json:"title"`
	State     string `json:"state"` // fixed|still_reproduces|not_verified
	Note      string `json:"note"`
}

// verifyEngine is engine.Verify. Tests replace it to check the output
// without a container runtime.
var verifyEngine = engine.Verify

func runVerify(env Env, args []string) int {
	fs := newFlagSet(env, "verify", "<run-id>", "Re-run a run's stored proofs of concept against the code as it is now.\nA proof that no longer succeeds marks its finding fixed. Proofs run only in the sandbox,\nso a container runtime is required. The run id may be a unique prefix, or \"latest\".\n\nOnly a run of a local directory can be verified, not one of a git URL or a running target.\nProofs run against the directory that was scanned. The stored run is updated: outcomes are\nadded to its ledger and its reports are rewritten. Exit code 1 means a proof still succeeds\nor could not be verified.")
	var g globalFlags
	g.registerGroups(fs, flagsConfig|flagsOffline)
	format := fs.String("format", "text", "output `format`: text or json")
	var only listFlag
	fs.Var(&only, "finding", "re-run only the proofs of the finding with this `id` (SPK-XXXXXXXX); may be repeated")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 1 {
		fmt.Fprintf(env.Stderr, "spackle verify: expected one run id, got %d.\n", len(pos))
		return ExitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(env.Stderr, "spackle verify: unknown format %q: choose text or json\n", *format)
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
	var ids []string
	if len(only) > 0 {
		run, lerr := report.Load(runDir)
		if lerr != nil {
			fmt.Fprintf(env.Stderr, "spackle verify: %v\n", lerr)
			return ExitError
		}
		// The same check as report --finding: a malformed id, or one that
		// is not in the run, is a usage error.
		if run, err = onlyFindings(run, only); err != nil {
			fmt.Fprintf(env.Stderr, "spackle verify: %v\n", err)
			return ExitUsage
		}
		for _, f := range run.Findings {
			ids = append(ids, f.ID)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	outcomes, err := verifyEngine(ctx, engine.VerifyOptions{Config: cfg, RunDir: runDir, Progress: env.Stderr, Findings: ids})
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle verify: %v\n", err)
		if errors.Is(err, engine.ErrRefused) {
			return ExitUsage
		}
		return ExitError
	}
	still, unknown := 0, 0
	rows := make([]verifyOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		row := verifyOutcome{FindingID: o.FindingID, Title: o.Title, State: "fixed", Note: o.Note}
		switch {
		case o.Inconclusive:
			row.State = "not_verified"
			unknown++
		case o.Reproduces:
			row.State = "still_reproduces"
			still++
		}
		rows = append(rows, row)
	}
	if *format == "json" {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			Outcomes    []verifyOutcome `json:"outcomes"`
			Still       int             `json:"still"`
			Fixed       int             `json:"fixed"`
			NotVerified int             `json:"not_verified"`
		}{rows, still, len(outcomes) - still - unknown, unknown}); err != nil {
			fmt.Fprintf(env.Stderr, "spackle verify: %v\n", err)
			return ExitError
		}
	} else {
		labels := map[string]string{"fixed": "fixed", "still_reproduces": "STILL REPRODUCES", "not_verified": "NOT VERIFIED"}
		for _, r := range rows {
			fmt.Fprintf(env.Stdout, "%s  %-17s %s\n    %s\n", r.FindingID, labels[r.State], r.Title, r.Note)
		}
		fmt.Fprintf(env.Stdout, "\n%d proof(s) re-run: %d still reproduce, %d no longer do, %d could not be verified.\n", len(outcomes), still, len(outcomes)-still-unknown, unknown)
	}
	// A proof that could not be verified is not a pass.
	if still > 0 || unknown > 0 {
		return ExitFindings
	}
	return ExitOK
}
