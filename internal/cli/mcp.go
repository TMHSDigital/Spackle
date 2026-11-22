package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/mcp"
	"github.com/TMHSDigital/spackle/internal/version"
)

// rootList collects the repeatable --root flag.
type rootList []string

func (r *rootList) String() string { return strings.Join(*r, ", ") }

func (r *rootList) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("a root cannot be empty: give a directory")
	}
	*r = append(*r, v)
	return nil
}

// runMCP serves the MCP tools on standard input and output. It registers
// its own short flag list instead of the shared one: every limit a client
// works within is fixed here by the operator, and flags such as --yes or
// --out have no meaning for a server.
func runMCP(env Env, args []string) int {
	fs := newFlagSet(env, "mcp", "", "Serve Spackle tools over MCP on stdin and stdout, for AI clients.\nThe client may scan only local directories inside a --root. The model, the\nbudgets and the state directory come from the config file, never from the client.\nStandard output carries protocol messages only; status goes to standard error.")
	var (
		roots      rootList
		configPath string
		allowModel bool
		offline    bool
	)
	fs.Var(&roots, "root", "`directory` the client may scan; repeat for more (default: the working directory)")
	fs.StringVar(&configPath, "config", "", "`file` to read instead of ./spackle.toml")
	fs.BoolVar(&allowModel, "allow-model", false, "let scans call the configured model and spend within its budgets")
	fs.BoolVar(&offline, "offline", false, "refuse any connection that would leave this machine")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 0 {
		fmt.Fprintf(env.Stderr, "spackle mcp: unexpected argument %q.\nThe server takes flags only. Name the directories a client may scan with --root.\n", pos[0])
		return ExitUsage
	}
	cfg, _, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle mcp: %v\n", err)
		return ExitUsage
	}
	if offline {
		cfg.Offline = true
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(env.Stderr, "spackle mcp: %v\n", err)
		return ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err = mcp.Serve(ctx, env.Stdin, env.Stdout, mcp.Options{
		Roots:      roots,
		Config:     cfg,
		AllowModel: allowModel,
		Version:    version.Version,
		Doctor:     mcpDoctor(cfg, allowModel),
		Log:        env.Stderr,
	})
	switch {
	case err == nil, errors.Is(err, context.Canceled):
		return ExitOK
	case errors.Is(err, mcp.ErrOptions):
		fmt.Fprintf(env.Stderr, "spackle mcp: %v\n", err)
		return ExitUsage
	}
	fmt.Fprintf(env.Stderr, "spackle mcp: %v\n", err)
	return ExitError
}

// mcpDoctor adapts the CLI's doctor checks for the MCP doctor tool. Without
// --allow-model the checks run against a config with no model, so a client
// cannot make the server contact a provider, and the model rows are replaced
// by one row that says why no model is used.
func mcpDoctor(cfg config.Config, allowModel bool) func(context.Context) []mcp.Check {
	held := !allowModel && cfg.Model.Configured()
	if !allowModel {
		cfg.Model = config.Model{}
		cfg.Stages = nil
	}
	return func(ctx context.Context) []mcp.Check {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		var out []mcp.Check
		for _, c := range doctorChecks(ctx, cfg) {
			if held && c.area == "Model" {
				continue
			}
			out = append(out, mcp.Check{Area: c.area, Name: c.name, Status: c.status, Note: c.note})
		}
		if held {
			out = append(out, mcp.Check{
				Area: "Model", Name: "provider", Status: "warn",
				Note: "a model is configured but this server was started without --allow-model: scans through MCP run the deterministic stages only",
			})
		}
		return out
	}
}
