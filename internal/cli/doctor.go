package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/lang"
	"github.com/TMHSDigital/spackle/internal/mcp"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/version"
)

// check is one line of doctor output.
type check struct {
	area   string
	name   string
	status string // ok|missing|warn|fail
	note   string
}

func runDoctor(env Env, args []string) int {
	fs := newFlagSet(env, "doctor", "", "Check the sandbox runtime, scanners and model configuration.\nMissing optional tools are reported but do not fail the check.")
	var g globalFlags
	g.registerGroups(fs, flagsConfig|flagsModel|flagsOffline)
	format := fs.String("format", "text", "output `format`: text or json")
	if _, err := parseInterleaved(fs, args); err != nil {
		return flagExit(err)
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(env.Stderr, "spackle doctor: unknown format %q: choose text or json\n", *format)
		return ExitUsage
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle doctor: %v\n", err)
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	checks := doctorChecks(ctx, cfg)
	if *format == "json" {
		return doctorJSON(env, checks)
	}
	fmt.Fprintf(env.Stdout, "spackle %s\n\n", version.Version)
	failed := false
	area := ""
	for _, c := range checks {
		if c.area != area {
			if area != "" {
				fmt.Fprintln(env.Stdout)
			}
			area = c.area
			fmt.Fprintln(env.Stdout, area)
		}
		line := fmt.Sprintf("  %-10s %-18s", "["+c.status+"]", c.name)
		if c.note != "" {
			line += " " + c.note
		}
		fmt.Fprintln(env.Stdout, strings.TrimRight(line, " "))
		if c.status == "fail" {
			failed = true
		}
	}
	fmt.Fprintln(env.Stdout)
	if failed {
		fmt.Fprintln(env.Stdout, "Result: a required check failed. Fix the [fail] lines above.")
		return ExitUsage
	}
	fmt.Fprintln(env.Stdout, "Result: ready. Lines marked [missing] are optional and only reduce coverage.")
	return ExitOK
}

// doctorJSON prints the checks for a program to read. The rows have the
// same shape as the MCP doctor tool returns. The exit code is the same as
// for the text form: 2 when a required check failed.
func doctorJSON(env Env, checks []check) int {
	out := struct {
		Version string      `json:"version"`
		Ready   bool        `json:"ready"`
		Checks  []mcp.Check `json:"checks"`
	}{Version: version.Version, Ready: true, Checks: []mcp.Check{}}
	for _, c := range checks {
		out.Checks = append(out.Checks, mcp.Check{Area: c.area, Name: c.name, Status: c.status, Note: c.note})
		if c.status == "fail" {
			out.Ready = false
		}
	}
	enc := json.NewEncoder(env.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(env.Stderr, "spackle doctor: %v\n", err)
		return ExitError
	}
	if !out.Ready {
		return ExitUsage
	}
	return ExitOK
}

func doctorChecks(ctx context.Context, cfg config.Config) []check {
	var out []check

	if gitx.Available() {
		out = append(out, check{"Tools", "git", "ok", "history, worktrees and bisect are available"})
	} else {
		out = append(out, check{"Tools", "git", "missing", "install git for repository URLs, fix branches and bisect"})
	}

	out = append(out, runtimeChecks(ctx, cfg)...)

	for _, s := range seed.Builtin() {
		out = append(out, check{"Seeders", s.Name(), "ok", "built in"})
	}
	for _, s := range seed.External() {
		if cfg.Scan.Scanners != nil && !slices.Contains(cfg.Scan.Scanners, s.Name()) {
			out = append(out, check{"Seeders", s.Name(), "off", engine.DisabledScannerNote})
			continue
		}
		ok, note := s.Available()
		st := "ok"
		if !ok {
			st = "missing"
		}
		out = append(out, check{"Seeders", s.Name(), st, note})
	}

	out = append(out, modelChecks(ctx, cfg)...)
	return out
}

// detectRuntime finds the container runtime. It is the sandbox package's
// own detection, so doctor and a scan cannot disagree about whether proofs
// can run. Tests replace it.
var detectRuntime = sandbox.Detect

func runtimeChecks(ctx context.Context, cfg config.Config) []check {
	if cfg.Sandbox.Runtime == "none" {
		return []check{{"Sandbox", "runtime", "warn", "disabled in config: proofs and fixes will not be run"}}
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rt, err := detectRuntime(cctx, cfg.Sandbox.Runtime)
	if err != nil {
		status := "warn"
		if errors.Is(err, sandbox.ErrNoRuntime) {
			status = "missing"
		}
		return []check{{"Sandbox", "runtime", status, err.Error() + ". Findings are still reported"}}
	}
	checks := []check{{"Sandbox", rt.Name(), "ok", "engine is answering, default network: none"}}
	for _, name := range lang.Names() {
		img := cfg.Sandbox.Images[name]
		if rt.ImagePresent(cctx, img) {
			checks = append(checks, check{"Sandbox", "image " + name, "ok", img})
		} else {
			checks = append(checks, check{"Sandbox", "image " + name, "missing", img + " is not pulled; it is fetched on first use, or run: " + rt.Name() + " pull " + img})
		}
	}
	return checks
}

// modelChecks validates the configured provider. The live round-trip is
// added by doctorProbe when a provider is configured.
func modelChecks(ctx context.Context, cfg config.Config) []check {
	if !cfg.Model.Configured() {
		return []check{{"Model", "provider", "warn", "none configured: scans run the deterministic stages only. See docs/config.md"}}
	}
	var out []check
	seen := map[string]bool{}
	stages := append([]string{"default"}, config.Stages...)
	for _, stage := range stages {
		m := cfg.Model
		if stage != "default" {
			m = cfg.ForStage(stage)
		}
		key := m.Provider + "|" + m.Model + "|" + m.BaseURL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, doctorProbe(ctx, cfg, stage, m)...)
	}
	return out
}
