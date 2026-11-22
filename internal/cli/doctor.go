package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/gitx"
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
	g.register(fs)
	if _, err := parseInterleaved(fs, args); err != nil {
		return flagExit(err)
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(env.Stderr, "spackle doctor: %v\n", err)
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	checks := doctorChecks(ctx, cfg)
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

func runtimeChecks(ctx context.Context, cfg config.Config) []check {
	if cfg.Sandbox.Runtime == "none" {
		return []check{{"Sandbox", "runtime", "warn", "disabled in config: proofs and fixes will not be run"}}
	}
	candidates := []string{"docker", "podman"}
	if cfg.Sandbox.Runtime != "auto" {
		candidates = []string{cfg.Sandbox.Runtime}
	}
	for _, name := range candidates {
		if _, err := exec.LookPath(name); err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, err := exec.CommandContext(cctx, name, "version", "--format", "{{.Server.Version}}").Output() //nolint:gosec // fixed program names, argument vector
		cancel()
		if err != nil {
			return []check{{"Sandbox", name, "warn", "installed but the engine is not answering: start it (for example Docker Desktop) to run proofs"}}
		}
		checks := []check{{"Sandbox", name, "ok", "engine " + strings.TrimSpace(string(out)) + ", default network: none"}}
		for _, lang := range []string{"go", "python", "javascript"} {
			img := cfg.Sandbox.Images[lang]
			ictx, icancel := context.WithTimeout(ctx, 10*time.Second)
			ierr := exec.CommandContext(ictx, name, "image", "inspect", "--format", "{{.Id}}", img).Run() //nolint:gosec // fixed program, image name from config
			icancel()
			if ierr != nil {
				checks = append(checks, check{"Sandbox", "image " + lang, "missing", img + " is not pulled; it is fetched on first use, or run: " + name + " pull " + img})
			} else {
				checks = append(checks, check{"Sandbox", "image " + lang, "ok", img})
			}
		}
		return checks
	}
	return []check{{"Sandbox", "runtime", "missing", "no Docker or Podman found: findings are still reported, but nothing is demonstrated or fix-verified"}}
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

// keyEnv returns the environment variable that holds the key for a model.
func keyEnv(m config.Model) string {
	if m.APIKeyEnv != "" {
		return m.APIKeyEnv
	}
	return config.DefaultKeyEnv(m.Provider)
}

// keyPresent reports whether the model's API key variable is set, without
// ever reading the value into output.
func keyPresent(m config.Model) (name string, ok bool) {
	name = keyEnv(m)
	if name == "" {
		return "", true
	}
	return name, os.Getenv(name) != ""
}
