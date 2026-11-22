package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/report"
)

// globalFlags are the flags shared by the commands that run or render.
type globalFlags struct {
	configPath   string
	provider     string
	model        string
	baseURL      string
	budgetTokens int
	budgetUSD    float64
	maxFindings  int
	offline      bool
	fix          bool
	noFix        bool
	pr           bool
	authorize    string
	format       string
	out          string
	yes          bool
	failOn       string
}

func (g *globalFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&g.configPath, "config", "", "`file` to read instead of ./spackle.toml")
	fs.StringVar(&g.provider, "provider", "", "model `provider`: anthropic, openai, openai-compatible or ollama")
	fs.StringVar(&g.model, "model", "", "model `name` for the provider")
	fs.StringVar(&g.baseURL, "base-url", "", "endpoint `url` for the openai-compatible and ollama providers")
	fs.IntVar(&g.budgetTokens, "budget-tokens", 0, "hard cap on total model `tokens` for the run")
	fs.Float64Var(&g.budgetUSD, "budget-usd", 0, "hard cap on model spend in `USD` for the run")
	fs.IntVar(&g.maxFindings, "max-findings", 0, "report at most `n` findings, highest severity first")
	fs.BoolVar(&g.offline, "offline", false, "refuse any connection that would leave this machine")
	fs.BoolVar(&g.fix, "fix", false, "write and verify fixes (the default)")
	fs.BoolVar(&g.noFix, "no-fix", false, "find and explain only; do not write fixes")
	fs.BoolVar(&g.pr, "pr", false, "push the fix branch and open a pull request")
	fs.StringVar(&g.authorize, "authorize", "", "scope `file` that authorizes a live target")
	fs.StringVar(&g.format, "format", "", "report `formats`, comma separated: terminal, markdown, html, json, sarif")
	fs.StringVar(&g.out, "out", "", "`directory` to write reports into")
	fs.BoolVar(&g.yes, "yes", false, "do not prompt; authorization and budgets must come from flags or config")
	fs.StringVar(&g.failOn, "fail-on", "", "lowest `severity` that makes the command exit 1: critical, high, medium, low or never")
}

// load reads the config file and applies the flags on top of it.
func (g *globalFlags) load() (config.Config, error) {
	cfg, _, err := config.Load(g.configPath)
	if err != nil {
		return config.Config{}, err
	}
	if g.fix && g.noFix {
		return config.Config{}, fmt.Errorf("--fix and --no-fix were both given: choose one")
	}
	if g.provider != "" {
		// Choosing a provider on the command line replaces the configured
		// model wholesale, so a stale model name is never sent to it.
		if g.provider != cfg.Model.Provider {
			cfg.Model = config.Model{}
		}
		cfg.Model.Provider = g.provider
	}
	if g.model != "" {
		cfg.Model.Model = g.model
	}
	if g.baseURL != "" {
		cfg.Model.BaseURL = g.baseURL
	}
	if g.budgetTokens != 0 {
		cfg.Budget.Tokens = g.budgetTokens
	}
	if g.budgetUSD != 0 {
		cfg.Budget.USD = g.budgetUSD
	}
	if g.maxFindings != 0 {
		cfg.Budget.MaxFindings = g.maxFindings
	}
	if g.offline {
		cfg.Offline = true
	}
	if g.noFix {
		off := false
		cfg.Fix.Enabled = &off
	}
	if g.fix {
		on := true
		cfg.Fix.Enabled = &on
	}
	if g.pr {
		cfg.Fix.PR = true
	}
	if g.format != "" {
		cfg.Output.Formats = splitList(g.format)
	}
	if g.out != "" {
		cfg.Output.Dir = g.out
	}
	if g.failOn != "" {
		cfg.Output.FailOn = g.failOn
	}
	for _, f := range cfg.Output.Formats {
		if _, ok := report.Ext(f); !ok {
			return config.Config{}, fmt.Errorf("unknown report format %q: choose from %s", f, strings.Join(report.Formats(), ", "))
		}
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// wantColor reports whether ANSI color should be written to w: only to a
// real terminal, and never when NO_COLOR is set.
func wantColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		// The legacy console prints escape codes literally. Windows
		// Terminal and the VS Code terminal announce themselves.
		return os.Getenv("WT_SESSION") != "" || os.Getenv("TERM_PROGRAM") != "" || os.Getenv("TERM") != ""
	}
	return true
}
