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
	configPath    string
	provider      string
	model         string
	baseURL       string
	budgetTokens  int
	budgetUSD     float64
	allowUnpriced bool
	maxFindings   int
	offline       bool
	fix           bool
	noFix         bool
	pr            bool
	authorize     string
	format        string
	out           string
	yes           bool
	failOn        string
	exclude       listFlag
}

// listFlag collects the values of a flag that may be given more than once.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// flagGroup names a set of related flags. A command registers only the
// groups it reads, so a flag that would be ignored is refused as unknown
// (exit 2) instead of being accepted and doing nothing.
type flagGroup uint

const (
	flagsConfig  flagGroup = 1 << iota // --config
	flagsModel                         // --provider, --model, --base-url
	flagsBudget                        // --budget-tokens, --budget-usd, --max-findings
	flagsOffline                       // --offline
	flagsFix                           // --fix, --no-fix
	flagsPR                            // --pr
	flagsScope                         // --authorize
	flagsOutput                        // --format, --out
	flagsYes                           // --yes
	flagsFailOn                        // --fail-on
	flagsExclude                       // --exclude

	flagsAll = flagsConfig | flagsModel | flagsBudget | flagsOffline | flagsFix | flagsPR |
		flagsScope | flagsOutput | flagsYes | flagsFailOn | flagsExclude
)

// register adds every shared flag. It is for commands that run a scan.
func (g *globalFlags) register(fs *flag.FlagSet) { g.registerGroups(fs, flagsAll) }

// registerGroups adds the flags of the given groups.
func (g *globalFlags) registerGroups(fs *flag.FlagSet, groups flagGroup) {
	has := func(group flagGroup) bool { return groups&group != 0 }
	if has(flagsConfig) {
		fs.StringVar(&g.configPath, "config", "", "`file` to read instead of ./spackle.toml")
	}
	if has(flagsModel) {
		fs.StringVar(&g.provider, "provider", "", "model `provider`: anthropic, openai, openai-compatible or ollama")
		fs.StringVar(&g.model, "model", "", "model `name` for the provider")
		fs.StringVar(&g.baseURL, "base-url", "", "endpoint `url` for the openai-compatible and ollama providers")
	}
	if has(flagsBudget) {
		fs.IntVar(&g.budgetTokens, "budget-tokens", 0, "hard cap on total model `tokens` for the run")
		fs.Float64Var(&g.budgetUSD, "budget-usd", 0, "hard cap on model spend in `USD` for the run")
		fs.BoolVar(&g.allowUnpriced, "allow-unpriced", false, "with --yes, run a model that has no known price although a dollar cap is set; the dollar cap is then not enforced")
		fs.IntVar(&g.maxFindings, "max-findings", 0, "report at most `n` findings, highest severity first")
	}
	if has(flagsOffline) {
		fs.BoolVar(&g.offline, "offline", false, "refuse any connection that would leave this machine")
	}
	if has(flagsFix) {
		fs.BoolVar(&g.fix, "fix", false, "write and verify fixes (the default)")
		fs.BoolVar(&g.noFix, "no-fix", false, "find and explain only; do not write fixes")
	}
	if has(flagsPR) {
		fs.BoolVar(&g.pr, "pr", false, "push the fix branch and open a pull request")
	}
	if has(flagsScope) {
		fs.StringVar(&g.authorize, "authorize", "", "scope `file` that authorizes a live target")
	}
	if has(flagsOutput) {
		fs.StringVar(&g.format, "format", "", "report `formats`, comma separated: terminal, markdown, html, json, sarif")
		fs.StringVar(&g.out, "out", "", "`directory` to write reports into")
	}
	if has(flagsYes) {
		fs.BoolVar(&g.yes, "yes", false, "do not prompt; authorization and budgets must come from flags or config")
	}
	if has(flagsExclude) {
		fs.Var(&g.exclude, "exclude", "`glob` of paths not to scan, relative to the target; may be repeated")
	}
	if has(flagsFailOn) {
		fs.StringVar(&g.failOn, "fail-on", "", "lowest `severity` that makes the command exit 1: critical, high, medium, low or never")
	}
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
		cfg.Budget.USDSet = true
	}
	if g.allowUnpriced {
		cfg.Budget.AllowUnpriced = true
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
	cfg.Scan.Exclude = append(cfg.Scan.Exclude, g.exclude...)
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
