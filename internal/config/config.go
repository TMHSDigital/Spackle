// Package config loads spackle.toml and merges it with defaults. Flags are
// applied on top by the CLI. API keys are never read from config or flags:
// config only names the environment variable that holds one.
package config

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/TMHSDigital/spackle/internal/lang"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// DefaultFile is the config file looked up in the working directory.
const DefaultFile = "spackle.toml"

// The pipeline stages that can have their own model. The names are config
// keys and are stored in ledgers.
const (
	StagePlanner      = "planner"
	StageInvestigator = "investigator"
	StageProver       = "prover"
	StageReviewer     = "reviewer"
	StageFixer        = "fixer"
	StageMechanical   = "mechanical"
)

// Stages lists the pipeline stages that can have their own model.
var Stages = []string{StagePlanner, StageInvestigator, StageProver, StageReviewer, StageFixer, StageMechanical}

// Provider names.
const (
	ProviderAnthropic        = "anthropic"
	ProviderOpenAI           = "openai"
	ProviderOpenAICompatible = "openai-compatible"
	ProviderOllama           = "ollama"
)

// Config is the whole configuration.
type Config struct {
	Model   Model            `toml:"model"`
	Stages  map[string]Model `toml:"stages"`
	Budget  Budget           `toml:"budget"`
	Scope   Scope            `toml:"scope"`
	Sandbox Sandbox          `toml:"sandbox"`
	Fix     Fix              `toml:"fix"`
	Scan    Scan             `toml:"scan"`
	Test    Test             `toml:"test"`
	Output  Output           `toml:"output"`
	Pricing map[string]Price `toml:"pricing"`
	Offline bool             `toml:"offline"`
	// StateDir is where runs and caches are stored.
	StateDir string `toml:"state_dir"`
}

// Model selects a provider and model.
type Model struct {
	Provider string `toml:"provider"`
	Model    string `toml:"model"`
	BaseURL  string `toml:"base_url"`
	// APIKeyEnv names the environment variable holding the API key.
	APIKeyEnv string `toml:"api_key_env"`
	// MaxOutputTokens caps one completion.
	MaxOutputTokens int `toml:"max_output_tokens"`
}

// Configured reports whether a provider has been chosen.
func (m Model) Configured() bool { return m.Provider != "" }

// Budget holds the hard caps of a run. Zero means "use the default"; caps
// cannot be turned off.
type Budget struct {
	Tokens      int      `toml:"tokens"`
	USD         float64  `toml:"usd"`
	WallTime    Duration `toml:"wall_time"`
	SandboxRuns int      `toml:"sandbox_runs"`
	MaxFindings int      `toml:"max_findings"`
	// MaxTurns caps tool-use turns for one agent task.
	MaxTurns int `toml:"max_turns"`
	// AllowUnpriced lets an unattended run start with a model that has no
	// known price although a dollar cap was set. The dollar cap cannot hold
	// for such a model, so only the other caps limit the run.
	AllowUnpriced bool `toml:"allow_unpriced"`
	// USDSet records that the dollar cap was set by the operator, in the
	// config file or with --budget-usd, and is not the built-in default.
	USDSet bool `toml:"-"`
}

// Scope is the authorized scope for live targets.
type Scope struct {
	// Hosts lists authorized hosts as host or host:port.
	Hosts        []string `toml:"hosts"`
	PathPrefixes []string `toml:"path_prefixes"`
	// AllowUnsafeMethods permits POST, PUT, PATCH and DELETE probes.
	AllowUnsafeMethods bool    `toml:"allow_unsafe_methods"`
	MaxRequests        int     `toml:"max_requests"`
	RequestsPerSecond  float64 `toml:"requests_per_second"`
	// Statement is the operator's own note on why they are authorized,
	// recorded in the ledger.
	Statement string `toml:"statement"`
}

// Sandbox configures the container runtime.
type Sandbox struct {
	Runtime  string            `toml:"runtime"` // auto|docker|podman|none
	Network  string            `toml:"network"` // none, or scope to attach the runtime's unfiltered bridge network to code-scan proofs
	MemoryMB int               `toml:"memory_mb"`
	CPUs     float64           `toml:"cpus"`
	PIDs     int               `toml:"pids"`
	Timeout  Duration          `toml:"timeout"`
	Images   map[string]string `toml:"images"`
}

// ExternalScanners are the names [scan] scanners accepts. A test in the
// seed package keeps it equal to the names of seed.External.
var ExternalScanners = []string{"semgrep", "gitleaks", "osv-scanner", "trivy", "hadolint"}

// Scan controls what a code scan covers.
type Scan struct {
	// Exclude lists forward-slash globs, relative to the target root, of
	// paths that are not read ("bench/corpus/**", "*.min.js").
	Exclude []string `toml:"exclude"`
	// Include lists directories to read although their name is skipped by
	// default ("build", "vendor/internal/**").
	Include []string `toml:"include"`
	// DisableRules lists rule ids whose leads are dropped.
	DisableRules []string `toml:"disable_rules"`
	// Scanners names the external scanners a scan may run. nil (the key
	// is absent) lets every installed one run; an empty list runs none.
	// The built-in rules always run.
	Scanners []string `toml:"scanners"`
}

// NamePlaceholder is replaced by the test name in [test] single.
const NamePlaceholder = "{name}"

// Test overrides the project test commands the mapper detects. Both run
// only in the sandbox, as an argument vector with no shell.
type Test struct {
	// Command runs the whole test suite: the scan's baseline run and the
	// suite check after a fix in debug mode.
	Command []string `toml:"command"`
	// Single runs one named test for spackle debug --test. Every
	// occurrence of {name} in an argument is replaced by the test name.
	Single []string `toml:"single"`
}

// SingleFor returns the single-test command for name, or nil when none is
// configured.
func (t Test) SingleFor(name string) []string {
	if len(t.Single) == 0 {
		return nil
	}
	out := make([]string, len(t.Single))
	for i, a := range t.Single {
		out[i] = strings.ReplaceAll(a, NamePlaceholder, name)
	}
	return out
}

// Fix configures the fixer.
type Fix struct {
	Enabled     *bool `toml:"enabled"`
	MaxAttempts int   `toml:"max_attempts"`
	// PR pushes the fix branch and opens a pull request.
	PR bool `toml:"pr"`
}

// On reports whether fixing is enabled (the default).
func (f Fix) On() bool { return f.Enabled == nil || *f.Enabled }

// Output configures reports.
type Output struct {
	Formats []string `toml:"formats"`
	Dir     string   `toml:"dir"`
	// FailOn is the lowest severity that makes scan exit 1.
	FailOn string `toml:"fail_on"`
	// FailOnConfidence is the lowest confidence a finding needs to count
	// toward FailOn: plausible (every finding), high or demonstrated.
	FailOnConfidence string `toml:"fail_on_confidence"`
}

// Price is the cost of a model per million tokens, in USD.
type Price struct {
	InputPerMTok  float64 `toml:"input_per_mtok"`
	OutputPerMTok float64 `toml:"output_per_mtok"`
}

// Duration parses TOML strings such as "30m".
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("%q is not a duration: use a form such as 90s, 30m or 2h", string(text))
	}
	d.Duration = v
	return nil
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		Budget: Budget{
			Tokens:      2_000_000,
			USD:         5,
			WallTime:    Duration{30 * time.Minute},
			SandboxRuns: 40,
			MaxFindings: 50,
			MaxTurns:    24,
		},
		Scope: Scope{PathPrefixes: []string{"/"}, MaxRequests: 400, RequestsPerSecond: 5},
		Sandbox: Sandbox{
			Runtime: "auto", Network: "none", MemoryMB: 1024, CPUs: 2, PIDs: 256,
			Timeout: Duration{2 * time.Minute},
			Images:  lang.DefaultImages(),
		},
		Fix:      Fix{MaxAttempts: 3},
		Output:   Output{Formats: []string{"terminal"}, FailOn: "high", FailOnConfidence: "plausible"},
		StateDir: ".spackle",
	}
}

// Load reads the config file at path over the defaults. When path is empty
// it looks for spackle.toml in the working directory and returns the
// defaults if there is none. The second result is the file that was read,
// or "" when none was.
func Load(path string) (Config, string, error) {
	cfg := Default()
	explicit := path != ""
	if !explicit {
		path = DefaultFile
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the operator names their own config file
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return cfg, "", cfg.Validate()
		}
		return Config{}, "", fmt.Errorf("read config %s: %w. Pass --config with the right path, or omit it to use defaults", path, err)
	}
	var file Config
	md, err := toml.Decode(string(raw), &file)
	if err != nil {
		return Config{}, "", fmt.Errorf("config %s is not valid TOML: %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return Config{}, "", fmt.Errorf("config %s has unknown keys: %s. Remove them or check the spelling against docs/config.md", path, strings.Join(keys, ", "))
	}
	// scanners = [] runs no external scanner, which differs from leaving
	// the key out.
	if md.IsDefined("scan", "scanners") && file.Scan.Scanners == nil {
		file.Scan.Scanners = []string{}
	}
	cfg.merge(file)
	if err := cfg.Validate(); err != nil {
		return Config{}, "", fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, path, nil
}

// merge overlays the values set in file onto c.
func (c *Config) merge(file Config) {
	if file.Model.Configured() || file.Model.Model != "" || file.Model.BaseURL != "" {
		c.Model = file.Model
	}
	if len(file.Stages) > 0 {
		c.Stages = file.Stages
	}
	b := file.Budget
	if b.Tokens != 0 {
		c.Budget.Tokens = b.Tokens
	}
	if b.USD != 0 {
		c.Budget.USD = b.USD
		c.Budget.USDSet = true
	}
	if b.AllowUnpriced {
		c.Budget.AllowUnpriced = true
	}
	if b.WallTime.Duration != 0 {
		c.Budget.WallTime = b.WallTime
	}
	if b.SandboxRuns != 0 {
		c.Budget.SandboxRuns = b.SandboxRuns
	}
	if b.MaxFindings != 0 {
		c.Budget.MaxFindings = b.MaxFindings
	}
	if b.MaxTurns != 0 {
		c.Budget.MaxTurns = b.MaxTurns
	}
	s := file.Scope
	if len(s.Hosts) > 0 {
		c.Scope.Hosts = s.Hosts
	}
	if len(s.PathPrefixes) > 0 {
		c.Scope.PathPrefixes = s.PathPrefixes
	}
	c.Scope.AllowUnsafeMethods = s.AllowUnsafeMethods
	if s.MaxRequests != 0 {
		c.Scope.MaxRequests = s.MaxRequests
	}
	if s.RequestsPerSecond != 0 {
		c.Scope.RequestsPerSecond = s.RequestsPerSecond
	}
	c.Scope.Statement = s.Statement
	sb := file.Sandbox
	if sb.Runtime != "" {
		c.Sandbox.Runtime = sb.Runtime
	}
	if sb.Network != "" {
		c.Sandbox.Network = sb.Network
	}
	if sb.MemoryMB != 0 {
		c.Sandbox.MemoryMB = sb.MemoryMB
	}
	if sb.CPUs != 0 {
		c.Sandbox.CPUs = sb.CPUs
	}
	if sb.PIDs != 0 {
		c.Sandbox.PIDs = sb.PIDs
	}
	if sb.Timeout.Duration != 0 {
		c.Sandbox.Timeout = sb.Timeout
	}
	for lang, img := range sb.Images {
		c.Sandbox.Images[lang] = img
	}
	if file.Fix.Enabled != nil {
		c.Fix.Enabled = file.Fix.Enabled
	}
	if file.Fix.MaxAttempts != 0 {
		c.Fix.MaxAttempts = file.Fix.MaxAttempts
	}
	c.Fix.PR = file.Fix.PR
	if len(file.Scan.Exclude) > 0 {
		c.Scan.Exclude = file.Scan.Exclude
	}
	if len(file.Scan.Include) > 0 {
		c.Scan.Include = file.Scan.Include
	}
	if len(file.Scan.DisableRules) > 0 {
		c.Scan.DisableRules = file.Scan.DisableRules
	}
	if file.Scan.Scanners != nil {
		c.Scan.Scanners = file.Scan.Scanners
	}
	if len(file.Test.Command) > 0 {
		c.Test.Command = file.Test.Command
	}
	if len(file.Test.Single) > 0 {
		c.Test.Single = file.Test.Single
	}
	if len(file.Output.Formats) > 0 {
		c.Output.Formats = file.Output.Formats
	}
	if file.Output.Dir != "" {
		c.Output.Dir = file.Output.Dir
	}
	if file.Output.FailOn != "" {
		c.Output.FailOn = file.Output.FailOn
	}
	if file.Output.FailOnConfidence != "" {
		c.Output.FailOnConfidence = file.Output.FailOnConfidence
	}
	if len(file.Pricing) > 0 {
		c.Pricing = file.Pricing
	}
	c.Offline = file.Offline
	if file.StateDir != "" {
		c.StateDir = file.StateDir
	}
}

// ForStage returns the model for a stage: its own entry when one exists,
// otherwise the default model. Fields the stage entry leaves empty are
// inherited when the provider is the same.
func (c Config) ForStage(stage string) Model {
	m, ok := c.Stages[stage]
	if !ok || !m.Configured() {
		return c.Model
	}
	if m.Provider == c.Model.Provider {
		if m.Model == "" {
			m.Model = c.Model.Model
		}
		if m.BaseURL == "" {
			m.BaseURL = c.Model.BaseURL
		}
		if m.APIKeyEnv == "" {
			m.APIKeyEnv = c.Model.APIKeyEnv
		}
	}
	if m.MaxOutputTokens == 0 {
		m.MaxOutputTokens = c.Model.MaxOutputTokens
	}
	return m
}

// Validate checks the configuration and reports every problem at once.
func (c Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	checkModel := func(where string, m Model) {
		if !m.Configured() {
			if m.Model != "" || m.BaseURL != "" {
				add("%s sets a model or base_url but no provider: set provider to anthropic, openai, openai-compatible or ollama", where)
			}
			return
		}
		switch m.Provider {
		case ProviderAnthropic, ProviderOpenAI, ProviderOllama:
		case ProviderOpenAICompatible:
			if m.BaseURL == "" {
				add("%s uses provider openai-compatible, which needs base_url (for example https://openrouter.ai/api/v1)", where)
			}
		default:
			add("%s has unknown provider %q: use anthropic, openai, openai-compatible or ollama", where, m.Provider)
		}
		if m.Model == "" {
			add("%s has a provider but no model name", where)
		}
		if strings.ContainsAny(m.APIKeyEnv, " =\t") || looksLikeKey(m.APIKeyEnv) {
			add("%s api_key_env must be the NAME of an environment variable, not a key. Put the key in the environment and name the variable here", where)
		}
	}
	checkModel("[model]", c.Model)
	names := make([]string, 0, len(c.Stages))
	for name := range c.Stages {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !contains(Stages, name) {
			add("[stages.%s] is not a stage: use one of %s", name, strings.Join(Stages, ", "))
			continue
		}
		if !c.Stages[name].Configured() {
			add("[stages.%s] has no provider, so it would be ignored: set provider (the other fields are inherited from [model] when the provider is the same)", name)
			continue
		}
		// Check the resolved model, so a stage may inherit fields from
		// [model] when it uses the same provider.
		checkModel("[stages."+name+"]", c.ForStage(name))
	}

	if c.Budget.Tokens < 0 || c.Budget.USD < 0 || c.Budget.WallTime.Duration < 0 || c.Budget.SandboxRuns < 0 || c.Budget.MaxFindings < 0 || c.Budget.MaxTurns < 0 {
		add("[budget] values cannot be negative")
	}
	switch c.Sandbox.Runtime {
	case "auto", "docker", "podman", "none":
	default:
		add("[sandbox] runtime %q is not one of auto, docker, podman, none", c.Sandbox.Runtime)
	}
	switch c.Sandbox.Network {
	case "none", "scope":
	default:
		add("[sandbox] network %q is not one of none, scope. \"scope\" attaches the runtime's default bridge network to every proof and fix check, and nothing filters it beyond the container runtime's own networking, so a proof can reach whatever that network reaches", c.Sandbox.Network)
	}
	// The sandbox package owns the limits of a run. Ask it now, so a value
	// it would refuse later (a timeout above its hard cap, a negative
	// limit) stops the run before anything is spent.
	if c.Sandbox.Network == "none" || c.Sandbox.Network == "scope" {
		if err := c.Sandbox.Profile().Validate(); err != nil {
			add("[sandbox] %s", strings.TrimPrefix(err.Error(), "sandbox: "))
		}
	}
	if c.Scope.MaxRequests < 0 || c.Scope.RequestsPerSecond < 0 {
		add("[scope] max_requests and requests_per_second cannot be negative")
	}
	if c.Fix.MaxAttempts < 0 {
		add("[fix] max_attempts cannot be negative")
	}
	if c.Model.MaxOutputTokens < 0 {
		add("[model] max_output_tokens cannot be negative")
	}
	for name, m := range c.Stages {
		if m.MaxOutputTokens < 0 {
			add("[stages.%s] max_output_tokens cannot be negative", name)
		}
	}
	switch c.Output.FailOn {
	case "critical", "high", "medium", "low", "never":
	default:
		add("[output] fail_on %q is not one of critical, high, medium, low, never", c.Output.FailOn)
	}
	switch c.Output.FailOnConfidence {
	case "plausible", "high", "demonstrated":
	default:
		add("[output] fail_on_confidence %q is not one of plausible, high, demonstrated", c.Output.FailOnConfidence)
	}
	for _, p := range append(append([]string(nil), c.Scan.Exclude...), c.Scan.Include...) {
		if err := walk.CheckPattern(p); err != nil {
			add("[scan] %w", err)
		}
	}
	for _, r := range c.Scan.DisableRules {
		if strings.TrimSpace(r) == "" {
			add("[scan] disable_rules has an empty rule id")
		}
	}
	for _, s := range c.Scan.Scanners {
		if !slices.Contains(ExternalScanners, s) {
			add("[scan] scanners names %q, which is not one of the external scanners (%s)", s, strings.Join(ExternalScanners, ", "))
		}
	}
	checkVector := func(key string, v []string) {
		for _, a := range v {
			if strings.TrimSpace(a) == "" || strings.ContainsRune(a, 0) {
				add("[test] %s has an empty argument: give the program and each argument as a separate, non-empty string", key)
				return
			}
		}
		if len(v) > 0 && strings.HasPrefix(v[0], "-") {
			add("[test] %s starts with %q, which is an option, not a program: put the program first", key, v[0])
		}
	}
	checkVector("command", c.Test.Command)
	checkVector("single", c.Test.Single)
	if len(c.Test.Single) > 0 && !slices.ContainsFunc(c.Test.Single, func(a string) bool { return strings.Contains(a, NamePlaceholder) }) {
		add("[test] single does not contain %s, so it cannot select the test named by --test: put %s where the test name goes", NamePlaceholder, NamePlaceholder)
	}
	for _, p := range c.Scope.PathPrefixes {
		if !strings.HasPrefix(p, "/") {
			add("[scope] path prefix %q must start with /", p)
		}
	}
	for _, h := range c.Scope.Hosts {
		if strings.Contains(h, "/") || strings.Contains(h, "*") || strings.TrimSpace(h) == "" {
			add("[scope] host %q must be a plain host or host:port, with no scheme, path or wildcard", h)
		}
	}
	return errors.Join(errs...)
}

// looksLikeKey catches the common mistake of pasting a key where the name
// of an environment variable belongs.
func looksLikeKey(s string) bool {
	return strings.HasPrefix(s, "sk-") || strings.HasPrefix(s, "sk_") || len(s) > 64
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// DefaultKeyEnv returns the conventional API key variable for a provider.
func DefaultKeyEnv(provider string) string {
	switch provider {
	case ProviderAnthropic:
		return "ANTHROPIC_API_KEY"
	case ProviderOpenAI:
		return "OPENAI_API_KEY"
	case ProviderOpenAICompatible:
		return "SPACKLE_API_KEY"
	}
	return ""
}

// Profile returns the container limits the [sandbox] table asks for, as
// they were written: the sandbox package fills in its defaults. It is the
// one place the table becomes a profile, so every command that starts a
// container runs it under the same limits.
func (s Sandbox) Profile() sandbox.Profile {
	return sandbox.Profile{
		Network: s.Network, MemoryMB: s.MemoryMB, CPUs: s.CPUs,
		PIDs: s.PIDs, Timeout: s.Timeout.Duration,
	}
}
