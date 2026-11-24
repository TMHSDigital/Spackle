package ledger

// Payload types for the events that reports are built from. They live here,
// next to the event type names, so the engine that writes them and the
// report loader that reads them share one definition.

// RunStart is the data of a run.start event.
type RunStart struct {
	RunID      string `json:"run_id"`
	Version    string `json:"version"`
	Command    string `json:"command"`     // scan|debug|verify
	Target     string `json:"target"`      // as the operator gave it, with credentials removed
	TargetKind string `json:"target_kind"` // path|git|url
	// TargetPath is the absolute directory that was scanned, for a path
	// target. Verify re-runs proofs against it, wherever it is run from.
	TargetPath string `json:"target_path,omitempty"`
	// RepoPrefix is the scanned directory's path from the top of its git
	// work tree, with forward slashes ("" at the top or outside git).
	RepoPrefix string `json:"repo_prefix,omitempty"`
	Commit     string `json:"commit,omitempty"`
	// Ref is the branch or tag that was asked for with --ref, for a git
	// URL target. Commit is what it resolved to.
	Ref string `json:"ref,omitempty"`
	// ResumedFrom is the id of the run this run continues (scan --resume).
	ResumedFrom string `json:"resumed_from,omitempty"`
	Mode        string `json:"mode"` // deterministic|agentic
	Provider    string `json:"provider,omitempty"`
	Model       string `json:"model,omitempty"`
	Offline     bool   `json:"offline,omitempty"`
	// Scope is the authorized scope for a live target, as confirmed.
	Scope string `json:"scope,omitempty"`
	// ScopeSource says how authorization was given: scope-file, config or interactive.
	ScopeSource string `json:"scope_source,omitempty"`
	Isolation   string `json:"isolation,omitempty"` // sandbox profile summary, or "no container runtime"
}

// MapSummary is the data of a map event.
type MapSummary struct {
	Files       int      `json:"files"`
	Skipped     int      `json:"skipped"`
	Languages   []string `json:"languages,omitempty"`
	Frameworks  []string `json:"frameworks,omitempty"`
	EntryPoints int      `json:"entry_points"`
	InfraFiles  int      `json:"infra_files"`
	TestCommand string   `json:"test_command,omitempty"`
	Endpoints   int      `json:"endpoints,omitempty"` // for a live target
}

// SeederStatus is the data of a seeder event.
type SeederStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Note      string `json:"note,omitempty"`
	Leads     int    `json:"leads"`
	Error     string `json:"error,omitempty"`
}

// ModelCall is the data of a model.call event. It records accounting, not
// content: prompts and completions are kept out of the ledger.
type ModelCall struct {
	Stage        string  `json:"stage"`
	Provider     string  `json:"provider"`
	Model        string  `json:"model"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	Estimated    bool    `json:"estimated,omitempty"`
	CostUSD      float64 `json:"cost_usd"`
	CostKnown    bool    `json:"cost_known"`
	Error        string  `json:"error,omitempty"`
}

// BudgetSkip is the data of a budget.skip event.
type BudgetSkip struct {
	Cap     string   `json:"cap"`     // which cap was reached
	Skipped []string `json:"skipped"` // what was not examined
}

// Verdict is the data of a verdict event: a change to a finding's standing.
type Verdict struct {
	FindingID string `json:"finding_id"`
	Stage     string `json:"stage"`   // reviewer|prover|fixer|verify
	Outcome   string `json:"outcome"` // confirmed|dismissed|demonstrated|not-reproduced|fixed|fix-rejected
	Reason    string `json:"reason,omitempty"`
}

// Reject is the data of a draft.reject event.
type Reject struct {
	Stage  string `json:"stage"`
	Intent string `json:"intent,omitempty"`
	Reason string `json:"reason"`
}

// SandboxRun is the data of a sandbox.run event.
type SandboxRun struct {
	FindingID string `json:"finding_id,omitempty"`
	Purpose   string `json:"purpose"` // poc|tests|fix-verify|repro|bisect
	Image     string `json:"image"`
	Command   string `json:"command"`
	ExitCode  int    `json:"exit_code"`
	TimedOut  bool   `json:"timed_out,omitempty"`
	Isolation string `json:"isolation"`
	OutputRef string `json:"output_ref,omitempty"` // path relative to the run directory
}

// RunEnd is the data of a run.end event.
type RunEnd struct {
	Outcome string `json:"outcome"` // completed|budget-exhausted|interrupted|failed
	Note    string `json:"note,omitempty"`
}

// ToolCall is the data of a tool.call event. Arguments are redacted and
// clipped; results are not stored, only their size.
type ToolCall struct {
	Stage   string `json:"stage"`
	Tool    string `json:"tool"`
	Args    string `json:"args"`
	IsError bool   `json:"is_error,omitempty"`
	Bytes   int    `json:"bytes"`
}

// Intent is the data of an intent event: one planned investigation.
type Intent struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Class      string   `json:"class,omitempty"`
	Hypothesis string   `json:"hypothesis"`
	Files      []string `json:"files,omitempty"`
	LeadIDs    []string `json:"lead_ids,omitempty"`
	Priority   int      `json:"priority"`
	Source     string   `json:"source"` // planner|fallback|resumed
}

// HTTPExchange is the data of an http.exchange event: a pointer to one
// recorded request and response. The full exchange, redacted, is in the
// referenced evidence file.
type HTTPExchange struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	Note   string `json:"note,omitempty"`
	Ref    string `json:"ref"`
}
