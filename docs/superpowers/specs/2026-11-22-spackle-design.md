# Spackle v0.1.0 design

Date: 2026-11-22
Status: approved by the build prompt (autonomous execution); builder calls are marked "Call:".

## Intent

Spackle is an agentic security and debugging platform for systems the operator owns or is
authorized to test. It finds real flaws, proves them in a sandbox, explains how an attacker
would exploit each one and what the blast radius is, and writes and verifies the fix.

It exists because the comparable open source engine (ARTEX) shipped as a pure offensive tool
with no identity, listening ports and default credentials, and was reused by criminals. Spackle
keeps the agentic capability and adds what a defender needs: authorized-scope gating, no
listening surface, redaction before any model call, an evidence ledger, honest confidence
labels, and remediation.

## Goals

- `spackle scan <path|url>` returns ranked findings that read like a senior pentester's report
  entry: identity, CVSS 4.0 severity, the flaw, exploitation scenario, proof, blast radius,
  remediation, confidence.
- Three surfaces: code (SAST plus agentic review), running targets (DAST), infrastructure and
  config. Plus a debug mode that starts from a failing test or an issue.
- Works with no LLM at all (deterministic leads), better with one. Bring your own model:
  Anthropic, any OpenAI-compatible endpoint, Ollama. Fully offline mode.
- One static Go binary, Windows first-class.
- A public repository that is fit for strangers on the first push.

## Non-goals (v0.1)

- Auto-run proofs for languages other than Go, Python and TypeScript/JavaScript.
- A web UI. An HTTP MCP transport. Both are roadmap items; nothing listens in v0.1.
- Cloud account API scanning. Infrastructure coverage in v0.1 is files the operator has on
  disk (Dockerfiles, Terraform, Kubernetes manifests, CI workflows).
- Authenticated crawling with a browser engine. DAST uses plain HTTP.

## Anti-goals

- Becoming a redistributable exploit kit. Proofs are evidence in a run folder, tied to the
  authorized target, never packaged as standalone tools.
- Any invented number or claim. No benchmark table without a committed results file.
- Executing model-written or target-supplied code on the host outside the sandbox.
- Any ARTEX code, prompt or asset. Clean room; ideas only.

## Constraints

- Go: minimum 1.26, latest 1.27. `CGO_ENABLED=0`.
- Apache-2.0.
- CI must pass on ubuntu, macos and windows with no API key and no container runtime
  (sandbox integration tests run on Linux only and skip elsewhere with a clear message).
- No em dashes, no emojis in any prose.

## Approaches considered

1. **Thin orchestrator over existing scanners.** Shell out to Semgrep, Trivy, nuclei and have
   an LLM summarize. Cheap to build, but useless without the scanners installed, adds no
   reachability reasoning, and cannot prove or fix anything. Rejected: it is a report
   formatter, not the tool described.
2. **General autonomous agent with a shell.** One agent loop with a shell tool inside a
   container. Flexible, but scope and budgets are hard to enforce, runs are not reproducible,
   and prompt injection from target content becomes command execution. Rejected: conflicts
   with principles 2 and 3.
3. **Staged pipeline with typed hand-offs and an append-only ledger (chosen).** Deterministic
   stages (mapper, seeders) produce typed leads. LLM stages (planner, investigators, prover,
   reviewer, fixer) each get a narrow allowlisted tool set, a budget slice, and typed JSON
   output validated by the engine. Every event goes to the ledger; reports are a pure function
   of the ledger. This gives enforceable scope, reproducible reports, testability with a fake
   provider, and graceful degradation when a stage has no budget or no model.

## Architecture

```
target -> authz gate -> mapper -> seeders -> planner -> investigators -> prover -> reviewer -> fixer -> report
                                     \________________ ledger (append-only JSONL) ________________/
```

### Package layout (`internal/`)

| Package | Responsibility |
|---|---|
| `cli` | Subcommand dispatch, flags, exit codes, help with the authorized-use notice |
| `config` | `spackle.toml` loading, flag and env merge, per-stage provider selection |
| `target` | Classify a target: local path, git URL, live URL. Decides whether the scope gate applies |
| `authz` | Authorized-scope gate: scope file parsing, host and CIDR matching, per-run confirmation |
| `mapper` | No-LLM target map: languages, frameworks, entry points, trust boundaries, test and build commands. Cached by commit SHA |
| `seed` | Lead producers. External scanner adapters (Semgrep, gitleaks, osv-scanner, Trivy, hadolint) plus built-in rules for code, secrets, Dockerfile, Kubernetes, Terraform and CI workflows |
| `redact` | Secret detection and redaction. Used by seeders (to report location, never value) and by the provider wrapper |
| `envelope` | Wraps untrusted content in nonce-delimited data blocks and neutralizes delimiter forgery |
| `llm` | Provider interface and implementations: `anthropic`, `openai` (compatible), `ollama`, `fake` (recorded). Usage and cost normalization. Offline guard |
| `budget` | Hard caps: tokens, USD, wall time, sandbox runs, findings. Stagnation detection |
| `ledger` | Append-only `ledger.jsonl` writer and reader with causal parents |
| `finding` | Finding schema, validation, CVSS 4.0 scoring, dedup, ranking |
| `agent` | Planner, investigator, reviewer, prover, fixer loops and the allowlisted tool registry |
| `sandbox` | Container runtime abstraction (Docker, Podman): isolation profile, limits, copy-on-write source |
| `dast` | Scope-bound HTTP client, baseline probe, crawl, request and response capture |
| `debug` | Debug mode: reproduce, bisect, root cause, fix, verify |
| `gitx` | Git plumbing: commit SHA, worktree and branch creation, bisect, clone |
| `report` | Renderers: terminal, Markdown, HTML, JSON, SARIF 2.1.0. Input is a ledger only |
| `mcp` | Stdio MCP server (JSON-RPC 2.0 over stdin and stdout) |
| `bench` | Corpus runner and scoring (precision, recall, verified-fix rate, cost per finding) |

`cmd/spackle/main.go` only calls `cli.Main`.

### Run flow and degradation

1. Classify the target. A live URL, host or cloud account requires the scope gate. Local paths
   and git URLs (cloned, then treated as local source) do not.
2. Mapper and seeders run with no model. If no provider is configured the run stops here and
   reports leads as findings with confidence `plausible` and proof status `not-run`. This is
   the M1 behavior and remains the no-LLM path.
3. Planner converts map and leads into intents (scope, hypothesis, budget share), ordered by
   expected severity.
4. Investigators run one intent each with read-only tools. Output is a typed finding draft.
   Drafts that fail schema validation or cite locations that do not exist are rejected.
5. Prover builds a PoC and runs it in the sandbox. Pass promotes confidence to `demonstrated`.
   No runtime means proof status `not-run` and the finding is labelled reasoned.
6. Reviewer gets fresh context (the finding and tool access, not the investigator transcript)
   and tries to refute. Refuted findings are dismissed; the reason stays in the ledger.
7. Fixer writes the smallest patch in a worktree copy, re-runs tests and the PoC in the
   sandbox, rejects a patch that regresses or fails to close the PoC. Up to N tries.
8. Reports render from the ledger.

Any cap being hit stops new work, lets in-flight validation finish, and records a
`budget.skip` ledger event listing what was not examined. The report shows that list.

### The four principles in code

**Authorized use.** `authz.Gate` is the only constructor for a live-target handle; the DAST
HTTP client and the investigator `http_request` tool take that handle as a required argument,
so there is no code path to a live request without it. The gate is satisfied by
`--authorize <scope-file>` or a `[scope]` table in config (required in `--yes` and CI mode), or
by an interactive typed confirmation of the exact host. Scope lists hosts, ports and path
prefixes. Redirects and links leaving scope are refused and logged. Loopback targets still
require confirmation; the prompt is one line.

**Not a backdoor.** No package opens a listener. A test walks the Go AST of the module and
fails on any `net.Listen`, `http.ListenAndServe` or `http.Server` use outside test files. MCP is
stdio only in v0.1. No credentials exist to default. All target content reaches a model only
inside an `envelope` block with a per-run random nonce; the system prompt states that envelope
content is data. More importantly, the engine does not rely on the model obeying that: scope,
budgets and tool permissions live in Go and no tool exists that can change them. Tool
arguments are validated against the run scope (paths confined to the target root, hosts
confined to the scope) regardless of what the model asks.

**Secrets stay put.** `llm.Redacting` wraps every provider. Every outbound message and tool
result passes through `redact` first; a test provider asserts no planted secret ever arrives.
Secret findings carry file, line, rule and a short hash of the value, never the value.
`--offline` installs a dialer that refuses any non-loopback address, and provider construction
fails early if its base URL is not loopback. Call: a private-range LAN address is not treated
as local under `--offline`; only loopback is. This is stricter than some users want and is
documented.

**Clean room.** No ARTEX file is vendored, read into the repo, or paraphrased. The README
credits it as inspiration.

### Finding schema

`finding.Finding` carries: `id`, `title`, `class`, `cwe[]`, `owasp[]`, `location`
(file+line range, or endpoint+method+parameter), `severity` (CVSS 4.0 vector, score, label,
reasoning), `flaw` (description plus `flow[]` steps each quoting real code or traffic),
`exploitation` (preconditions, steps, chains_into), `proof` (status `demonstrated|reasoned|not-run`,
kind, artifact paths, captured result, isolation in effect), `blast_radius` (gains, exposed,
kill_chain with related finding ids), `remediation` (summary, patch as unified diff, why,
defense_in_depth, verification status, branch), `confidence` (`demonstrated|high|plausible`,
reason), `origin` (seeders and stages that contributed), `status`
(`open|dismissed|fixed`).

CVSS 4.0 scores are computed, not model-supplied: the model proposes a vector, the engine
validates and scores it. Call: use `github.com/pandatix/go-cvss` for CVSS 4.0 scoring rather
than reimplementing the macrovector tables.

### Providers

`llm.Provider` has one method, `Complete(ctx, Request) (Response, error)`, with messages, tool
definitions, and normalized `Usage{InputTokens, OutputTokens, Estimated bool}`. Tool calling
is normalized across the Anthropic Messages shape, the OpenAI Chat Completions shape and the
Ollama chat shape. Cost comes from a small built-in price table that config can override;
unknown models cost `0` and are marked `cost_unknown`. When a provider omits usage, tokens are
estimated at 4 bytes per token and marked estimated. Stages (`planner`, `investigator`,
`reviewer`, `prover`, `fixer`, `mechanical`) each resolve to a provider config, defaulting to
the run default. API keys come only from environment variables named in config.

### Sandbox

`sandbox.Runtime` shells out to the `docker` or `podman` CLI (no SDK dependency). Default
profile: `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`
root with a tmpfs work area, `--pids-limit`, memory and CPU limits, non-root user, wall-clock
timeout enforced by the host. Source is copied into the container work area rather than
bind-mounted read-write, so the working tree cannot be modified (Call: copy-in via a read-only
bind mount plus an in-container copy; this is the portable form of copy-on-write that works on
Docker Desktop for Windows). A run may widen network to reach an authorized DAST scope; the
profile actually used is recorded on each proof. With no runtime, nothing model-written is
executed and proofs are marked `not-run`.

Language images: `golang`, `python`, `node` official images, pinned by tag in config and
overridable. `doctor` reports whether they are present locally.

### Ledger and reproducibility

`.spackle/runs/<run-id>/ledger.jsonl` holds one JSON object per line: `seq`, `ts`, `parent`,
`type`, `data`. Types include `run.start`, `map`, `lead`, `model.call`, `tool.call`,
`sandbox.run`, `http.exchange`, `finding.upsert`, `verdict`, `budget.skip`, `run.end`. Per-finding
folders hold `finding.json`, `poc/`, `fix.patch`, `evidence/`, `review.md`. `spackle report`
reads only the ledger and renders with no clock, no map iteration order and no environment
input, so repeated renders are byte-identical. Run ids are `YYYYMMDD-HHMMSS-<6 hex>`.

### DAST

Scope-bound client with rate limiting and a request cap. Baseline probe (no LLM): security
headers, cookie flags, CORS misconfiguration, verbose errors, directory listing, reflected
input, open redirect, SQL error signatures, path traversal on file-like parameters, exposed
well-known files. Probes are non-destructive: GET and safe parameter mutation by default;
state-changing methods require `dast.allow_unsafe_methods` in the scope file. Every finding
links to the stored request and response pair. With a model, investigators get an
`http_request` tool bound to the same scope and caps.

### Debug mode

`spackle debug [path] --test <name> | --issue <file|text>`: reproduce in the sandbox (the
failing test, or a model-written reproduction test for an issue), optionally `git bisect`
between a known-good ref and HEAD using the reproduction as the oracle, produce a root-cause
write-up, patch in a worktree, verify the test passes and the suite does not regress. Requires
a model and a runtime; without them it reports what it can (the reproduction command and the
map) and says what is missing.

### MCP

Stdio JSON-RPC server exposing `spackle_scan`, `spackle_report`, `spackle_list_runs`,
`spackle_get_finding`, `spackle_verify`, `spackle_doctor`. Live targets through MCP require a
scope file path; the interactive confirmation is not available over MCP, so there is no way
for a model client to self-authorize.

### Dependencies

| Module | Why |
|---|---|
| `github.com/BurntSushi/toml` | `spackle.toml` parsing. No transitive dependencies |
| `go.yaml.in/yaml/v3` | Parsing Kubernetes manifests and CI workflows for the infra rules |
| `github.com/pandatix/go-cvss` | Correct CVSS 4.0 scoring |

Everything else is the standard library, including the CLI (`flag`), HTTP providers, SARIF,
MCP and HTML rendering (`html/template`). Final choices are recorded in `ARCHITECTURE.md`.

## Testing

- Unit tests per stage with `llm/fake`, a scripted provider, so CI needs no key.
- Golden files for all five report formats.
- Principle suites: injection corpus against envelope and tool validation; scope gate for live
  targets; sandbox argument defaults; redaction before provider; no listener in the module.
- Sandbox integration tests behind a runtime check, run in CI on Linux.
- Bench corpus doubles as an end-to-end regression for the deterministic path.

## What is left to the builder

Rule coverage of the built-in seeders, prompt wording, the terminal layout, the palette and
the wordmark, and the exact fixture set are builder calls, recorded as they are made.

## Honest limits to state in the README

- Small local models underperform at this work.
- Non-Go/Python/JS languages get findings and analysis without an auto-run proof.
- Without a container runtime nothing is demonstrated.
- The benchmark section shows numbers only from a committed results file.
