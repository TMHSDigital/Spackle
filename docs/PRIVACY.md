# Privacy

Status: this describes the v0.1.0 design. `ROADMAP.md` tracks which milestones have landed.

This document says what leaves the operator machine during a Spackle run, what is redacted first, and what is stored locally.

## What leaves the machine

| Mode | Sent to a model provider | Network destinations | Notes |
|---|---|---|---|
| No model configured | Nothing | None from Spackle for a local path. A git URL target is cloned from its remote. A live target receives scope-bound requests | The run stops after the mapper and seeders. Leads are reported with confidence `plausible` and proof status `not-run` |
| Hosted provider (Anthropic, OpenAI, OpenRouter, and other OpenAI-compatible endpoints) | Prompts built from the target: source code excerpts, file paths, tool results, and HTTP traffic from the target, with detected secrets redacted | The provider base URL in config, plus the destinations in the row above | The provider's own retention and training terms apply. Spackle does not control them. API keys are read from environment variables named in config and are sent only to that provider as credentials |
| Local model (Ollama or a loopback OpenAI-compatible server) | The same redacted prompts, sent to the local server | The loopback address of the model server, plus the destinations in the first row | Nothing is sent to a third party by Spackle. A model server on another machine on the LAN is a remote destination, not a local one |
| `--offline` | Only to a provider whose base URL is loopback, or nothing if no model is configured | Loopback only, for connections Spackle itself makes | A dialer refuses any non-loopback address. Provider construction fails early if the base URL is not loopback. Private-range LAN addresses are refused |

Two points apply to every row:

- Redaction runs before every provider call, including calls to a local model.
- The `--offline` dialer governs connections made by the Spackle process. See "External tools" below for programs Spackle starts.

## What is always redacted

Secret values are redacted before any provider call. Every outbound message and every tool result passes through redaction first. A detected secret is replaced by the name of the rule that matched and a short hash of the value.

The same rule applies to findings. A secret finding records the file, line, rule, and short hash. It never records the value, so the value does not appear in the ledger or in a report through a finding.

Redaction works by rule. A secret in a format no rule matches is not detected and is not redacted.

## What is not redacted

When a model is configured, these are sent to it as they are:

- Source code excerpts from the target.
- File paths.
- HTTP traffic from the target (requests and responses), minus detected secrets.

If the source itself is confidential, use a local model, run with no model, or use `--offline`.

## No telemetry and no update check

Spackle has no telemetry. It does not report usage, errors, or findings to the project or to anyone else. It does not check for updates. It makes no network connection that the run does not require.

## What is stored locally

Each run writes to `.spackle/` in the working directory:

| Item | Location | Content |
|---|---|---|
| Ledger | `.spackle/runs/<run-id>/ledger.jsonl` | Every event of the run: model calls, tool calls, sandbox runs, HTTP exchanges, findings, verdicts |
| Evidence | Per-finding folders | `finding.json`, `poc/`, `fix.patch`, `evidence/`, `review.md`, including stored request and response pairs |
| Reports | Rendered from the ledger | Terminal, Markdown, HTML, JSON, SARIF |

Treat `.spackle/` as sensitive. It describes weaknesses in your system and contains working proofs of concept, source excerpts, and captured traffic. Add `.spackle/` to `.gitignore` and do not commit or share it without review. Remove real hostnames and unredacted reports before attaching anything to a public issue.

Spackle does not upload this folder anywhere.

## External tools

Spackle can use programs that are separate from it. They run locally with the operator's privileges and have their own network behavior.

- **External scanners.** Semgrep, gitleaks, osv-scanner, Trivy, and hadolint run on the operator machine. Some of them, including osv-scanner and Trivy, may fetch vulnerability databases themselves. Check each scanner's own documentation for what it downloads and what it reports.
- **Container images.** The sandbox uses the official `golang`, `python`, and `node` images. Pulling an image contacts the container registry. `spackle doctor` reports whether the images are already present locally.
- **Git.** A git URL target is cloned from its remote.

The design does not state that `--offline` constrains these separate programs. For a run with no outside traffic, pull the images and update the scanner databases in advance, or disable the scanners that need the network.
