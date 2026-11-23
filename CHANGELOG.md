# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A `[scan]` configuration table: `exclude` (also `--exclude`, repeatable) keeps paths out of the scan, `include` reads a directory that is skipped by default, and `disable_rules` drops the leads of a rule. The report lists what was excluded.

### Fixed

- Different rules of the same class that fire at one place (several container hardening rules on one line, several advisories on one lockfile, several missing headers on one page) are now reported as separate findings instead of one. Finding ids of uninvestigated leads change as a result.
- Findings in files whose name contains two dots, such as the Next.js catch-all route `pages/api/auth/[...nextauth].js`, are no longer dropped. Only a real `..` path segment is refused.

## [0.1.0] - 2026-11-22

The first release.

### Added

- Repository foundation: license, security policy, contribution guide, CI, release pipeline configuration, and project documentation.
- `spackle scan` for local directories and git URLs, with no model required: a target mapper (languages, frameworks, entry points, trust boundaries, test command), built-in seeders for code, secrets, Dockerfiles, Kubernetes, Terraform and GitHub workflows, and adapters for Semgrep, gitleaks, osv-scanner, Trivy and hadolint.
- The finding schema with CVSS 4.0 scoring computed from the vector, validation, deduplication and ranking.
- The append-only evidence ledger, and `spackle report`, which rebuilds terminal, Markdown, HTML, JSON and SARIF reports from the ledger alone.
- `spackle doctor`, which reports the container runtime, sandbox images, scanners and model configuration.
- Secret detection and redaction: reports and the ledger name the rule, location and a short hash, never the value.
- `examples/demo-app` and the benchmark corpus under `bench/corpus`, both intentionally vulnerable test data.
- Model providers, bring your own key: Anthropic (native Messages API), any OpenAI-compatible endpoint (OpenAI, OpenRouter, Azure OpenAI, Together, Groq, Fireworks, llama.cpp, LM Studio, vLLM) and Ollama, selectable per pipeline stage. Token and cost accounting is normalized; usage a provider does not report is estimated and marked estimated; an unpriced model is reported as cost unknown instead of $0.
- `--offline`: a provider whose endpoint is not on this machine is refused before the run starts, and the HTTP client refuses any non-loopback address.
- Agentic stages: a planner, investigators with a read-only allowlisted tool set, an adversarial reviewer with fresh context, and cross-finding chain analysis. Every draft is checked against the target before it becomes a finding: quoted lines must exist in the cited file, locations must resolve inside the target, and the CVSS score is computed from the vector.
- Untrusted-input envelopes with a per-run nonce around all target content, and redaction of secrets before any provider call.
- Hard budget caps on tokens, spend, wall time, sandbox runs and findings, with stagnation detection, a cost estimate before a paid run, and a report section listing what was skipped.
- Container sandbox for proofs and fixes (Docker or Podman): no network, all capabilities dropped, read-only root filesystem, non-root user, resource and time limits, source mounted read-only. With no runtime nothing is executed and proofs are labelled not run.
- Prover and fixer: a proof of concept is run in the sandbox and stored as evidence; a fix is accepted only if the changed files compile, the proof stops working, and a passing test suite still passes. Fixes are committed to a `spackle/<run-id>` branch in a new worktree; the working tree is never modified.
- `spackle verify <run-id>`, which re-runs stored proofs against the current code.
- `--pr`, which pushes the fix branch and opens a draft pull request.
- `spackle mcp`, a stdio MCP server whose limits are set by the operator on the command line.
- `doctor` now validates each configured model with a free round-trip and warns about small or tool-less local models.
- Running-target analysis: `spackle scan <url>` behind the authorized-scope gate (`--authorize <scope-file>`, a `[scope]` table, or a typed confirmation of the host). A scope-bound client that never follows a redirect out of scope, a read-only baseline probe (security headers, cookie flags, CORS, error disclosure, directory listing, reflected input, SQL error signatures, open redirect, path traversal, exposed files), every request and response stored as evidence, and model assessment of each observation through a scope-bound `http_request` tool.
- Debug mode: `spackle debug --test <name>` or `--issue <file|text>` reproduces a failure in the sandbox, finds the root cause, optionally bisects from `--good <ref>`, and writes a verified fix.
- GitHub Action (`action.yml`) that installs a release, verifies its checksum and provenance, runs a scan and uploads SARIF.
- Benchmark runner (`make bench`) that scores a run against the corpus ground truth and writes `bench/results/<date>-<model>.json`, and the first committed results file (deterministic, no model).
- A single-page project site under `docs/`, and README sections generated from real output (`tools/demosvg`, `tools/readme`).

### Fixed

- A target directory that sits inside an unrelated git repository is no longer treated as part of it: fix branches are created only when the fixed files are tracked, and the recorded commit only when the target has tracked files.
- `git show` is called with text conversion and external diff disabled, so a repository's own git configuration cannot run a program when history is read.

[Unreleased]: https://github.com/TMHSDigital/Spackle/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TMHSDigital/Spackle/releases/tag/v0.1.0
