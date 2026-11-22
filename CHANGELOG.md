# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
