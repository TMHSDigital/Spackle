# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A `[scan]` configuration table: `exclude` (also `--exclude`, repeatable) keeps paths out of the scan, `include` reads a directory that is skipped by default, and `disable_rules` drops the leads of a rule. The report lists what was excluded.

### Changed

- `spackle verify` re-runs proofs against the directory that was scanned, which is now recorded as an absolute path, instead of resolving the target as typed against the current directory.
- Directories that are pruned by default are now listed in the report as "Not read". `vendor`, `dist`, `build`, `target` and `coverage` are pruned only at the target root or where a marker file shows they are dependencies or build output, so a first-party package with one of those names is scanned.
- The sandbox no longer copies `.git`, `.spackle`, virtual environments and tool caches from the top of the target into the in-memory work directory, which makes each run faster and leaves more of the memory limit for the program. `node_modules` and `vendor` are still copied.
- A finding with a checked patch that is not applied now has status `patch-available` instead of `fixed`, and it counts toward `--fail-on`: the exit code no longer passes while the flaw is still in the scanned code. `fixed` is kept for a finding whose proof no longer succeeds against the code itself, as `spackle verify` establishes. The JSON report counts gain `patch_available`, and SARIF lists a fixed finding at level `note`.
- Agent search tools are faster on large targets: the target listing is taken from the mapper and shared by every stage of a run, and a file is scanned for secrets once and again only when it changes.
- The deterministic scan is faster: the built-in code, secret and infrastructure seeders process files in parallel, each secret rule runs only on files that contain one of its literal markers, and listing the target no longer stats every file twice.
- A rule now reports at most 50 leads per file and a seeder at most 5000 leads per run, so one generated or vendored file can no longer bury a report or exhaust memory. The seeder line in the report says how many leads were dropped and where. The report of an external scanner is read up to 256 MiB.
- The `go` directive in `go.mod` is now `1.26.11`, so a source install with an older Go 1.26 toolchain builds with the current patch release and its standard library fixes.

### Fixed

- Different rules of the same class that fire at one place (several container hardening rules on one line, several advisories on one lockfile, several missing headers on one page) are now reported as separate findings instead of one. Finding ids of uninvestigated leads change as a result.
- Findings in files whose name contains two dots, such as the Next.js catch-all route `pages/api/auth/[...nextauth].js`, are no longer dropped. Only a real `..` path segment is refused.
- A conversation that uses all its turns now ends with a final answer on the Anthropic provider. The last request used to drop the tool list, which the API refuses when the history holds tool calls, so the investigation was recorded as failed.
- A proof of concept that times out or is killed is no longer read as "the flaw is gone". The fixer rejects such a patch attempt, `spackle verify` keeps the finding status and reports the proof as not verified (and exits 1), and a debug bisect stops instead of counting the commit as good.
- The fix branch no longer picks up uncommitted edits. A fix for a file with uncommitted changes in the working tree stays a patch file, with a note, instead of being committed (and, with `--pr`, pushed) together with those edits. A fix that fails part way no longer leaves files behind for the next fix commit.
- SARIF file paths are now relative to the repository root when a subdirectory of a git repository is scanned, so code scanning alerts attach to the right file (for example with the Action input `path: services/api`).
- Investigations that failed, drafts that were refused and leads dropped at validation are now listed under "What was skipped" in the terminal, Markdown and HTML reports and in a new `rejected` array of the JSON report. They used to be recorded in the ledger only, so a report could say nothing was skipped when part of the plan produced no result.
- The quote check on a drafted finding now compares against the file as the model saw it, with secrets shown as redaction markers, so a finding whose cited line holds a secret is no longer rejected. A quote must also cover a meaningful part of the line it matches: a fragment of a few characters is refused.
- `spackle debug --good <rev>` on Linux: each commit exported for bisect is now readable by the unprivileged sandbox user. The export used to be private to the operator, so every bisect probe failed to copy the source and bisect stopped early.
- Built-in code rules now read comments in the syntax of the file language. A Go or Python statement that starts with `*` and a JavaScript private member that starts with `#` are no longer skipped as comments, a word in a trailing comment can no longer hide a lead, and commented-out code no longer produces one.
- The Go rule for file paths built from request data no longer treats `filepath.Clean` as a sanitizer: `filepath.Join(base, filepath.Clean(input))` keeps a leading `../` and is now reported. `filepath.Base` and the rooted `Clean("/" + input)` idiom still suppress the lead.
- Interrupting an agentic scan (Ctrl-C) no longer discards the findings already investigated. Each finding is written to the ledger as soon as it is complete, the run ends with outcome `interrupted`, the reports are written, and the command exits 3. An interrupt during planning is no longer reported as `completed`, and one failed proof or fix step no longer ends the whole run.
- A sandbox run that times out while the source is still being copied is now reported as a setup failure instead of a timed-out proof.
- Large inputs can no longer exhaust memory or stall a run: the diff of a fix is computed in a bounded table (a very large rewrite is shown as one block), a fix may only patch a regular file within the 1 MiB source limit, a Dockerfile instruction with many continuation lines is parsed in linear time, and over-long quotes in a draft are refused before the file is searched.

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
