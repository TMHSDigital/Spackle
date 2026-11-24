# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A `[scan]` configuration table: `exclude` (also `--exclude`, repeatable) keeps paths out of the scan, `include` reads a directory that is skipped by default, and `disable_rules` drops the leads of a rule. The report lists what was excluded.
- Action input `spackle-dir`, to run the Action with an existing binary instead of a downloaded release, and output `has-sarif`.
- `spackle doctor --format json` prints the checks as JSON, with the same rows the MCP `doctor` tool returns.
- `spackle scan <git URL> --ref <branch or tag>` scans a named branch or tag instead of the default branch. The ref is recorded in the run.
- `spackle scan <directory> --since <revision>` reports only on files changed since that revision, so a pull request is judged on what it changes. Leads in other files are left out and the report says how many; with a model only the changed files are planned for investigation. The Action exposes it as the `diff-base` input, which needs a checkout with `fetch-depth: 0`.
- `spackle scan <directory> --resume <run id>` (or `--resume latest`) continues a scan that stopped on its budget. It investigates what that run planned and did not reach, under a new budget and without planning again, and carries the earlier findings into the new report. It is refused when the target's commit changed since, unless `--force` is passed. A scan that stops on its budget prints the command.
- `spackle scan --dry-run` shows what a scan would read, each seeder and its lead count, the leads by class, the number of investigations that would be planned and the cost estimate. It calls no model and stores no run.
- SARIF reports now carry the traced data flow of a finding as `codeFlows`, readable rule names, descriptions and remediation help from the class table, and the verification text and fix branch of a finding that has a patch.
- `spackle runs` lists the stored runs, and `spackle runs prune --keep <n>` or `--older-than <age>` deletes old runs with their clones and fix worktrees after listing them.
- `spackle runs compare <older> <newer>` lists the findings that are new, gone, or present in both of two stored runs.

### Changed

- `spackle scan --dry-run --yes` now says when the real run would be refused because its dollar cap cannot be enforced for a model without a known price. The dry run still exits 0.
- The report of a running-target scan now states that requests were sent without credentials and that pages behind a login were not examined.
- A run that nobody confirms (`--yes`, the GitHub Action, the MCP server, `spackle bench --yes`) is now refused with exit code 2 when you set a dollar cap (`--budget-usd` or `usd` under `[budget]`) and the model has no known price, because that cap could not stop the run. The message shows the `[pricing]` table to add. Pass `--allow-unpriced` or set `allow_unpriced = true` under `[budget]` to run under the token cap alone. In the Action, set `args: --allow-unpriced`. Local models, OpenRouter and the built-in default cap are not affected.
- `spackle verify` re-runs proofs against the directory that was scanned, which is now recorded as an absolute path, instead of resolving the target as typed against the current directory.
- Directories that are pruned by default are now listed in the report as "Not read". `vendor`, `dist`, `build`, `target` and `coverage` are pruned only at the target root or where a marker file shows they are dependencies or build output, so a first-party package with one of those names is scanned.
- The sandbox no longer copies `.git`, `.spackle`, virtual environments and tool caches from the top of the target into the in-memory work directory, which makes each run faster and leaves more of the memory limit for the program. `node_modules` and `vendor` are still copied.
- A finding with a checked patch that is not applied now has status `patch-available` instead of `fixed`, and it counts toward `--fail-on`: the exit code no longer passes while the flaw is still in the scanned code. `fixed` is kept for a finding whose proof no longer succeeds against the code itself, as `spackle verify` establishes. The JSON report counts gain `patch_available`, and SARIF lists a fixed finding at level `note`.
- The MCP tools `list_runs` and `get_finding` answer from a small summary and the finding's own file instead of decoding the whole ledger of each run. Runs stored by an earlier version are read from the ledger as before.
- Model calls of a long investigation are prepared faster: each message is checked for secrets once, not again on every later turn of the conversation.
- Agent search tools are faster on large targets: the target listing is taken from the mapper and shared by every stage of a run, and a file is scanned for secrets once and again only when it changes.
- The deterministic scan is faster: the built-in code, secret and infrastructure seeders process files in parallel, each secret rule runs only on files that contain one of its literal markers, listing the target no longer stats every file twice, and a file is read once for the mapper and all built-in seeders instead of up to three times.
- A rule now reports at most 50 leads per file and a seeder at most 5000 leads per run, so one generated or vendored file can no longer bury a report or exhaust memory. The seeder line in the report says how many leads were dropped and where. The report of an external scanner is read up to 256 MiB.
- The `go` directive in `go.mod` is now `1.26.11`, so a source install with an older Go 1.26 toolchain builds with the current patch release and its standard library fixes.
- `report`, `verify`, `doctor` and `debug` now accept only the flags they read. A flag that used to be accepted and ignored, such as `spackle report latest --fail-on low`, is now a usage error with exit code 2.
- The notes that say which languages have automatic proofs now name them as "Go, Python, JavaScript and TypeScript", as the documentation does. The list is generated from one table of supported languages.

### Fixed

- The Semgrep adapter runs Semgrep with the `p/default` rule set instead of `--config auto`, which Semgrep refuses with metrics off. It used to fail on every run, so a scan got no Semgrep leads. Metrics stay off.
- The lead count shown for each seeder is now the number of its leads the scan reports. In a diff scan (`--since`), and with `[scan] exclude` or `disable_rules`, it used to be the count for the whole target, so the seeder lines did not add up to the lead total.
- A scan that is cancelled no longer hands further files to the built-in seeders, and a cancelled scan of a small target is reported as stopped early instead of complete.
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
- Release pipeline: the container image is built only after the release tests pass, a prerelease tag no longer moves the `latest` image tag, and the image reports the same version, commit and build date as the release archives.
- The GitHub Action could not be loaded: `action.yml` was not valid YAML (an unquoted colon in an input description). It now parses, and a new workflow runs the Action against the demo app on Linux, macOS and Windows.
- The Action `args` input now accepts several lines. It used to read only the first line and drop the rest silently. A value with quotes, which would have been split into pieces, is refused with a clear message.
- The GitHub Action no longer stops at the scan step when the scan finds something. The step ran under `bash -e`, so a scan that exited 1 ended it before the SARIF upload and left the `exit-code` and `sarif` outputs empty.
- Scanner results that an external scanner adapter could not classify are no longer dropped without a word: the seeder line in the report now says how many were skipped and why.
- A fix to a file that exists but is empty is now written as a modification. It used to be written as a file creation, which `git apply` refuses.
- A GitLab repository in a subgroup (`https://gitlab.com/group/subgroup/project`) is now recognized as a git URL instead of a running application, and the refusal for an unrecognized address on a code hosting site says to use the clone URL ending in `.git`.
- `spackle doctor` now uses the same container runtime detection as a scan, so it no longer reports a daemonless Podman as not answering while scans run proofs in it. It also checks the TypeScript sandbox image.
- The HTML report now shows control characters and bidirectional overrides as visible escapes, like the terminal and Markdown reports. They used to reach the page raw, so a quoted line could display in a different order than its bytes.
- Built-in rule accuracy: the Python SQL call rules now require SQL text, so `ssh.execute("cd " + d)` is no longer reported as SQL injection; the insecure-random rules require a sensitive word that stands on its own, so a random index into `keys` is no longer reported; and a rule finding carries the same OWASP categories as a model-drafted finding of its class.
- `spackle bench`: a fixture whose scan failed is no longer counted as a clean fixture left alone or as missed flaws. Failed fixtures are left out of the totals and counted in their own `failed_fixtures` figure, and no results file is written for such a run unless `--force` is given.
- One definition of "test code" is now used everywhere. A fix can no longer edit a test under `test/`, `spec/` or a `conftest.py`, and the built-in code rules skip the same files the mapper and the fixer treat as tests.
- Sandbox limits and other numeric settings are now checked when the configuration is loaded. A `[sandbox] timeout` above the 15 minute cap or a negative limit is refused before the run starts, instead of failing every proof after the model call that wrote it.
- `spackle debug`: bisect now checks the committed code at HEAD first and, when it does not show the failure, says the cause is uncommitted changes instead of blaming the HEAD commit. A `--test` name that matches no test is refused before any model call, instead of being read as a failing or a passing test.
- The running-target note "N URL(s) were outside the authorized scope" now counts each URL once instead of once per page that links to it.
- The wall time cap now also bounds a model call or sandbox run that is in progress when the cap is reached. Such a call is stopped and the run ends as budget exhausted; it used to run on for as long as the provider client or the sandbox timeout allowed.
- The clone of a git URL target is removed when no run comes of it (the run is refused, not confirmed, or a dry run). It used to stay under the state directory with nothing referring to it.
- A provider response with a success status and a body that cannot be decoded (an HTML page from a proxy, or a response over the size limit) is no longer requested again. It used to be sent up to three times, each of which a hosted provider could charge for.
- `spackle verify` no longer marks a finding fixed when its proof never succeeded during the scan. It re-runs only the proofs of findings the scan demonstrated and says which findings it skipped.
- A run that is cancelled or reaches its deadline while a provider request is in flight is reported as stopped. It used to be reported as a failed request with a hint to check the network.
- Standard input redirected from the null device (`< /dev/null`, `< NUL`) is no longer taken for a terminal. `scan`, `bench` and `runs prune` now say that there is no terminal to confirm on and to pass `--yes`, instead of showing a prompt nobody can answer.
- Runs started in the same second now sort in the order they were started, so `latest`, `spackle runs` and `spackle runs prune --keep` no longer pick the older of two such runs. A run id keeps its form: after the timestamp come a two-digit sequence number and four random hex digits, where there used to be six random digits.
- A running-target assessment that uses up the scope's `max_requests` now ends with outcome `budget-exhausted`, and the report lists the findings that were not assessed. It used to end as `completed`, and a finding could be dismissed by a model that had been refused the requests it asked for.
- `spackle verify` no longer marks a finding fixed when its proof prints the marker and then exits with an error. The flaw was still observed, so the outcome is inconclusive and the finding keeps its status. The scan, the fixer and verify now judge a proof run by one rule.
- The map cache is used again on the second and later scans of a clean repository. The default state directory `.spackle`, untracked inside the target, used to make the work tree count as changed, so the cache was written once and never read.
- Long model output, proof output and error text are no longer cut in the middle of a multi-byte character, which left a replacement character in the ledger and the reports.

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
