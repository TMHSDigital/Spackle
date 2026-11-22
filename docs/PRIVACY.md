# Privacy

This document says what leaves your machine during a Spackle run, what is redacted first, and what is stored locally.

## What leaves the machine

| Mode | Sent to a model provider | Network destinations | Notes |
| :--- | :--- | :--- | :--- |
| No model configured | Nothing | None from Spackle for a local directory. A git URL target is cloned from its remote. A running target receives scope-bound requests | The run ends after the mapper and the seeders, or after the baseline probe for a running target. Leads are reported with confidence `plausible` and proof status `not-run` |
| Hosted provider (Anthropic, OpenAI, OpenRouter and other OpenAI-compatible endpoints) | The prompts described in the next section, with detected secrets redacted | The provider's endpoint, plus the destinations in the row above | The provider's own retention and training terms apply. Spackle does not control them. The API key is read from an environment variable and sent only to that provider as a credential. Provider redirects are never followed |
| Local model (Ollama, or an OpenAI-compatible server on a loopback address) | The same redacted prompts, sent to the local server | The loopback address of the model server, plus the destinations in the first row | Spackle sends nothing to a third party. A model server on another machine on your network is a remote destination, not a local one |
| `--offline` | Only to a provider whose endpoint is loopback, or nothing if no model is configured | Loopback only, for connections Spackle itself makes | A provider that is not on loopback is refused before the run starts. The dialer refuses every non-loopback address, checked on the resolved IP, and proxies are ignored. A running target must be on loopback too. Private LAN addresses are refused |

Two points apply to every row:

- Redaction runs before every provider call, including calls to a local model.
- `--offline` governs connections made by the Spackle process. See "External tools" below for programs Spackle starts.

## What is sent to a model

When a model is configured, a provider receives these and nothing else:

- **System prompts.** Spackle's own instructions for each stage. They contain no target content.
- **The map summary and the leads**, to the planner: languages, frameworks, entry points and trust boundaries with their file names and line numbers, and each lead's title, location and redacted snippet.
- **Excerpts of files the model asked to read.** Investigators, the reviewer, the prover and the fixer have read-only tools: `read_file`, `list_dir`, `grep`, `find_symbol`, `find_references`, `git_log` and `git_show`. What a tool returns is sent back to the model. That is source code, file names, and commit messages and patches from the target's history. A model sees only the files it asks for, and only inside the target.
- **Finding text.** The reviewer, the prover, the fixer and the chain analysis are given the finding under work: its title, location, description, quoted flow and attack steps.
- **Sandbox output.** When a proof or a candidate fix fails, its output is sent back so the model can correct it.
- **For a running target: request and response excerpts.** The model is given the recorded exchanges for a finding, and the result of any follow-up request it makes through the scope-bound `http_request` tool: status, response headers and the first part of the body. Credential headers and cookie values are masked in what is stored and shown.
- **In debug mode: the failure.** The test output or the issue text you passed with `--issue`, and the output of the reproduction.

All target content is wrapped in a delimited envelope that marks it as data, and all of it passes through secret redaction first.

With per-stage models, each stage's prompts go to that stage's provider.

## What is always redacted

Every outbound message passes through redaction before a provider call: the system prompt, user text, tool results, and tool arguments being replayed. Tools also redact their own output before returning it. A detected secret is replaced by `[REDACTED:<rule>:<hash>]`, the name of the rule that matched and a short hash of the value.

The rules cover private key blocks, AWS access key ids and secret keys, GitHub and GitLab tokens, Slack tokens and webhooks, Stripe keys, Google API keys, Anthropic and OpenAI keys, JSON Web Tokens, passwords in URLs, and a generic rule for high-entropy values assigned to secret-looking names.

The same applies to what is stored. A secret finding records the file, the line, the rule and the short hash, never the value. Sandbox output and recorded exchanges are redacted before they are written.

Redaction works by pattern. A secret in a format no rule matches is not detected and is not redacted.

## What is not redacted

When a model is configured, these are sent to it as they are:

- Source code excerpts from the target.
- File paths and commit messages.
- HTTP traffic from a running target, minus detected secrets and masked credential headers.

If the source itself is confidential, use a local model, run with no model, or use `--offline`.

## No telemetry and no update check

Spackle has no telemetry. It does not report usage, errors or findings to the project or to anyone else. It does not check for updates. It makes no network connection that the run does not require.

## What is stored locally

Each run writes to the state directory, `.spackle/` in the working directory unless `state_dir` says otherwise. Files are created with owner-only permissions.

| Item | Location | Content |
| :--- | :--- | :--- |
| Ledger | `runs/<run-id>/ledger.jsonl` | The record of the run: see below |
| Findings | `runs/<run-id>/findings/<id>/` | `finding.json`, the proof under `poc/`, sandbox output under `evidence/`, `fix.patch`, `review.md` |
| Exchanges | `runs/<run-id>/evidence/exchanges/` | Every request and response sent to a running target, redacted, with stored bodies capped in size |
| Reports | `runs/<run-id>/reports/` | Terminal, Markdown, HTML, JSON and SARIF |
| Map cache | `cache/` | The target map, keyed by commit |
| Clones | `clones/<run-id>/` | The shallow clone of a git URL target |
| Fix worktrees | `worktrees/<run-id>/` | The checkout that holds the fix branch |

### What the ledger stores

- The run's start and end: target, commit, mode, provider and model names, the authorized scope and how it was given, the sandbox profile.
- The map summary, each seeder's status, and every lead with its redacted snippet.
- Every planned investigation.
- For each model call: the stage, the provider, the model, token counts, cost, and an error message if the call failed.
- For each tool call: the stage, the tool, its arguments (redacted and cut to 500 characters), whether it failed, and the size of the result.
- For each sandbox run: the purpose, image, command, exit code, isolation profile, and a pointer to the output file.
- For each HTTP exchange: the method, URL, status, and a pointer to the stored exchange.
- Every finding in full, every verdict, every rejected draft with its reason, and what was skipped under a budget cap.

### What the ledger does not store

- **Prompts and completions.** A model call is recorded as accounting only. The text sent to and received from a model is not written anywhere.
- **Tool results.** Only their size is recorded.
- **API keys.** They are read from the environment at the moment a provider is built and are never written.
- **Secret values.** Only the rule, the location and a short hash.

Findings do quote source lines, and evidence files hold sandbox output and captured traffic. Treat the state directory as sensitive. It describes weaknesses in your system and contains working proofs of concept. Add `.spackle/` to `.gitignore` and do not commit or share it without review. Remove real hostnames and unredacted reports before attaching anything to a public issue.

Spackle does not upload this folder anywhere. With `--pr`, it pushes the fix branch to the repository's `origin` remote and opens a draft pull request whose body lists the fixed findings: their ids, titles, locations and severities.

## External tools

Spackle can use programs that are separate from it. They run locally with your privileges and have their own network behavior. Spackle cannot control what another program does once it runs, so in `--offline` mode it does not start the ones that need the network: Semgrep, osv-scanner and Trivy are skipped and listed as skipped in the report, a git URL target is refused instead of cloned, and a sandbox image that is not already on the machine is not pulled (the proof is reported as not run). gitleaks and hadolint work on local files and still run.

- **External scanners.** Semgrep, gitleaks, osv-scanner, Trivy and hadolint run when they are on your `PATH`. Some of them fetch rules or vulnerability databases themselves: Spackle runs Semgrep with `--config auto` and `--metrics off`, and osv-scanner and Trivy look up vulnerability data. Check each scanner's own documentation for what it downloads and what it reports.
- **Container images.** The sandbox uses the `golang`, `python` and `node` images named in config. An image that is not present locally is pulled on first use, which contacts the container registry. `spackle doctor` reports which images are present.
- **Git.** A git URL target is cloned from its remote. `--pr` pushes a branch.
- **The GitHub CLI.** `--pr` calls `gh` to open the pull request.

For a run with no outside traffic: use `--offline`, scan a local directory, and pull the sandbox images in advance so proofs can still run.
