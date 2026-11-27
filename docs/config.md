# Configuration

Spackle runs with no configuration at all. A scan with no model configured runs the deterministic stages and costs nothing. You add configuration to choose a model, change the budgets, authorize a running target, or tune the sandbox.

## Where configuration comes from

Three layers, strongest first:

1. Command line flags.
2. `spackle.toml` in the working directory, or the file you name with `--config`.
3. Built-in defaults.

Rules worth knowing:

- A missing `./spackle.toml` is fine: the defaults apply. A missing file named with `--config` is an error.
- An unknown key in the file is an error, so a typo cannot silently do nothing.
- Every problem in the file is reported at once, with the table it is in.
- A flag overrides one value. The exception is `--provider`: naming a provider that differs from the one in `[model]` replaces the whole `[model]` table, so a stale model name or base URL is never sent to the new provider. Pass `--model` (and `--base-url` where needed) along with it.
- API keys are never read from flags or from the file. The file names the environment variable that holds the key. A value in `api_key_env` that looks like a key is rejected.

`spackle doctor` loads the same configuration and checks it, including a free round trip to each configured provider. `spackle doctor --format json` prints the same checks for a program to read: `version`, `ready`, and `checks`, each with `area`, `name`, `status` (`ok`, `missing`, `warn` or `fail`) and `note`. The exit code is 2 when a required check failed, in either format.

## Every key and its default

This file is valid as written and equals the built-in defaults. Commented lines show optional keys that have no default.

```toml
# Where runs, the map cache, clones and fix worktrees are stored.
state_dir = ".spackle"

# true is the same as passing --offline on every command.
offline = false

# [model] is absent by default: no model, deterministic stages only.
# [model]
# provider = "anthropic"          # anthropic, openai, openai-compatible or ollama
# model = "claude-opus-5-5"       # required once a provider is set
# base_url = ""                   # required for openai-compatible; optional elsewhere
# api_key_env = ""                # NAME of the environment variable that holds the key
# max_output_tokens = 0           # cap on one completion; 0 lets the provider layer choose

# Per-stage overrides. Stages: planner, investigator, prover, reviewer, fixer, mechanical.
# [stages.planner]
# provider = "ollama"
# model = "<a local model>"

[budget]
tokens = 2000000        # input plus output tokens for the run
usd = 5.0               # model spend for the run
wall_time = "30m"       # a duration such as 90s, 30m or 2h
sandbox_runs = 40       # container runs for the run
max_findings = 50       # findings reported, highest ranked first
max_turns = 24          # tool-use turns in one agent conversation (code scans and debug)
# allow_unpriced = false  # true lets an unattended run use a model with no known price although usd is set

[scope]
# hosts = ["localhost:8081"]   # absent by default: no running target is authorized
path_prefixes = ["/"]
allow_unsafe_methods = false   # true permits POST, PUT, PATCH and DELETE
max_requests = 400
requests_per_second = 5.0
statement = ""                 # your note on why you are authorized; recorded in the ledger

[sandbox]
runtime = "auto"        # auto, docker, podman or none
network = "none"        # none or scope
memory_mb = 1024
cpus = 2.0
pids = 256
timeout = "2m"          # one container run; values above 15m are refused

[sandbox.images]
go = "golang:1.27"
python = "python:3.13-slim"
javascript = "node:24-slim"
typescript = "node:24-slim"

[fix]
enabled = true
max_attempts = 3
pr = false              # true is the same as --pr

[scan]
exclude = []            # globs of paths not to read, for example ["bench/corpus/**"]
include = []            # default-skipped directories to read anyway, for example ["build"]
disable_rules = []      # rule ids whose leads are dropped
# scanners = ["gitleaks", "hadolint"]  # external scanners that may run; absent: every installed one

# [test] is absent by default: the test commands come from the project (see Project test commands).
# [test]
# command = ["npx", "vitest", "run"]                  # runs the whole suite
# single = ["npx", "vitest", "run", "-t", "{name}"]   # runs one test for spackle debug --test

[output]
formats = ["terminal"]  # terminal, markdown, html, json, sarif
dir = ""                # same as --out
fail_on = "high"        # critical, high, medium, low or never
fail_on_confidence = "plausible"  # plausible, high or demonstrated: the confidence a finding needs to count toward fail_on

# Prices in USD per million tokens, for models Spackle has no price for.
# [pricing."<model name>"]
# input_per_mtok = 0.0
# output_per_mtok = 0.0
```

Flags that map onto these keys: `--provider`, `--model`, `--base-url`, `--budget-tokens`, `--budget-usd`, `--allow-unpriced`, `--max-findings`, `--offline`, `--fix`, `--no-fix`, `--pr`, `--format`, `--out`, `--fail-on`, `--fail-on-confidence`, `--exclude` (repeatable, adds to `[scan] exclude`). `--authorize` names a scope file and `--yes` turns off every prompt. `spackle scan <git URL> --ref <branch or tag>` scans that branch or tag instead of the remote's default branch; the ref is recorded in the run next to the commit it resolved to. A commit hash is not accepted as a ref. `spackle scan <directory> --since <revision>` reports only on files changed since that revision (a branch, a tag or a commit of the directory's git repository): leads in other files are left out, the report says how many, and with a model only the changed files are planned for investigation. It is refused for a git URL and for a running target. `--changed` does the same for the files that differ from the last commit (staged or not) and new files git does not ignore, for a scan before you commit; it cannot be combined with `--since`. [ci.md](ci.md#scan-only-what-a-pull-request-changed) has the details. `spackle scan <directory> --resume <run id>` continues a run that stopped on its budget (see [Budgets](#budgets)). `spackle scan <target> --dry-run` maps the target and runs the seeders, then prints what would be read, each seeder's status and lead count, the leads by class, how many investigations would be planned and the cost estimate. With `--yes` it also says when the real run would be refused because its dollar cap cannot be enforced for a model without a known price (see [Pricing](#pricing)). It calls no model, stores no run and exits 0; with `--format json` it prints the same as one JSON object. It works for a directory or a git URL, not for a running target.

Stored runs accumulate under `state_dir`. `spackle runs` lists them, newest first, with target, outcome and finding count (`--format json` for a program). `spackle runs prune --keep <n>` deletes all but the newest `n`, and `--older-than <age>` (for example `30d` or `72h`) deletes runs started longer ago; with both, a run is deleted when either rule selects it. The runs are listed first, and nothing is deleted without `--yes` or a typed confirmation on a terminal. Pruning a run also removes its clone and its fix worktree from the state directory; a fix branch stays in your repository.

`spackle runs compare <older-run-id> <newer-run-id>` joins two stored runs on finding id and lists the findings that are new in the newer run, gone from it, and present in both (with any change of status or severity), as text or with `--format json`. Dismissed findings are left out. With `--fail-on <severity>` (and optionally `--fail-on-confidence`) it exits 1 when a new finding is at or above that severity and still unresolved; without it, it exits 0 whatever it found. A finding id includes the line, so code that moved to another line shows as one finding gone and one new. There is no flag for `state_dir`, the sandbox settings, `wall_time`, `sandbox_runs` or `max_turns`: set those in the file.

Each command accepts only the flags it reads, and any other flag is a usage error (exit code 2). `scan` takes all of them. `bench` takes all but `--authorize`, `--pr`, `--fail-on`, `--fail-on-confidence` and `--format`, and its `--out` is the directory for the results file. `debug` takes all but `--authorize`, `--pr`, `--fail-on` and `--fail-on-confidence`. `report` takes `--config`, `--format`, `--out` and `--finding`. `verify` takes `--config`, `--offline`, `--format` (`text` or `json`) and `--finding` (repeatable: re-run only that finding's proofs; an id not in the run exits 2). `doctor` takes `--config`, `--offline`, `--format` and the three model flags. `runs` and `rules` take `--format` (`runs` also `--config`); `runs prune` takes `--config`, `--keep`, `--older-than` and `--yes`; `runs compare` takes `--config`, `--format`, `--fail-on` and `--fail-on-confidence`. `spackle <command> --help` lists them.

## Providers

Spackle talks to each provider over plain HTTPS with no vendor SDK. Pick one provider for the run, and optionally a different one per stage.

Only Ollama, running locally, was exercised against a live endpoint during development. The wire format of every other provider on this page is covered by tests against recorded request and response shapes, not by live calls. Run `spackle doctor` after you configure one: it validates the key and the model name with a request that costs nothing.

### Anthropic

```toml
[model]
provider = "anthropic"
model = "claude-opus-5-5"
```

The key is read from `ANTHROPIC_API_KEY` unless `api_key_env` names another variable.

```shell
export ANTHROPIC_API_KEY=...        # PowerShell: $env:ANTHROPIC_API_KEY = "..."
spackle scan . --provider anthropic --model claude-opus-5-5
```

This needs API credits from the Anthropic console. A claude.ai Pro or Max subscription is not API access and cannot be used here.

Requests go to `https://api.anthropic.com/v1/messages`. Set `base_url` only if you route through a gateway that speaks the same API.

### OpenAI

```toml
[model]
provider = "openai"
model = "<an OpenAI model name>"
```

The key is read from `OPENAI_API_KEY` unless `api_key_env` names another variable.

```shell
export OPENAI_API_KEY=...
spackle scan . --provider openai --model "<an OpenAI model name>"
```

Requests go to `https://api.openai.com/v1/chat/completions`. Spackle has no built-in price for OpenAI models, so add a `[pricing]` entry (see [Pricing](#pricing)) if you want the dollar cap to apply. A run with `--yes` and a dollar cap you set is refused until you do, or until you pass `--allow-unpriced`.

### OpenAI-compatible: the flexible path

`provider = "openai-compatible"` works with any endpoint that implements Chat Completions with tool calling. `base_url` is required and is the API root: Spackle appends `/chat/completions` to it. The key is read from `SPACKLE_API_KEY` unless `api_key_env` names another variable, which is what the blocks below do. On the command line the key variable cannot be named, so export `SPACKLE_API_KEY` there.

**OpenRouter**

```toml
[model]
provider = "openai-compatible"
base_url = "https://openrouter.ai/api/v1"
model = "anthropic/claude-opus-5-5"
api_key_env = "OPENROUTER_API_KEY"
```

```shell
export SPACKLE_API_KEY=...
spackle scan . --provider openai-compatible --base-url https://openrouter.ai/api/v1 --model anthropic/claude-opus-5-5
```

Model names carry the vendor prefix. Spackle asks OpenRouter to report the real cost of each request and uses that figure, so the dollar cap works without a `[pricing]` entry.

**Azure OpenAI**

```toml
[model]
provider = "openai-compatible"
base_url = "https://<resource>.openai.azure.com/openai/deployments/<deployment>?api-version=<api version>"
model = "<deployment name>"
api_key_env = "AZURE_OPENAI_API_KEY"
```

The base URL includes the deployment path and the `api-version` query. Spackle keeps the query when it appends `/chat/completions`. For hosts ending in `.openai.azure.com` or `.cognitiveservices.azure.com` the key is sent in the `api-key` header automatically. `model` is still required; use the deployment name.

**Together, Groq, Fireworks**

```toml
[model]
provider = "openai-compatible"
base_url = "https://api.together.xyz/v1"
model = "<a model name from the provider>"
api_key_env = "TOGETHER_API_KEY"
```

```toml
[model]
provider = "openai-compatible"
base_url = "https://api.groq.com/openai/v1"
model = "<a model name from the provider>"
api_key_env = "GROQ_API_KEY"
```

```toml
[model]
provider = "openai-compatible"
base_url = "https://api.fireworks.ai/inference/v1"
model = "<a model name from the provider>"
api_key_env = "FIREWORKS_API_KEY"
```

The variable names in `api_key_env` are yours to choose. These endpoints do not report cost in a form Spackle reads, so add a `[pricing]` entry for the model.

### Local and offline

**Ollama**

```toml
[model]
provider = "ollama"
model = "<a tool-calling model you have pulled>"
```

```shell
spackle scan . --provider ollama --model "<a tool-calling model you have pulled>"
```

No key. The default endpoint is `http://127.0.0.1:11434`; set `base_url` if yours differs. Spackle uses Ollama's native chat API.

**llama.cpp, LM Studio, vLLM**

Any local server that serves Chat Completions works through `openai-compatible` with a localhost `base_url`. No key is needed for a loopback address.

```toml
[model]
provider = "openai-compatible"
base_url = "http://127.0.0.1:8080/v1"   # use the port your server listens on
model = "<the model name your server reports>"
```

A model served from a loopback address is treated as local: it costs nothing against the dollar cap and Spackle does not ask you to confirm an estimate.

**What `--offline` does**

`--offline` (or `offline = true`) is enforced in two places:

- Before anything runs, every configured provider is checked. If a provider's endpoint is not a loopback address, the run is refused.
- The HTTP client that providers use gets a dialer that resolves the name and refuses any address that is not loopback. Proxy settings from the environment are ignored in this mode.

Loopback means `localhost`, a name ending in `.localhost`, `127.0.0.0/8` or `::1`. A private LAN address such as `192.168.1.20` is refused: it is another machine. A running target must also be on loopback when `--offline` is set.

`--offline` refuses any connection Spackle itself would make to another machine: a remote model provider is rejected before the run starts, and a running target must be on localhost. It also keeps Spackle from starting things that would use the network on its behalf: a git URL target is refused instead of cloned, Semgrep, osv-scanner and Trivy are skipped (they download rules or vulnerability data) and shown as skipped in the report, and a sandbox image that is not already local is not pulled. See [PRIVACY.md](PRIVACY.md).

**What to expect from a local model**

This is agentic work. Each investigation is a multi-turn loop of tool calls that must end in strictly formatted JSON. It needs a capable tool-calling model: a strong coding model in the larger size classes. Small models underperform. They miss findings, quote code that is not in the file (those drafts are rejected) and produce malformed tool calls.

`spackle doctor` asks Ollama about the configured model and warns in two cases: the model does not report the `tools` capability, or its parameter size is below 20 billion. Both are warnings. Neither blocks a run.

### Per-stage models

Six stages can each use their own model:

| Stage | What it does |
| :--- | :--- |
| `planner` | Turns the map and the leads into a prioritized list of investigations |
| `investigator` | Traces one question through the code, or assesses one running-target observation |
| `reviewer` | Tries to refute a finding from fresh context |
| `prover` | Writes the proof of concept (and the reproduction script in debug mode) |
| `fixer` | Writes the patch (and the diagnosis in debug mode) |
| `mechanical` | Looks across confirmed findings for chains |

This example sends the reasoning-heavy stages to one model and the cheap ones to a local model:

```toml
[model]
provider = "anthropic"
model = "claude-opus-5-5"

[stages.planner]
provider = "ollama"
model = "<a local tool-calling model>"

[stages.mechanical]
provider = "ollama"
model = "<a local tool-calling model>"
```

Investigators, the reviewer, the prover and the fixer have no entry, so they use `[model]`.

The inheritance rule:

- A stage with no entry uses `[model]`.
- A stage entry must set `provider`. An entry without one is an error: the configuration is refused (exit code 2), because the entry would otherwise be ignored without a word.
- When the stage's provider is the same as `[model]`'s, the fields it leaves empty (`model`, `base_url`, `api_key_env`) are inherited. So `[stages.mechanical]` with `provider = "anthropic"` and `model = "claude-haiku-5-5"` reuses the default key variable.
- When the provider differs, nothing but `max_output_tokens` is inherited. Give the stage its own `model`, and its own `base_url` if the provider needs one.
- A table named for anything but the six stages is an error.

Every stage's provider is built before the run starts, so a missing key for one stage refuses the run before a run directory is created.

### Pricing

Spackle needs a price to turn tokens into dollars. The built-in table covers Anthropic first-party models only. These are list prices in USD per million tokens, from Anthropic's published model table as of 2026-11-03:

| Model | Input | Output | Cached input read |
| :--- | ---: | ---: | ---: |
| `claude-fable-5-2` | 8 | 40 | 0.20 |
| `claude-mythos-5-2` | 8 | 40 | 0.20 |
| `claude-fable-5-1` | 10 | 50 | 10% of input |
| `claude-fable-5` | 10 | 50 | 10% of input |
| `claude-opus-5-5` | 4 | 20 | 0.20 |
| `claude-opus-5` | 5 | 25 | 10% of input |
| `claude-opus-4-8` | 5 | 25 | 10% of input |
| `claude-opus-4-7` | 5 | 25 | 10% of input |
| `claude-opus-4-6` | 5 | 25 | 10% of input |
| `claude-sonnet-5-5` | 2 | 10 | 0.10 |
| `claude-sonnet-5` | 2 | 10 | 10% of input |
| `claude-sonnet-4-6` | 3 | 15 | 10% of input |
| `claude-haiku-5-5` | 0.10 | 0.50 | 10% of input |
| `claude-haiku-4-5` | 1 | 5 | 10% of input |

Cache writes are priced at 125% of input. Prices change; check the provider's current table and override an entry when it has moved.

Everything else needs one of two things:

- A `[pricing]` entry. It overrides the built-in table and adds models that are not in it:

  ```toml
  [pricing."<model name>"]
  input_per_mtok = 3.0
  output_per_mtok = 15.0
  ```

  For a router that names models `vendor/model`, an entry for either the full name or the part after the slash matches.

- A provider that reports the cost of each request. OpenRouter does, and Spackle uses its figure.

A local model always costs zero.

**What "cost unknown" means.** When a remote model has no price and the provider reports none, the call is recorded with a cost of zero and marked as unknown. The dollar cap then cannot stop the run, because nothing is added to the spend. The token cap, the wall time cap and the sandbox run cap still apply. Spackle says so before the run starts, `spackle doctor` warns about it, and the report marks the cost as unknown.

**A dollar cap you set is not silently dropped.** When nobody confirms the estimate (`--yes`, the GitHub Action, the MCP server, the benchmark) and you set the dollar cap yourself, with `usd` under `[budget]` or with `--budget-usd`, a run with an unpriced remote model is refused with exit code 2 before any model call. The message shows the `[pricing."<model>"]` table to add. To run anyway under the other caps, pass `--allow-unpriced` or set `allow_unpriced = true` under `[budget]`. The rule does not apply to the built-in default cap, to a local model, to OpenRouter (which reports its own cost), or when you answer the prompt on a terminal: the prompt carries the warning.

## Budgets

Caps are hard limits enforced in Go. No tool call and nothing in target content can raise them. A cap cannot be turned off: zero or a missing value means the default, and a negative value is an error.

| Key | Flag | Default | What it caps |
| :--- | :--- | ---: | :--- |
| `tokens` | `--budget-tokens` | 2,000,000 | Input plus output tokens across every model call |
| `usd` | `--budget-usd` | 5 | Model spend, where the price is known |
| `wall_time` | none | 30m | Time since the model stages started |
| `sandbox_runs` | none | 40 | Container runs: proofs, compile checks, test runs, fix checks |
| `max_findings` | `--max-findings` | 50 | Findings in the report |
| `max_turns` | none | 24 | Tool-use turns in one agent conversation |
| `allow_unpriced` | `--allow-unpriced` | false | Not a cap: lets an unattended run start with an unpriced model although `usd` is set (see [Pricing](#pricing)) |

`tokens`, `usd`, `wall_time` and `sandbox_runs` apply only when a model is configured. `max_findings` applies to every run.

`max_turns` applies to the agent conversations of a code scan and of debug mode. The model assessment of a running-target finding is capped at 8 turns whatever `max_turns` says.

What happens when a cap is reached:

- **Tokens, spend or wall time.** No new model call is made. Before each investigation Spackle also checks that roughly one more would fit, and stops planning new ones when it would not. Findings already produced are kept. The run ends with outcome `budget-exhausted`, and a `budget.skip` ledger event lists what was not investigated. The report shows that list. Leads that were never investigated are still reported, as `plausible`.

  To continue such a run, or one that was interrupted, pass its id: `spackle scan <directory> --resume <run id>` (or `--resume latest`). The new run does not plan again. It investigates what the earlier run planned and did not reach, with a new budget, and carries the earlier findings into its report, so that report is complete on its own. A finding the new run investigates or dismisses replaces the earlier entry for it. The new run's `run.start` event names the earlier run in `resumed_from`, and the earlier run is left as it is. A resume is refused when the earlier run has nothing left to investigate, when it scanned another directory, and when the directory's commit has changed since (pass `--force` to continue anyway: the plan and the carried findings then describe older code). It needs a model, and it works for a directory, not for a git URL or a running target. After a run that stopped on its budget, `spackle scan` prints the command to continue it.
- **Interrupt (Ctrl-C).** An agentic scan stops at the next step and keeps what it has: each finding is written to the ledger as soon as its investigation, review, proof and fix are done. The run ends with outcome `interrupted`, the reports are written, the report lists what was not investigated, and the command exits 3 because the run did not finish.
- **Sandbox runs.** No further container is started. A finding that could not be demonstrated or fix-checked for that reason keeps the labels it had earned.
- **Max findings.** Findings are ranked, the list is cut, and the ones dropped are named in a `budget.skip` event. One run plans at most 30 investigations whatever the other caps say.
- **Max turns.** The conversation gets one last request with no tools and a prompt to answer from what it has seen. The same happens when a model repeats identical tool calls four times.

Before a run that will call a paid model, Spackle prints an estimate and asks you to confirm. `--yes` skips the question. With no terminal and no `--yes` the run is refused: a pipe is not consent to spend money. A run on a local model does not ask.

## Scope

A local directory or a git URL needs no scope. A running target, given as an `http://` or `https://` URL, always does, and that includes `localhost`. Nothing is sent, and no run directory is created, until the scope gate passes.

Authorization comes from the first of these that is present:

1. `--authorize <scope-file>`.
2. A `[scope]` table with `hosts` in `spackle.toml`.
3. On a terminal only, a typed confirmation: Spackle shows the host and you type it back. Case and surrounding spaces are ignored; anything else, including `y`, is not accepted. This is never offered with `--yes`, without a terminal, or over MCP.

A source that is present but does not cover the target is a refusal. Spackle never falls through to the next source, so a wrong scope file cannot be papered over by a prompt.

### The scope file

A scope file is TOML. The keys sit at the top level or under `[scope]`, so a table copied from `spackle.toml` works unchanged. Mixing both places in one file is an error, and so is an unknown key.

```toml
hosts = ["localhost:8081", "staging.example.test"]
path_prefixes = ["/"]
allow_unsafe_methods = false
max_requests = 400
requests_per_second = 5
statement = "Staging environment owned by my team. Ticket SEC-123."
```

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `hosts` | none, required | Hosts that may receive requests, as `host` or `host:port` |
| `path_prefixes` | `["/"]` | Paths that may be requested |
| `allow_unsafe_methods` | `false` | Permit POST, PUT, PATCH and DELETE |
| `max_requests` | 400 | Requests for the whole run, counting every redirect hop. When the cap is reached while a model assesses the findings, the run ends with outcome `budget-exhausted` and the report lists the findings that were not assessed |
| `requests_per_second` | 5 | Rate limit. Values above 50 are lowered to 50 |
| `statement` | empty | Your note on why you are authorized. Recorded in the ledger |

### Matching rules

- **Hosts match exactly.** No wildcards, no aliases, no DNS. `localhost`, `127.0.0.1` and `[::1]` are three different hosts: list the one your URL uses. Names are compared in lower case.
- **Ports.** An entry without a port means the default port of the request's scheme (80 for http, 443 for https). An entry with a port matches that port only.
- **Host syntax.** A plain host or `host:port`. A scheme, a slash, a wildcard, userinfo or whitespace is refused. IPv6 addresses go in brackets. International names are written in punycode.
- **Paths.** A request path is decoded and cleaned first, so `/api/../admin` is judged as `/admin`. It is in scope when it equals a prefix or sits under it at a segment boundary: `/api` covers `/api` and `/api/users`, not `/apiv2`. Paths with an encoded slash or backslash, a backslash, or doubly encoded dots are refused outright, because a server may resolve them differently.
- **Methods.** GET, HEAD and OPTIONS are always permitted in scope. POST, PUT, PATCH and DELETE need `allow_unsafe_methods = true`. No other method is ever sent.
- **Schemes.** `http` and `https` only.
- **Redirects.** Followed by Spackle itself, at most 5 hops, each hop checked against the scope. A redirect that leaves the scope is not followed and the refusal is recorded. A 307 or 308 that would repeat a state-changing request at another URL is not followed.
- **Userinfo.** `http://allowed@other.test/` is judged as `other.test`, and credentials in a URL are never sent.

The same rules bind the baseline probe and the `http_request` tool a model uses. The tool has no argument that reaches the scope, the request cap or the rate limit.

**A running-target scan is not authenticated.** There is no setting for a login, a session cookie or an authorization header, and a cookie the target sets is not sent back. The scan covers what an anonymous visitor can reach, and every report of such a scan says so in its run notes.

## Sandbox

Proofs of concept, compile checks, test runs and fix checks run only in a container. Spackle drives the `docker` or `podman` command line.

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `runtime` | `auto` | `auto` tries Docker, then Podman. `none` disables the sandbox |
| `network` | `none` | `none`, or `scope` to attach the runtime's default bridge network to every proof and fix check of a code scan. Nothing filters that network: a proof can reach whatever the bridge reaches. There are no running-target proofs that need it in this version |
| `memory_mb` | 1024 | Memory limit. Swap is set to the same value, so there is no extra swap |
| `cpus` | 2 | CPU limit |
| `pids` | 256 | Process limit |
| `timeout` | 2m | Wall-clock limit for one run, enforced by the host. Above 15m is refused |
| `[sandbox.images]` | see above | Image per language: `go`, `python`, `javascript`, `typescript` |

Every run uses `--network none` (by default), `--cap-drop ALL`, `--security-opt no-new-privileges`, a read-only root filesystem, user `65534:65534`, and tmpfs mounts for `/work` and `/tmp`. Your source is mounted read-only and copied into `/work` inside the container, so the working tree cannot be changed. The copy leaves out top-level directories a run cannot need: `.git`, `.hg`, `.svn`, `.spackle`, `.venv`, `venv`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.terraform`, `.idea` and `.vscode`. `node_modules` and `vendor` are copied, because a proof or a test suite may import from them. `/work` is held in memory and counts against `memory_mb`, so the limit has to cover the copied source as well as the program. A copy that fails or does not finish within `timeout` is reported as a setup failure, never as a proof result. Go module downloads are turned off when there is no network.

Things to know:

- With no runtime, or `runtime = "none"`, nothing model-written is executed. Findings are still reported, labelled as traced by reading the code.
- Proofs run automatically for Go, Python, JavaScript and TypeScript targets. Other languages get findings and analysis without a proof.
- With no network, a proof can use only the language's standard library and what is already in your repository. Nothing can be installed.
- `network = "scope"` gives the container the runtime's ordinary bridge network. Spackle does not filter that traffic to your scope: only the container runtime's own networking applies. Leave it at `none` unless you have a specific reason.
- An image that is not present is pulled on first use. `spackle doctor` shows which images are local.
- The default images are tags, which move as the upstream projects publish patches. For runs that must be repeatable, set `[sandbox.images]` to digests (`python:3.13-slim@sha256:...`). The defaults are built into each release, so an old release keeps its old defaults: set your own images there too once a default is past its end of life.

## Scan coverage

| Key | Flag | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `exclude` | `--exclude` (repeatable) | none | Paths that are not read and whose scanner leads are dropped |
| `include` | none | none | Directories to read although their name is skipped by default |
| `disable_rules` | none | none | Rule ids whose leads are dropped |
| `scanners` | none | every installed scanner | External scanners that may run: `semgrep`, `gitleaks`, `osv-scanner`, `trivy`, `hadolint` |

Patterns are forward-slash globs relative to the target root. `*` and `?` match within one path segment and `**` matches any number of segments, so `bench/corpus/**` excludes that tree and `**/testdata/**` excludes every `testdata` directory. A pattern with no slash, such as `*.min.js`, is also matched against the file or directory name alone.

Some directories are not read by default, and each one that is pruned is listed in the report as "Not read":

- Dependency trees, caches and editor state, wherever they appear: `node_modules`, `.venv`, `venv`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.next`, `.nuxt`, `.terraform`, `.idea`, `.vscode`.
- `vendor`, `dist`, `build`, `target` and `coverage`, when they sit directly under the target root, or deeper when a marker shows they are dependencies or build output (for example `vendor` beside a `go.mod`, `dist` beside a `package.json`, `target` beside a `Cargo.toml` or holding `CACHEDIR.TAG`). A nested directory with one of these names and no marker, such as a `target` package, is read.

Name a pruned directory in `include` (for example `build` or `services/api/vendor/**`) when it holds source you answer for. Version control data (`.git`, `.hg`, `.svn`) and Spackle's own state directory are never read.

A rule id is the part after the colon in a finding's origin (`builtin-code:py-sql-fstring` is rule `py-sql-fstring`). Write `source:rule` to disable a rule for one scanner only. `spackle rules` (or `spackle rules --format json`) lists every built-in rule with its source, id, class, severity, CWE and the files it reads. A scan warns when `disable_rules` names something that looks like a built-in id (such as `py-sql-fstrng`) but matches none; ids of external scanners are not checked.

`scanners` chooses which external scanners run, before any of them starts, so a scanner you leave out costs no time and downloads nothing. Without the key every installed scanner runs; `scanners = []` runs none, and the built-in rules always run. A scanner left out is listed in the report and in `spackle doctor` as not run, with the reason. A name that is not one of the five is refused when the configuration is loaded.

Every excluded path is listed in the report as "Not read", and the report notes the configured exclusions, inclusions and disabled rules with the number of leads each removed, so a reader can see what the scan did not cover. The map cache is not used while `exclude` or `include` is set.

Two fixed limits keep one noisy file from burying a report: a rule reports at most 50 leads per file, and a seeder at most 5000 leads per run. When a limit drops leads, the seeder's line in the report says how many and names the rule and file with the most matches. Exclude the file, or disable the rule, to see the rest of the picture.

## Fixes

| Key | Flag | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `enabled` | `--fix`, `--no-fix` | `true` | Write and check fixes |
| `max_attempts` | none | 3 | Patch attempts per finding |
| `pr` | `--pr` | `false` | Push the fix branch and open a draft pull request |

Fixing needs a model and a container runtime. The fixer returns whole files, at most three per finding, and only files that already exist. Spackle computes the unified diff. A patch is rejected when the changed files no longer compile or parse, when the project's tests passed before and fail after, when it changes more than 400 lines, when it touches a test or proof file, or when the proof of concept still succeeds against the patched code.

A finding is marked `patch-available` only when a proof of concept that demonstrated it stops working against the patched code. The patch is not applied to your code, so the finding still counts toward `fail_on` until you merge it; `spackle verify` marks it `fixed` once the proof no longer succeeds against the code itself. When there was no proof to re-run, a patch that passes the other checks is still offered, labelled `unverified`, and the finding stays `open`.

Your working tree, index and current branch are never changed. Each patch is written to `findings/<id>/fix.patch` in the run directory. When the fixed files are tracked by git, the patches are also committed to a new branch `spackle/<run-id>` in a separate worktree under `<state_dir>/worktrees/`. `--pr` pushes that branch and opens a draft pull request through the GitHub CLI (`gh`), which must be installed and signed in.

## Project test commands

Spackle runs the project's own tests in the sandbox in three places: once on the unmodified code before a scan's fixer checks a patch, after a patch to see that the suite still passes, and in `spackle debug`, where `--test <name>` reproduces one failing test. By default it picks the commands itself from the project's main language:

| Language | Whole suite | One test (`--test`) |
| :--- | :--- | :--- |
| Go | `go test ./...` | `go test -count=1 -run ^<name>$ ./...` |
| Python | `python -m pytest -q` when pytest is named in the project's requirements, otherwise `python -m unittest discover` | `python -m pytest -q -k <name>`, or `python -m unittest -k <name>` |
| JavaScript, TypeScript | `npm test` when `package.json` has a test script | `node --test --test-name-pattern <name>` |

When those do not fit, for example a project on Jest, Vitest or Mocha, tests run through `make` or `tox`, or one package of a large Go module, set them under `[test]`:

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `command` | absent | The program and arguments that run the whole suite |
| `single` | absent | The program and arguments that run one test. Every `{name}` in an argument is replaced by the `--test` value |

```toml
[test]
command = ["npx", "vitest", "run"]
single = ["npx", "vitest", "run", "-t", "{name}"]
```

Each is an argument vector, not a shell line: the program comes first, every argument is its own string, and the test name stays inside the one argument it is placed in. Both run only in the sandbox, in the image of the project's language (`[sandbox.images]`), so the program must exist in that image. They apply to the project's main language. A run that uses them says so in its notes. `single` must contain `{name}`, and an empty argument or a first element that starts with `-` is an error when the configuration is loaded.

`spackle.toml` is read from the working directory. When you run Spackle from inside the project you scan, a `[test]` table committed in that project chooses commands Spackle runs in the sandbox; read it as you would a test script before running a scan with a model and a container runtime.

## Output

Every run writes all five formats to `<state_dir>/runs/<run-id>/reports/`, whatever you ask for. `formats` and `--format` choose what the command also prints or copies.

| Format | File | Notes |
| :--- | :--- | :--- |
| `terminal` | `report.txt` | The default. Printed to standard output. Color only on a terminal, never with `NO_COLOR` set |
| `markdown` | `report.md` | |
| `html` | `report.html` | One self-contained file |
| `json` | `report.json` | |
| `sarif` | `report.sarif` | SARIF 2.1.0, shaped for GitHub code scanning |

Where non-terminal formats go:

- With `--out <dir>` (or `dir`), each one is written to `<dir>/report.<ext>`.
- With no `--out` and exactly one format requested, it is printed to standard output.
- With no `--out` and several formats, they stay in the run directory and the path is printed.

Progress and status lines go to standard error, so standard output is safe to redirect.

`spackle report <run-id>` re-renders a stored run from its ledger alone. The run id may be a unique prefix, or `latest`. `--finding <id>` (repeatable) renders only those findings, as terminal text unless you pass `--format`; an id that is not in the run exits 2.

### Exit codes

`fail_on` (or `--fail-on`) is the lowest severity that makes `scan` exit 1. Findings with status `open` or `patch-available` count: a checked patch that is not applied leaves the flaw in the scanned code. `never` always exits 0 when the run itself succeeds. `fail_on_confidence` (or `--fail-on-confidence`) is the lowest confidence a finding needs to count: `plausible` (the default, every finding), `high` or `demonstrated`.

| Code | Meaning |
| :--- | :--- |
| 0 | The command ran. No open finding at or above the threshold |
| 1 | The command ran. At least one open finding at or above the threshold |
| 2 | Refused before running: bad flags, bad configuration, a target that does not exist, a missing scope, a run that was not confirmed |
| 3 | The run itself failed |

Other commands use the same codes with their own meaning of 1:

- `spackle verify` exits 1 when at least one stored proof still succeeds or could not be verified (it timed out, was killed, or the sandbox failed).
- `spackle debug` exits 1 when the failure is still open or the run ended early. `fail_on` does not apply to it.
- `spackle doctor` exits 2 when a required check fails.
- `spackle report` exits 0 when the report was rendered, whatever it contains.
