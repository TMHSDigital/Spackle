# Contributing to Spackle

Thanks for helping. Bug reports, detection accuracy reports, new rules, and documentation fixes are all welcome.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go through a private report, described in [SECURITY.md](SECURITY.md), and not through a public issue.

Spackle is pre-release. [ROADMAP.md](ROADMAP.md) lists the milestones and [CHANGELOG.md](CHANGELOG.md) records what has landed.

## The one rule

Every change is reviewed against one rule:

> Spackle is for systems the operator owns or has written permission to test.

In practice, a contribution will not be merged if it does any of the following, however useful it is otherwise:

- Weakens the scope gate, or adds a path to a live request that does not pass through it.
- Adds a listener.
- Sends unredacted content to a model provider.
- Copies code or prompts from ARTEX. ARTEX is licensed AGPL-3.0 and Spackle is a clean room project under Apache-2.0. If you have read ARTEX source closely, say so in the pull request.

## Set up

You need Go 1.26 or newer and git. Docker or Podman is optional and is needed only for the sandbox tests, which skip with a clear message when no runtime is present.

On Windows, in PowerShell:

```powershell
git clone https://github.com/TMHSDigital/Spackle
cd Spackle
.\make.ps1 build
```

On Linux and macOS:

```shell
git clone https://github.com/TMHSDigital/Spackle
cd Spackle
make build
```

Both entry points take the same targets: `build`, `test`, `lint`, `fmt`, `tidy`, `bench`, `clean`. Use `.\make.ps1 <target>` on Windows and `make <target>` elsewhere.

`lint` needs [golangci-lint](https://golangci-lint.run) v2 on your `PATH`. The dev container in `.devcontainer/` installs it for you.

## Check your change

Run the same three commands CI runs:

```shell
make lint
make test
make build
```

On Windows:

```powershell
.\make.ps1 lint
.\make.ps1 test
.\make.ps1 build
```

CI runs on Linux, macOS, and Windows with no API key and no container runtime. Tests must pass in that environment. Use the fake provider in `internal/llm` for anything that would otherwise call a model.

## How the code is laid out

`cmd/spackle/main.go` only calls `cli.Main`. Everything else lives under `internal/`.

| Package | Responsibility |
|---|---|
| `cli` | Subcommand dispatch, flags, exit codes, help with the authorized-use notice |
| `config` | `spackle.toml` loading, flag and env merge, per-stage provider selection |
| `target` | Classifies a target as a local path, git URL, or live URL, and decides whether the scope gate applies |
| `authz` | The authorized-scope gate: scope file parsing, host and CIDR matching, per-run confirmation |
| `mapper` | The target map, built with no model: languages, frameworks, entry points, trust boundaries, test and build commands |
| `seed` | Lead producers: external scanner adapters and built-in rules for code, secrets, Dockerfile, Kubernetes, Terraform, and CI workflows |
| `redact` | Secret detection and redaction, used by seeders and by the provider wrapper |
| `envelope` | Wraps untrusted content in nonce-delimited data blocks and neutralizes delimiter forgery |
| `llm` | The provider interface and its implementations (`anthropic`, `openai`, `ollama`, `fake`), usage and cost normalization, the offline guard |
| `budget` | Hard caps on tokens, cost, wall time, sandbox runs, and findings, plus stagnation detection |
| `ledger` | The append-only `ledger.jsonl` writer and reader |
| `finding` | The finding schema, validation, CVSS 4.0 scoring, dedup, and ranking |
| `agent` | Planner, investigator, reviewer, prover, and fixer loops, and the allowlisted tool registry |
| `sandbox` | The container runtime abstraction (Docker, Podman): isolation profile, limits, copied-in source |
| `dast` | The scope-bound HTTP client, baseline probe, crawl, and request and response capture |
| `debug` | Debug mode: reproduce, bisect, root cause, fix, verify |
| `gitx` | Git plumbing: commit SHA, worktree and branch creation, bisect, clone |
| `report` | Renderers for terminal, Markdown, HTML, JSON, and SARIF 2.1.0. The only input is a ledger |
| `mcp` | The stdio MCP server |
| `bench` | The corpus runner and scoring |

The table describes the design. Some packages may not exist yet. The design document is in `docs/superpowers/specs/`.

## Benchmark

`make bench` (or `.\make.ps1 bench`) runs the corpus under `bench/corpus/` and writes a results file under `bench/results/`.

- A number appears in the README or the docs only if it comes from a committed results file.
- Never edit a results file by hand. If a number is wrong, fix the cause and run the benchmark again.
- The fixtures under `bench/corpus/` and `examples/demo-app/` are vulnerable on purpose. Do not fix them.

## Sign your commits (DCO)

Every commit needs a sign-off line. Add it with `-s`:

```shell
git commit -s -m "fix(redact): catch keys split across lines"
```

That appends `Signed-off-by: Your Name <you@example.com>` to the message. By signing off you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org). In short, you state that:

- You wrote the contribution, or you have the right to submit it under the project's open source license.
- If it builds on someone else's work, that work came under a compatible open source license and you may submit it with your changes.
- If someone else gave it to you, they certified one of the points above and you have not changed it.
- You understand the contribution and your sign-off are public and kept with the project indefinitely.

The full text at the link above is what you are agreeing to. The summary here does not replace it.

## Pull requests

- Branch from `main` and keep each pull request to one change.
- Use [Conventional Commits](https://www.conventionalcommits.org) for commit messages and the pull request title: `feat(seed): ...`, `fix(authz): ...`, `docs: ...`.
- Add a line to `CHANGELOG.md` under "Unreleased" when users will notice the change.
- Add or update tests. Write the test first where you can.
- A new dependency needs a reason, recorded in `docs/ARCHITECTURE.md`. The standard library is the default.
- Match the prose style of the docs: plain sentences, no emojis, no em dashes.

## Reporting bugs and false positives

- For a crash, a wrong exit code, or broken output, use the [bug report form](https://github.com/TMHSDigital/Spackle/issues/new?template=bug_report.yml).
- For a false positive, a false negative, a wrong severity, or a wrong fix, use the [detection accuracy form](https://github.com/TMHSDigital/Spackle/issues/new?template=detection_accuracy.yml). A minimal snippet that reproduces the result is the most useful thing to attach.

Do not paste secrets, real target hostnames, or unredacted reports into an issue.
