# CI

Spackle runs in CI two ways: through the GitHub Action in this repository, or as a plain binary in any other system. Both run the same `spackle scan`.

The default costs nothing. With no model configured a scan runs the deterministic stages only: the built-in rules and whichever scanners are installed on the runner. It needs no key and calls no model. You add a model when you want leads investigated.

## The GitHub Action

A complete workflow for pull requests:

```yaml
name: spackle

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: TMHSDigital/Spackle@v0.1.0
        with:
          version: v0.1.0
          fail-on: high
```

`contents: read` lets the job check out the code. `security-events: write` lets it upload the SARIF report to code scanning. Nothing else is needed.

`uses: TMHSDigital/Spackle@v0.1.0` pins the action's own steps. The `version` input chooses which Spackle release those steps install, and its default is `latest`. Set both to the same tag when you want the run to be repeatable.

What the action does, in order:

1. Downloads the release archive for the runner's operating system and architecture, and verifies it (see below).
2. Runs `spackle scan <path> --yes --format sarif,markdown --out <temp dir> --fail-on <fail-on>`, with `--no-fix` unless you set `fix: true`.
3. Appends the Markdown report to the job summary.
4. Uploads the SARIF report to code scanning, under the category `spackle`.
5. Fails the job with the scan's exit code. The upload runs first, so a failing scan still shows its alerts.

Release archives exist for Linux, macOS and Windows runners on x64 and arm64.

### Inputs

| Input | Default | Meaning |
| :--- | :--- | :--- |
| `path` | `.` | Directory to scan, relative to the workspace |
| `version` | `latest` | Spackle release to install, for example `v0.1.0`. `latest` resolves the newest release |
| `fail-on` | `high` | Lowest severity that fails the job: `critical`, `high`, `medium`, `low` or `never` |
| `upload-sarif` | `true` | Upload the SARIF report to code scanning. Needs `security-events: write` |
| `provider` | empty | Model provider: `anthropic`, `openai`, `openai-compatible` or `ollama`. Empty runs the deterministic stages only |
| `model` | empty | Model name for the provider |
| `base-url` | empty | Endpoint for the `openai-compatible` provider |
| `budget-usd` | `2` | Hard cap on model spend for the run, in USD. Used only when `provider` is set |
| `fix` | `false` | Write and verify fixes. Off by default in CI; findings are still reported |
| `args` | empty | Extra arguments passed to `spackle scan`, split on spaces and line breaks, so the value may span several lines. One argument cannot contain a space, and a value with a quote character is refused with exit code 2 |
| `github-token` | the workflow token | Used to download the release and verify its provenance |
| `spackle-dir` | empty | Directory that already holds a `spackle` binary. When set, no release is downloaded or verified. Meant for testing a build from source |

### Outputs

| Output | Meaning |
| :--- | :--- |
| `sarif` | Path of the SARIF report |
| `exit-code` | Exit code of the scan: 0, 1, 2 or 3 (see [Exit codes](#exit-codes)) |
| `has-sarif` | `true` when the scan wrote a SARIF report |

Give the step an `id` to read them:

```yaml
      - id: spackle
        uses: TMHSDigital/Spackle@v0.1.0
        with:
          fail-on: never
      - run: echo "Spackle exited ${{ steps.spackle.outputs.exit-code }}"
```

### Adding a model

Set `provider` and `model`, and pass the key through `env` from a repository secret. The action never takes a key as an input: Spackle reads keys only from environment variables.

```yaml
      - uses: TMHSDigital/Spackle@v0.1.0
        with:
          version: v0.1.0
          provider: anthropic
          model: claude-opus-5-5
          budget-usd: '2'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The variable depends on the provider:

| Provider | Variable |
| :--- | :--- |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openai` | `OPENAI_API_KEY` |
| `openai-compatible` | `SPACKLE_API_KEY`, or the variable named by `api_key_env` in a committed `spackle.toml` |

With a model, the run spends money, up to `budget-usd`. The action passes `--yes`, so nobody is asked to confirm the estimate: setting `provider` is the consent. If Spackle has no price for the model (every `openai` model, and most `openai-compatible` endpoints other than OpenRouter), the dollar cap cannot be enforced, so the scan is refused with exit code 2 and the message shows the `[pricing]` table to commit in `spackle.toml`. To run under the token cap alone, set `args: --allow-unpriced`. See [config.md](config.md#pricing).

A committed `spackle.toml` in the scanned repository's working directory is read as usual. Use it for per-stage models, budgets other than the dollar cap, or pricing. Point at a file elsewhere with `args: --config path/to/spackle.toml`.

Pull requests from forks do not receive repository secrets, so a model step has no key there. Keep the deterministic default for those runs.

Proofs and fix checks need a container runtime on the runner. Without one, a model run still investigates and reports, and labels its findings as traced by reading the code.

### SARIF and code scanning

The report is SARIF 2.1.0. What it carries:

- One result per finding that is not dismissed. Dismissed findings are left out.
- One rule per finding class, with CWE tags.
- `level`: `error` for critical and high, `warning` for medium, `note` for low and none.
- `security-severity`: the CVSS 4.0 score, which code scanning uses for its own severity labels. Unscored findings carry none.
- A fingerprint equal to the finding id. Ids are derived from the class and the location, so the same flaw keeps its alert across runs.
- `confidence` and `proof_status` as result properties.

Set `upload-sarif: false` to skip the upload and handle the file yourself through the `sarif` output.

### How the action verifies what it downloads

The install step does three things before it runs anything:

1. Downloads the archive and `checksums.txt` from the release with the GitHub CLI.
2. Checks the archive's SHA-256 against its line in `checksums.txt`.
3. Runs `gh attestation verify <archive> --repo TMHSDigital/Spackle`, which checks that the archive carries build provenance from this repository's release workflow.

If either check fails, the step fails and Spackle is never run. Action inputs reach the scan through environment variables and as separate arguments. They are never interpolated into the script.

## Exit codes

| Code | Meaning | In the action |
| :--- | :--- | :--- |
| 0 | The scan ran. No unresolved finding at or above `fail-on` | The job passes |
| 1 | The scan ran. At least one unresolved finding at or above `fail-on` | The job fails, after the SARIF upload |
| 2 | Refused before running: bad arguments, bad configuration, or missing authorization | The job fails |
| 3 | The run itself failed | The job fails |

A finding is unresolved when its status is `open` or `patch-available`. A patch that Spackle wrote and checked is not applied to the code that was scanned, so such a finding still fails the job until the patch is merged and a later scan or `spackle verify` no longer reproduces it. Fixed and dismissed findings do not count toward the threshold. The SARIF report agrees with this rule: unresolved findings keep the level of their severity, and a fixed finding is listed at level `note`. `fail-on: never` makes a successful scan exit 0 whatever it found.

## Other CI systems

Spackle is one static binary. Download a release archive, verify it, and run it.

```shell
# Verify, with the GitHub CLI
sha256sum --ignore-missing -c checksums.txt
gh attestation verify spackle_<version>_linux_amd64.tar.gz --repo TMHSDigital/Spackle

# Scan
spackle scan . --yes --format sarif,markdown --out spackle-report --fail-on high --no-fix
```

The reports land in `spackle-report/report.sarif` and `spackle-report/report.md`. Status lines go to standard error. Use the exit code to pass or fail the job. All five formats are also kept under `.spackle/runs/<run-id>/reports/`.

To add a model, export the key variable from your CI system's secret store and pass `--provider`, `--model` and `--budget-usd`, or commit a `spackle.toml`.

## Two rules for CI

**`--yes` is required.** CI has no terminal. Without `--yes`, a run that would call a paid model is refused, because a pipe is not consent to spend money. With `--yes`, Spackle never prompts: the budgets and any authorization must come from flags or from the config file. A deterministic scan of a directory does not prompt either way, but pass `--yes` so the job never waits on a question.

**A running target in CI needs a committed scope file.** A URL target always goes through the authorized-scope gate. With `--yes`, or with no terminal, the typed confirmation is not offered, so the scope must come from `--authorize <scope-file>` or a `[scope]` table in `spackle.toml`. Without one the run is refused with exit code 2 and nothing is sent.

```shell
spackle scan http://localhost:8081 --yes --authorize ci/scope.toml --format sarif --out spackle-report
```

```toml
# ci/scope.toml
hosts = ["localhost:8081"]
statement = "Ephemeral instance started by this CI job."
```

Commit the scope file so the authorization is reviewed like any other change. The file format and the matching rules are in [config.md](config.md#scope).
