# Comparison with other tools

Status: this describes the v0.1.0 design. `ROADMAP.md` tracks which milestones have landed.

## How to read this

Spackle is new and unproven. Every other tool on this page is established, has real users, and has been tested against far more code and far more targets than Spackle has. Where this page says "Spackle does differently", it describes the v0.1.0 design, not a measured result. Spackle publishes no benchmark numbers until a results file is committed.

Spackle uses several of these tools as lead sources. Its seeders can run Semgrep, gitleaks, osv-scanner, Trivy, and hadolint when they are installed, and feed their output into the pipeline. In those cases Spackle depends on the other tool and does not replace it.

This page avoids version-specific claims. Products change, and some statements below are marked as not verified. Check each project's own documentation before you rely on a detail here. Corrections are welcome.

## ARTEX

ARTEX is an open source agentic engine for offensive security testing. It is the project that prompted Spackle: the Spackle design document describes it as a pure offensive tool that shipped with listening ports and default credentials and was reused by criminals. ARTEX is licensed under AGPL-3.0. Spackle is a clean-room project. It copies no code, prompts, or assets from ARTEX, and credits it as inspiration only. The statements about ARTEX on this page come from the Spackle design document and have not been verified against the current ARTEX release.

Does better than Spackle:

- Broader offensive tooling for reconnaissance and exploitation.
- Long-running multi-agent orchestration.
- A user interface for watching and steering a run.
- More time in use on real engagements.

Spackle does differently:

- Requires an explicit authorized scope before any request to a live target.
- Opens no listener and has no credentials to default.
- Redacts detected secrets before any model call.
- Adds remediation: it writes a patch and verifies it against the tests and the proof.
- Keeps proofs as evidence in a run folder and does not package them as standalone tools.
- Is licensed under Apache-2.0.

## Semgrep

Semgrep is a static analysis tool that matches patterns in source code using rules written in a syntax close to the language being scanned. It has an open source engine and a commercial platform. The split of features between the two changes over time and is not verified here.

Does better than Spackle:

- A mature rule ecosystem with broad language coverage, maintained over many years.
- Speed. A scan is fast enough to run on every commit.
- Determinism. The same rules on the same code give the same result.
- Simple custom rules that a team can write and review.
- No model required, so no model cost and no source sent to a provider by the engine.

Spackle does differently:

- Uses Semgrep as one lead source when it is installed.
- Adds model stages that reason about whether a lead is reachable, and a reviewer that tries to refute it.
- Tries to prove a finding by running a proof of concept in a sandbox.
- Writes a patch and re-runs the tests and the proof against it.
- Also examines running targets and infrastructure files.

## CodeQL

CodeQL is a semantic code analysis engine from GitHub. It builds a database from source code and runs queries written in the QL language against it. It powers GitHub code scanning. Its license terms differ between open source and private code, so check them for your use.

Does better than Spackle:

- Deep interprocedural dataflow and taint tracking.
- A full query language for expressing precise, custom analyses.
- A large library of maintained queries.
- Deterministic results.
- Tight integration with GitHub pull requests and alerts.

Spackle does differently:

- Does not build a semantic database. Its code analysis is seeders plus model review, which is less rigorous than a dataflow engine.
- Tries to demonstrate a finding with a proof of concept in a sandbox.
- Writes and verifies a fix.
- Covers running targets and infrastructure files as well as code.
- Needs no build of the target for its deterministic path.

## Snyk

Snyk is a commercial developer security platform. It covers open source dependencies, first-party code, container images, and infrastructure as code, and integrates with source hosts, CI systems, and editors.

Does better than Spackle:

- A curated vulnerability database maintained by a dedicated research team.
- Commercial support, service terms, and organization-level reporting and policy.
- Broad integrations and an established workflow for dependency upgrades, including automated fix pull requests.
- Coverage of many languages and package ecosystems.

Spackle does differently:

- Runs as a local binary with no account and no hosted service.
- Can run fully offline, with no model or with a loopback model.
- Has no vulnerability database of its own. It relies on osv-scanner and Trivy for dependency leads when they are installed.
- Tries to prove a finding in a sandbox and labels its confidence as `demonstrated`, `high`, or `plausible`.
- Is open source under Apache-2.0.

## GitHub Copilot Autofix

Copilot Autofix is a GitHub feature that uses a model to suggest fixes for code scanning alerts, shown in the pull request or alert view. Which alert sources and languages it covers, and which plans include it, are not verified here.

Does better than Spackle:

- Works inside the pull request flow developers already use, with no setup on the developer machine.
- Builds on CodeQL alerts, which rest on precise dataflow analysis.
- Is run and maintained by GitHub as a hosted service.

Spackle does differently:

- Runs on the operator machine and works with a model the operator chooses, including a local one.
- Verifies a fix by re-running the tests and the proof of concept in a sandbox, and rejects a patch that regresses or fails to close the proof.
- Finds issues itself. Autofix fixes alerts that another scanner raised.
- Works outside GitHub.

## nuclei

nuclei is an open source scanner from ProjectDiscovery. It sends requests described by YAML templates and matches the responses. Templates cover several protocols, with HTTP the most common.

Does better than Spackle:

- A very large community template library that tracks newly disclosed vulnerabilities.
- Speed and scale across many hosts.
- Deterministic, reviewable checks: a template states exactly what is sent and what counts as a match.
- No model required.
- Wide adoption and long use in real testing.

Spackle does differently:

- Does not use nuclei as a lead source in v0.1 and has no comparable template library. Its DAST baseline is a small fixed set of non-destructive probes.
- Binds every request to an authorized scope, and refuses redirects and links that leave it.
- Sends state-changing methods only when the scope file allows them.
- Connects a running-target finding to source code and a fix when the source is available.

## CAI (Cybersecurity AI by Alias Robotics)

CAI is an open source framework from Alias Robotics for building and running AI agents for security work. As far as we know, it supports many model providers and gives agents command execution and security tooling. Its current feature set is not verified here.

Does better than Spackle:

- A general agent framework: users can compose their own agents, tools, and workflows.
- Broader offensive capability, including work that needs a shell and existing security tools.
- Flexibility for tasks Spackle does not attempt, such as capture-the-flag challenges and open-ended engagements.
- A published research record from its authors.

Spackle does differently:

- Is a fixed staged pipeline, not a framework. It trades flexibility for enforceable scope and budgets and reproducible reports.
- Gives the model no shell on the host. Model-written code runs only in a sandbox container.
- Enforces scope, budgets, and tool permissions in code, where the model cannot change them.
- Renders reports from an append-only ledger.
- Ends with a verified fix.

## PentestGPT

PentestGPT is an open source tool that uses a language model to guide a penetration test. It began as a research project in which the model suggests next steps and the human tester carries them out. Later versions may automate more of this. That is not verified here.

Does better than Spackle:

- Supports a human tester through an open-ended engagement and adapts to what the tester finds.
- Handles targets and techniques outside Spackle's fixed surfaces.
- Has a published academic evaluation.
- Keeps a human in the loop for each action, at least in its original design.

Spackle does differently:

- Runs a pipeline without a human choosing each step, inside a scope fixed before the run.
- Examines source code and infrastructure files as well as running targets.
- Produces typed findings with computed CVSS 4.0 scores, not free-form guidance.
- Tries to prove findings in a sandbox and writes and verifies fixes.

## Summary table

Cells use "yes", "no", "partly", "varies", or "not verified". Notes follow the table.

| Tool | Primary surface | Proves findings | Writes fixes | Runs offline | Listens on a port by default |
|---|---|---|---|---|---|
| Spackle | Code, running targets, infrastructure files | partly | yes | yes | no |
| ARTEX | Running targets (offensive testing) | not verified | not verified | not verified | yes |
| Semgrep | Source code | no | partly | yes | no |
| CodeQL | Source code | no | no | yes | no |
| Snyk | Dependencies, code, containers, infrastructure as code | no | partly | no | no |
| GitHub Copilot Autofix | Code scanning alerts on GitHub | no | yes | no | no |
| nuclei | Running targets | partly | no | partly | no |
| CAI | Agent framework for security tasks | varies | not verified | not verified | not verified |
| PentestGPT | Running targets (guided testing) | varies | no | not verified | not verified |

Notes:

- **Spackle, proves findings.** Auto-run proofs cover Go, Python, and TypeScript/JavaScript, and need a container runtime. Without one, nothing is demonstrated.
- **Spackle, writes fixes.** The fixer needs a model. With no model, Spackle reports leads only.
- **Spackle, runs offline.** With no model, or with a model on loopback. External scanners and image pulls have their own network behavior, described in `docs/PRIVACY.md`.
- **ARTEX, listens.** This is taken from the Spackle design document, not from a check of the current release.
- **Semgrep, writes fixes.** Rules can carry a fix pattern. Model-assisted fixes belong to the commercial platform, as far as we know.
- **Semgrep and CodeQL, runs offline.** With rules or query packs already on disk.
- **Snyk, runs offline.** The usual setup calls the Snyk service. Self-hosted or air-gapped options are not verified here.
- **Snyk, writes fixes.** Mainly dependency upgrades, plus suggested code fixes in some products.
- **nuclei, proves findings.** A template match is evidence from a real response. How strong that evidence is depends on the template.
- **nuclei, runs offline.** Templates can be local, but the tool exists to send traffic to targets.
- **CAI and PentestGPT, proves findings.** These tools act against a target, or guide a tester who does. Whether a result counts as proof depends on the run.
