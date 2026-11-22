# Security policy

## Reporting a problem

Report security problems privately:

**<https://github.com/TMHSDigital/Spackle/security/advisories/new>**

Do not open a public issue for them. Include the version or commit you ran, your operating system, what you did, and what happened. Leave out secrets, real target hostnames, and unredacted reports. You should get a first reply within seven days.

## Supported versions

Spackle is pre-release. Once releases exist, fixes go into the latest release and the `main` branch. Until then, fixes go into `main`.

## What counts

Spackle is designed to examine systems on behalf of the person running it. It must never work against that person, and it must never reach past the scope they authorized. These are security problems:

- Spackle opening a listener of any kind.
- A secret value reaching a model provider or appearing in a report.
- Content from a target changing the scope, the budget, or the tool permissions of a run.
- A proof of concept or other model-written code executing on the host outside the sandbox.
- A model reading a file outside the target, or a fix changing your working tree, index or current branch.
- A request leaving the authorized scope, including through a redirect or a followed link.
- `--offline` allowing a connection to a non-loopback address.
- A sandbox escape made possible by Spackle's own configuration of the container.
- A target repository running code on the host through Spackle's use of git.
- The MCP server: a tool call that scans or reads outside the directories named with `--root`, reaches a running target, or reads outside the runs directory.
- The MCP server: a tool call that makes Spackle call a model, and so spend money, when the server was started without `--allow-model`.
- An API key being accepted from a flag or a config file, written to disk, or sent to a host other than its provider.
- A release artifact whose signature or provenance does not verify.

## What does not count

These are not security problems in Spackle, and a normal issue is the right place for them:

- Findings Spackle reports about your own code. Those are yours to fix or dismiss.
- False positives and false negatives. Use the [detection accuracy form](https://github.com/TMHSDigital/Spackle/issues/new?template=detection_accuracy.yml).
- Vulnerabilities in the fixtures under `bench/corpus/` and `examples/demo-app/`. They are vulnerable on purpose.

## How Spackle hardens itself

The design rests on four principles. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) describes each one and how it is enforced. [ROADMAP.md](ROADMAP.md) and [CHANGELOG.md](CHANGELOG.md) say what has been built so far.

- **Authorized use only.** A running target requires a scope file, a `[scope]` table in config, or a typed confirmation of the exact host before any request is sent. Redirects and links that leave the scope are refused and logged.
- **No listening ports.** No package opens a listener, and a test fails the build if one appears outside test files. The MCP server speaks over stdin and stdout only, scans only local directories inside the roots you name, and calls a model only when you start it with `--allow-model`.
- **Secrets are redacted before any model call.** Every outbound message and tool result passes through redaction first. A secret finding records the file, line, rule, and a short hash of the value, never the value.
- **Clean room from ARTEX.** No ARTEX code, prompt, or asset is in this repository.

Target content is treated as untrusted data. It reaches a model only inside a delimited envelope, and scope, budgets, and tool permissions are enforced in Go, where no tool can change them.

## Responsible use

Run Spackle only against systems you own or have written permission to test. Testing a system without permission is illegal in most places, and the scope gate exists so that a run cannot do it by accident. Proofs of concept are evidence for the authorized run they belong to. Do not repackage them as standalone tools.
