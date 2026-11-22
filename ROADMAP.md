# Roadmap

## Status

Spackle is pre-release. Version 0.1.0 is in progress and no release has been published. A milestone is ticked below only when its work is merged to `main`. [CHANGELOG.md](CHANGELOG.md) records what has landed.

## v0.1.0 milestones

- [x] M0: public foundation
- [x] M1: mapper, seeders, reporting
- [x] M2: agents and rich findings
- [x] M3: sandbox, prover, fixer
- [x] M4: running-target analysis and debug mode
- [x] M5: GitHub Action, pull request output, MCP server
- [x] M6: benchmark, docs site, release

## After v0.1.0

These are intentions, in no fixed order. None of them is scheduled, and none of them is in the code today.

Running targets:

- Authenticated running-target scans: custom headers and login flows. Today the probe sends unauthenticated requests.
- Model-driven investigation of endpoints beyond the baseline probe's findings. Today a model assesses what the probe flagged and does not explore further.
- Running-target proofs inside the sandbox. Today a running-target finding rests on recorded requests and responses.
- Authenticated crawling with a browser engine.

Proofs and fixes:

- Auto-run proofs for more languages: Java, C#, Rust, Ruby, PHP. Today proofs run for Go, Python, JavaScript and TypeScript.
- Dependency installation inside the sandbox through an allowlisted proxy. Today a proof can use only the standard library and what is in the repository.
- Parallel investigations. Today investigations run one at a time.

Evidence and reports:

- A tamper-evident, hash-chained ledger. Today the ledger is append-only by file mode and convention.
- Baseline files to accept findings, so a known finding stops failing a build.

Surfaces and interfaces:

- An HTTP MCP transport on loopback with a per-session token. Today MCP is standard input and output only.
- MCP tools for verifying and fixing a stored run.
- A local web UI bound to 127.0.0.1 with a per-session token, off by default.
- Cloud account configuration review through read-only provider APIs. Today infrastructure coverage is files on disk.

Distribution:

- A Homebrew tap and a Scoop bucket.

## Not planned

- A hosted service.
- Listening by default.
- Packaging proofs as standalone tools.
