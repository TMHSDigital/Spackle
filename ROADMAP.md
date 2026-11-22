# Roadmap

## Status

Spackle is pre-release. Version 0.1.0 is in progress and no release has been published. A milestone is ticked below only when its work is merged to `main`. [CHANGELOG.md](CHANGELOG.md) records what has landed.

## v0.1.0 milestones

- [x] M0: public foundation
- [x] M1: mapper, seeders, reporting
- [x] M2: agents and rich findings
- [x] M3: sandbox, prover, fixer
- [ ] M4: running-target analysis and debug mode
- [ ] M5: GitHub Action, pull request output, MCP server
- [ ] M6: benchmark, docs site, release

## After v0.1.0

These are intentions, in no fixed order. None of them is scheduled.

- A local web UI bound to 127.0.0.1 with a per-session token, off by default.
- MCP over HTTP on loopback, with the same token model.
- Auto-run proofs for more languages: Java, C#, Rust, Ruby, PHP.
- Cloud account configuration review through read-only provider APIs.
- Authenticated crawling with a browser engine.
- A Homebrew tap and a Scoop bucket.
- Baseline files to suppress accepted findings.

## Not planned

- A hosted service.
- Listening by default.
- Packaging proofs as standalone tools.
