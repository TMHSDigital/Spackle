# Guidance for coding agents

This file is for AI coding agents working in this repository. Human contributors should read [CONTRIBUTING.md](CONTRIBUTING.md).

## What this project is

Spackle is an agentic security and debugging CLI for systems the operator owns or is authorized to test. It finds flaws, proves them in a container sandbox, explains exploitation and blast radius, and writes the fix. It is one static Go binary (`spackle`, module `github.com/TMHSDigital/spackle`), licensed Apache-2.0.

Do not describe a feature as shipped unless the code and tests for it are on `main`. [ROADMAP.md](ROADMAP.md) and [CHANGELOG.md](CHANGELOG.md) hold the status.

## Commands

| Task | Unix | Windows PowerShell |
|---|---|---|
| Build the binary | `make build` | `.\make.ps1 build` |
| Run the tests | `make test` | `.\make.ps1 test` |
| Run the linters | `make lint` | `.\make.ps1 lint` |
| Format the code | `make fmt` | `.\make.ps1 fmt` |
| Tidy `go.mod` | `make tidy` | `.\make.ps1 tidy` |
| Run the tests with the race detector (needs cgo) | `make test-race` | `.\make.ps1 test-race` |
| Run the benchmark corpus | `make bench` | `.\make.ps1 bench` |
| Remove build output | `make clean` | `.\make.ps1 clean` |
| Lint, test, then build | `make all` | `.\make.ps1 all` |

Run `lint`, `test`, and `build` before you call a change done. CI runs the same three on Linux, macOS, and Windows with no API key and no container runtime.

`lint` runs `go vet` and `golangci-lint` v2. The linter must be built with a Go version at least as new as the one in use. A linter binary built with an older Go fails to load the code: rebuild it with the current toolchain instead of skipping the lint step.

Update report golden files with:

```shell
go test ./internal/report -update
```

Read the diff of every golden file you update. A golden change you cannot explain is a bug.

## Layout

- `cmd/spackle/main.go` only calls `cli.Main`.
- `internal/` holds every package: `agent` (with `agent/tools`), `authz`, `bench`, `budget`, `cli`, `config`, `dast`, `diffx`, `engine`, `envelope`, `finding`, `gitx`, `ledger`, `llm`, `mapper`, `mcp`, `policy`, `redact`, `report`, `sandbox`, `seed`, `target`, `version`, `walk`. The table with one line per package is in [CONTRIBUTING.md](CONTRIBUTING.md) and in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- `bench/corpus/` and `examples/demo-app/` hold fixtures that are vulnerable on purpose. Do not fix them and do not lint them.
- `bench/results/` holds committed benchmark results. Never edit one by hand.
- `docs/superpowers/` holds the design specification (`specs/`) and the implementation plan (`plans/`). Read the spec before you change behavior.

## Hard rules

1. **No listeners in non-test code.** No `net.Listen`, `http.ListenAndServe`, or `http.Server` outside `_test.go` files. A test walks the module's AST and enforces this. Do not weaken or skip that test.
2. **Keys come from the environment only.** API keys are read from the environment variables named in config. Never accept a key in a flag, a config value, or a file, and never log one.
3. **All target content is untrusted.** Source files, HTTP responses, tool output, and issue text go through `internal/envelope` and `internal/redact` before they reach a provider. Scope, budgets, and tool permissions are enforced in Go. Do not add a tool that can change them.
4. **Never copy from ARTEX.** No code, prompts, or assets, and no paraphrase of them. ARTEX is AGPL-3.0 and this is a clean room project. Do not fetch or read ARTEX source while working here.
5. **Live targets go through the scope gate.** `authz.Gate` is the only constructor for a live-target handle. Do not add a second path to a live request.
6. **Model-written code runs only in the sandbox.** With no container runtime, nothing model-written is executed and the proof is marked `not-run`.
7. **No invented numbers.** Benchmark figures come only from a committed results file.

## Working conventions

- **Prose.** No em dashes and no emojis, in docs, comments, commit messages, and user-facing strings. Use commas, colons, or parentheses. Headings are sentence case.
- **Commits.** Conventional Commits (`feat(scope): ...`, `fix(scope): ...`, `docs: ...`), signed off with `git commit -s`.
- **Tests first.** Write the failing test, then the code. Use the fake provider in `internal/llm` for model stages so tests need no key and no network.
- **Windows is first-class.** Build paths with `path/filepath`, never by joining strings with `/`. Expect CRLF in input files and handle it. Do not assume a POSIX shell is present. Golden files are stored with LF.
- **Dependencies.** The standard library is the default. A new module needs a reason recorded in `docs/ARCHITECTURE.md`.
- **Changelog.** Add a line under "Unreleased" in `CHANGELOG.md` for any change a user will notice.
