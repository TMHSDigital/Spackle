# Spackle benchmark corpus

WARNING: everything under `bench/corpus/` is intentionally vulnerable. The
fixtures are small, deliberately flawed sample programs and configuration files
that exist only so Spackle can be pointed at them and measured. Never deploy
them, never expose them to a network, and never copy code out of them into a
real project. Every fixture directory carries a `SPACKLE_FIXTURE` marker file
and a `README.md` that says the same thing. Any secret-looking value in the
corpus is a fake placeholder made up for the fixture.

## What the corpus is

A set of labelled targets with known ground truth. Each fixture is a few small
files that either contain planted vulnerabilities at known locations or are
clean decoys that look risky to a naive pattern matcher but are correct.
Running Spackle over the corpus and comparing its findings with the ground
truth gives precision and recall figures that can be tracked over time and
across models.

The vulnerable lines carry no marker comments. What is planted is documented
only in each fixture's `README.md` and `truth.json`.

Fixtures marked `hard` are cases a line-based linter is likely to miss or get
wrong: taint that crosses several functions or files before it reaches the
sink, checks that are present but logically wrong, access control flaws with no
dangerous API involved, and check-then-act races. Each hard fixture explains
why in its README.

The bundled demo target in `examples/demo-app/` uses the same `truth.json`
format and can be scored the same way.

## Fixture naming

- `<lang>-<class>-<nn>`: a vulnerable fixture. `<lang>` is `go`, `py`, `ts`,
  `js` or `infra`; `<class>` is the main vulnerability class planted (for
  `infra` fixtures, the kind of files involved); `<nn>` is a two-digit sequence
  number.
- `<lang>-clean-<nn>`: a clean decoy with nothing planted.

Go fixtures have their own `go.mod` (module `example.com/fixture/<dir>`), so
they are not packages of the parent module. All fixtures use only the standard
library of their language, apart from plain import lines where a well-known
library call is the point of the fixture. Fixture servers bind 127.0.0.1 only.
Some fixtures include a tiny passing test file so that a fix can be checked for
regressions; those tests never exercise the vulnerability.

## truth.json schema

Every fixture has a `truth.json`:

```json
{
  "fixture": "py-sql-injection-01",
  "language": "python",
  "difficulty": "easy",
  "clean": false,
  "description": "One sentence on what is planted and where.",
  "vulnerabilities": [
    {
      "class": "sql-injection",
      "cwe": "CWE-89",
      "file": "app.py",
      "line": 23,
      "sink": "cursor.execute",
      "note": "f-string query built from the q parameter"
    }
  ]
}
```

- `fixture`: the directory name.
- `language`: `go`, `python`, `typescript`, `javascript` or `infrastructure`.
- `difficulty`: `easy` or `hard`.
- `clean`: `true` for decoys, which always have an empty `vulnerabilities`
  array.
- `description`: one sentence on what is planted and where.
- `vulnerabilities[].class`: one of the class names listed below.
- `vulnerabilities[].cwe`: the closest CWE identifier.
- `vulnerabilities[].file`: path relative to the fixture directory, with
  forward slashes.
- `vulnerabilities[].line`: 1-based line of the sink, meaning the line where
  the dangerous operation happens. For a flaw that is an omission (for example
  a container with no non-root user), the line is the nearest concrete anchor
  and the `note` says so.
- `vulnerabilities[].sink`: the function, call or setting at that line.
- `vulnerabilities[].note`: a short explanation.

Allowed class names: `sql-injection`, `command-injection`, `code-injection`,
`unsafe-deserialization`, `template-injection`, `path-traversal`, `ssrf`,
`xss`, `open-redirect`, `hardcoded-secret`, `weak-crypto`, `weak-hash`,
`insecure-random`, `tls-verification`, `jwt-verification`, `auth-bypass`,
`broken-access-control`, `cors-misconfiguration`, `debug-enabled`,
`information-disclosure`, `race-condition`, `container-privilege`,
`container-hardening`, `supply-chain`, `ci-injection`, `ci-permissions`,
`network-exposure`, `public-storage`, `unencrypted-storage`, `xxe`,
`mass-assignment`.

## How matching works

A reported finding matches a truth entry when all three hold:

1. the class is equal,
2. the file is equal (path relative to the fixture directory, forward slashes),
3. the reported line is within 3 lines of the truth line.

Each truth entry can be matched by at most one finding, and each finding can
match at most one truth entry. A matched finding is a true positive. A finding
that matches no truth entry is a false positive; this includes every finding
reported in a clean decoy. A truth entry that no finding matches is a false
negative.

## Metrics

- Precision: true positives divided by all reported findings
  (TP / (TP + FP)). It answers "how much of what Spackle reported is real".
- Recall: true positives divided by all truth entries (TP / (TP + FN)). It
  answers "how much of what is planted did Spackle find".
- Verified-fix rate: of the true positives for which Spackle proposed a fix,
  the fraction whose fix is verified. A fix is verified when, after applying
  it, the fixture still builds, its test suite (where it has one) still
  passes, and a rescan no longer reports the matched finding.
- Cost per finding: total model spend for the run divided by the number of
  true positives. Spend on false positives and on decoys is included in the
  numerator, so noise makes this number worse.

## Results

Results are only ever produced by `make bench`. Numbers are never typed in by
hand, estimated, or copied from another run. Each run writes one file,
`bench/results/<date>-<model>.json`, and that file is committed as produced.
Any figure quoted in documentation must come from a committed results file.

## Adding a fixture

1. Create `bench/corpus/<lang>-<class>-<nn>/` with 1 to 4 small source files.
2. Add `SPACKLE_FIXTURE`, a `README.md` that says what is planted, and
   `truth.json`.
3. Do not annotate the vulnerable lines; the scanner must find them unaided.
4. Never use a realistic credential. Use an obviously fake value assigned to a
   secret-named variable.
5. Check that every `truth.json` line number points at the sink line.
