# Benchmark

Spackle ships a labelled corpus and a command that scores a run against it. This page says what the corpus is, how a finding is matched to ground truth, how each metric is computed, how to run it, and what the numbers do not tell you.

This page states no results. The README shows them, in a table generated from the results files committed under [bench/results](../bench/results).

## What the corpus is

[bench/corpus](../bench/corpus) holds small fixture projects. Each is a few files that either contain planted flaws at known locations or are clean decoys: code that looks risky to a pattern matcher and is correct.

- Fixtures are written in Go, Python, TypeScript and JavaScript, plus infrastructure files (Dockerfiles, Kubernetes manifests, Terraform, CI workflows).
- Every fixture has a `truth.json` that lists each planted flaw with its class, file and line, a `README.md` that says what is planted, and a `SPACKLE_FIXTURE` marker file. The runner refuses a directory without all three, so it cannot be pointed at an arbitrary tree by mistake.
- The vulnerable lines carry no marker comments. The scanner has to find them unaided.
- Fixtures marked `hard` are cases a line-based rule is likely to miss or get wrong: taint that crosses several functions, checks that are present but logically wrong, access control flaws with no dangerous API involved, check-then-act races.

Everything under `bench/corpus/` is vulnerable on purpose. Never deploy it. [bench/README.md](../bench/README.md) has the fixture naming scheme, the `truth.json` schema and the steps for adding a fixture.

## How scoring works

Each fixture is scanned as its own run, in a temporary state directory, and its findings are compared with its `truth.json`. The matching rule, quoted from `internal/bench/score.go`:

> A reported finding matches a truth entry when the class is equal, the file is equal (forward slashes, case-sensitive) and the line is within 3 lines. Each truth entry and each reported finding is matched at most once; when several candidates exist prefer the smallest line distance, then the lower finding id. Dismissed findings are ignored entirely (not TP, not FP). In a clean fixture every non-dismissed reported finding is a false positive.

In practice:

- A matched finding is a **true positive**.
- A finding that is not dismissed and matches no truth entry is a **false positive**. Two findings for one planted flaw give one true positive and one false positive.
- A truth entry that no finding matches is a **false negative**.
- A finding Spackle dismissed counts as nothing. Dismissing a real flaw therefore shows up as a false negative, and dismissing a decoy hit removes a false positive.
- Confidence does not matter to matching. A `plausible` lead at the right class and line is a true positive.
- A fixture whose scan fails is recorded with its error, and its planted flaws count as missed.

## Metrics

Each is computed over the totals for the run, exactly as below. A ratio with a zero denominator is reported as 0. Ratios are rounded to four decimal places in the file.

| Metric | Computation |
| :--- | :--- |
| Precision | TP / (TP + FP). How much of what Spackle reported is real |
| Recall | TP / (TP + FN). How much of what is planted Spackle found |
| F1 | 2 x precision x recall / (precision + recall) |
| Verified-fix rate | Verified fixes / TP |
| Cost per finding | Model spend for the whole run / TP |
| Decoys flagged | The number of clean fixtures with at least one false positive, next to the number of clean fixtures |

Notes on two of them:

- **Verified-fix rate is verified fixes divided by true positives.** The denominator is every true positive, not only the ones Spackle tried to fix. A true positive counts as a verified fix when its finding has status `patch-available` or `fixed` and its verification record starts with `verified`, which means the proof of concept that demonstrated it stopped working against the patched code. A patch that was written but not verified does not count. A deterministic run never attempts a fix, so the table shows `n/a` there, not 0%.
- **Cost per finding includes everything the run spent**, on false positives and decoys too, so noise makes it worse. The table shows `n/a` for a deterministic run or a run with no true positives, and `unknown` when any call used a model whose price Spackle does not know. A number is never guessed.

The file also breaks the totals down by language and by difficulty.

## How to run it

The deterministic run needs no model and costs nothing:

```shell
make bench            # Linux and macOS
.\make.ps1 bench      # Windows PowerShell
```

Both build the binary and run:

```shell
spackle bench --corpus bench/corpus --out bench/results
```

`bench` is a maintainer command. It does not appear in `spackle help`, and `spackle bench --help` lists its flags:

| Flag | Default | Meaning |
| :--- | :--- | :--- |
| `--corpus` | `bench/corpus` | Directory that holds the fixtures |
| `--out` | `bench/results` | Directory to write the results file into, or to read for `--table` |
| `--force` | off | Overwrite an existing results file for the same date and model |
| `--table` | off | Print the README table for all results in `--out` and exit without running |
| `--provider`, `--model`, `--base-url` | none | The model to benchmark. See [config.md](config.md#providers) |
| `--budget-usd` | 5 | Spend cap for the whole benchmark, across all fixtures |
| `--budget-tokens` | 2,000,000 | Token cap, applied to each fixture separately |
| `--config` | `./spackle.toml` | Config file, for per-stage models and pricing |
| `--yes` | off | Skip the confirmation before a paid run |

To benchmark a model:

```shell
spackle bench --provider anthropic --model claude-opus-5-5 --budget-usd 5
```

What to expect from a paid run:

- Before the first fixture, Spackle says how many scans it will run, with which model, and the spend cap, then asks you to confirm. Without a terminal it refuses unless you pass `--yes`.
- The dollar cap is enforced across the whole benchmark. Each fixture gets what is left. If Spackle does not know the model's price the dollar cap cannot be enforced; add `[pricing]` first.
- When the cap is reached, or a scan is refused for a reason that would repeat, the run stops. A run that did not cover every fixture prints its partial figures and writes no results file, so a partial run can never be quoted.
- Verified fixes need a container runtime. Without one, nothing is demonstrated and the verified-fix rate is 0.
- The check for an existing results file happens before any scan, so a name clash never throws away a run that cost money.

The repository also has a manually triggered `bench` workflow that runs the same command and uploads the results file as an artifact. Committing a results file is a separate, reviewed change.

## The results file

One run writes one file: `bench/results/<date>-<model>.json`. The date is UTC. The model name is lower-cased and reduced to letters, digits, dots, underscores and dashes. A deterministic run is named `<date>-none.json`.

| Field | Content |
| :--- | :--- |
| `schema` | `spackle.bench/v1`. A file with another schema is refused |
| `date` | `YYYY-MM-DD`, UTC |
| `spackle_version`, `commit` | What produced it |
| `mode` | `deterministic` or `agentic` |
| `provider`, `model` | The model benchmarked; `model` is `none` for a deterministic run |
| `corpus` | Counts: fixtures, clean, vulnerable, truth entries, fixtures by language |
| `totals` | True and false positives, false negatives, precision, recall, F1, verified fixes and rate, cost, tokens, cost per finding, decoys flagged |
| `by_language`, `by_difficulty` | The same totals, split |
| `fixtures` | Per fixture: the counts, each matched pair, each missed truth entry, each spurious finding, and the error if the scan failed |
| `notes` | Anything that qualifies the run |

Because every match, miss and spurious finding is listed, you can check any total by hand.

## The honesty rule

- A results file is produced only by `spackle bench`. It is never edited by hand. If a number is wrong, fix the cause and run again.
- A results file is never overwritten silently. Replacing one takes `--force`.
- The README table is generated by `spackle bench --table` from the committed files only. It is never typed in or adjusted.
- A figure appears in the README or the docs only if it comes from a committed results file.

## Limits

Read the numbers with these in mind.

- **The fixtures are small and synthetic.** A few files each, written to contain one or a few flaws. Real code has more context, more indirection and more noise. The results do not transfer to a large real codebase.
- **The flaws are planted.** They are the kinds of flaw the authors thought to write, at lines the authors know. A tool can do well here and still miss what nobody planted.
- **Decoys measure false positives, within limits.** They show whether Spackle flags safe code that looks risky. They are a handful of cases, not a survey of everything a rule can get wrong.
- **The corpus is public.** A model may have seen it, and rules can be tuned to it. Treat a high score as necessary, not sufficient.
- **A match is class, file and line.** It does not grade the explanation, the proof or the quality of the patch beyond "the proof stopped working".
- **Model runs vary.** Two runs with the same model can differ. One results file is one run.

The useful comparison is between two results files on the same corpus version: one model against another, or one Spackle version against the next. To learn how Spackle does on your code, run it on your code.
