# Findings

A finding is one reported flaw. Every stage produces the same structure and every report format renders it. This page describes each field, the labels Spackle puts on a finding and exactly when it assigns them, and ends with a real finding from a scan of the bundled demo application.

The labels are the point. A finding says how sure Spackle is and why: leads, not verdicts, until something stronger than a pattern match backs them.

## Where findings live

Each run directory, `<state_dir>/runs/<run-id>/`, holds:

| Path | Content |
| :--- | :--- |
| `ledger.jsonl` | The record of the run. Reports are rendered from this file alone |
| `findings/<id>/finding.json` | One finding, in the schema below |
| `findings/<id>/poc/` | The proof of concept and `poc.json`, when one was run |
| `findings/<id>/evidence/` | Output of every sandbox run for the finding |
| `findings/<id>/fix.patch` | The patch, when one was accepted |
| `findings/<id>/review.md` | The reason, when the finding was dismissed |
| `evidence/exchanges/` | Recorded requests and responses, for a running target |
| `reports/report.<ext>` | The report in all five formats |

## The schema

Field names are the JSON names. Fields marked optional are left out when empty.

### Top level

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `id` | string | `SPK-` and eight hex digits. Derived from the class, file, start line, method, endpoint and parameter, so the same flaw gets the same id on every run of the same target |
| `title` | string | Short and specific |
| `surface` | string | `code`, `running-target`, `infrastructure` or `debug` |
| `class` | string | One of the classes listed below |
| `cwe` | string list, optional | Entries of the form `CWE-89` |
| `owasp` | string list, optional | OWASP Top 10 category, taken from the class |
| `location` | object | Where the flaw is |
| `severity` | object | The CVSS 4.0 assessment |
| `flaw` | object | What is wrong and how data reaches the sink |
| `exploitation` | object | The attacker's scenario |
| `proof` | object | The demonstration, or why there is none |
| `blast_radius` | object | What an attacker gains |
| `remediation` | object | The fix |
| `confidence` | object | The label and its reason |
| `origin` | string list, optional | What contributed: `builtin-code:py-sql-fstring-var`, `investigator:<intent id>` and so on |
| `status` | string | `open`, `patch-available`, `fixed` or `dismissed` |
| `dismiss_reason` | string, optional | Required when `status` is `dismissed` |

### `location`

A finding has a file, an endpoint, or both. At least one is required.

| Field | Meaning |
| :--- | :--- |
| `file` | Forward-slash path relative to the target root |
| `start_line`, `end_line` | 1-based line range |
| `symbol` | Function or handler name |
| `method` | HTTP method, for a running target |
| `endpoint` | Path on the running target |
| `parameter` | The parameter involved |

### `severity`

| Field | Meaning |
| :--- | :--- |
| `cvss_vector` | A CVSS 4.0 base vector. Optional only when `unscored` is true |
| `cvss_score` | Computed by Spackle from the vector |
| `label` | `critical`, `high`, `medium`, `low` or `none` |
| `reasoning` | Why the vector has the values it has |
| `unscored` | True when there is no valid vector and the label is an estimate |

### `flaw`

| Field | Meaning |
| :--- | :--- |
| `description` | What is wrong |
| `flow` | Optional list of steps from source to sink |
| `flow[].role` | `source`, `propagation`, `sanitizer` or `sink` |
| `flow[].file`, `flow[].line` | Where the step is |
| `flow[].quote` | The code on that line, quoted from the file |
| `flow[].note` | What happens there |

### `exploitation`

| Field | Meaning |
| :--- | :--- |
| `preconditions` | What the attacker needs before starting |
| `steps` | The attack, step by step |
| `chains_into` | What the flaw enables next |

### `proof`

| Field | Meaning |
| :--- | :--- |
| `status` | `demonstrated`, `reasoned`, `not-run` or `failed` |
| `kind` | `script`, `test` or `http-sequence` |
| `summary` | What the proof does |
| `artifacts` | Paths relative to the run directory |
| `command` | The command that ran |
| `result` | Captured output or a response excerpt, redacted |
| `isolation` | The sandbox profile that was in effect |
| `reason` | Why there is no demonstration, when there is none |

### `blast_radius`

| Field | Meaning |
| :--- | :--- |
| `gains` | What the attacker ends up with |
| `exposed` | The specific data or systems at risk |
| `kill_chain` | How this finding combines with others |
| `related` | Ids of the findings it combines with |

### `remediation`

| Field | Meaning |
| :--- | :--- |
| `summary` | The change to make. Always present |
| `patch` | A unified diff, when a patch was accepted |
| `why` | Why the change closes the flaw |
| `defense_in_depth` | Optional extra hardening |
| `verification` | A sentence that says what was and was not checked. It starts with `verified`, `unverified`, `no patch`, `not applied` or `not attempted` |
| `branch` | The fix branch, when one was created |

### `confidence`

| Field | Meaning |
| :--- | :--- |
| `level` | `demonstrated`, `high` or `plausible` |
| `reason` | What was verified and what was not. Always present |

## Confidence levels

A model cannot award itself `demonstrated`. Whatever a draft says, only `high` and `plausible` are accepted from a model, and anything else becomes `plausible`.

| Level | Assigned when |
| :--- | :--- |
| `plausible` | A scanner lead that no model confirmed: no model is configured, the lead was not selected for investigation, or its investigation produced no usable result. Also an investigated finding whose investigator said a step was assumed, and a finding whose reviewer could neither confirm nor refute it (a `high` drops to `plausible`). In debug mode, an issue that was not reproduced |
| `high` | An investigator read every step from an attacker-reachable source to the sink, the draft passed validation, and the reviewer did not return "uncertain". For a running target: the recorded exchange shows the symptom of the flaw, and exploiting it was not attempted |
| `demonstrated` | A proof of concept ran in the sandbox, exited 0 and printed the marker Spackle gave it. For a running target: the behavior itself is in the recorded exchange. In debug mode: the failure was reproduced in the sandbox |

A finding with confidence `demonstrated` must have proof status `demonstrated`. Validation enforces that.

## Proof statuses

| Status | Assigned when |
| :--- | :--- |
| `not-run` | Nothing was investigated or run. Every finding of a run with no model has this status. So does a lead a model run did not confirm, and a debug issue that was not reproduced |
| `reasoned` | The exploit path was traced from code or traffic and nothing was run. This is the status of every investigated code finding until a proof succeeds. It stays `reasoned` when there is no container runtime, when the language has no auto-run proof, when the sandbox image is unavailable, when the prover said a proof is not possible in the sandbox, or when the proof was rejected before running. The `reason` field says which. For a running target it is used when the exchange shows a symptom only, such as a SQL error message |
| `demonstrated` | The proof ran and showed the flaw. Requires at least one artifact and a captured result |
| `failed` | A proof ran in the sandbox and did not show the flaw, after up to two attempts. The finding stays open on the code reading alone, and the output is kept so you can see what happened |

### What "demonstrated" means for code

The prover is given a random marker of the form `SPACKLE-PROOF-<16 hex>`. The proof counts when the container run did not time out, exited 0, and its output contains the marker. The proof is told to print the marker only after it has asserted the flaw's effect.

That is a precise claim and a limited one. The proof is model-written, and a careless proof could print the marker without truly exercising the flaw. Three things stand against that: the proof is stored in `findings/<id>/poc/` for you to read, the fixer must make the same proof stop working, and the review of the finding is done independently of the proof. Read the proof before you rely on it.

A proof may only add files, inside `spackle_poc/` or as `spackle_poc_test.go`. It may not replace a file of the target. Its command is a program and arguments, never a shell line.

### What "demonstrated" means for a running target

The baseline probe is read-only by default. For these classes the recorded exchange is itself the demonstration: `xss` (the marker came back unescaped), `open-redirect`, `path-traversal`, `exposed-file`, `directory-listing`, `missing-security-header`, `insecure-cookie`, `cors-misconfiguration` and `information-disclosure`. Their proof kind is `http-sequence` and the artifacts are the stored exchanges.

SQL injection is reported as `reasoned` with confidence `high`, not `demonstrated`. The probe sees the database error. Exploiting the injection would not be non-destructive, so Spackle does not do it.

## Status

| Status | Assigned when |
| :--- | :--- |
| `open` | The default |
| `dismissed` | The reviewer refuted the finding with a concrete reason, an investigator concluded a lead does not hold up, or a model assessed a running-target observation and did not confirm it. The reason is kept in `dismiss_reason`, in the ledger and in `review.md` |
| `patch-available` | A patch was accepted and the proof of concept that demonstrated the finding no longer succeeds against the patched code. The patch is on the fix branch or in `fix.patch`; the code that was scanned is unchanged, so the flaw is still there until the patch is merged. It counts toward `--fail-on` like an open finding |
| `fixed` | `spackle verify` re-ran the stored proof against the current code and it no longer succeeds. Verify sets the status back to `open` when the proof succeeds again |

A dismissal needs a reason. A reviewer that says "refuted" without one does not dismiss anything: the finding is kept and the verdict is recorded as uncertain.

Dismissed findings stay in the report, ranked last. Only `open` findings count toward `fail_on`.

## How severity is computed

Spackle computes the score. A model proposes a CVSS 4.0 vector and nothing else: the score and the label always come from the vector, through a CVSS library, and validation rejects a finding whose stored score does not match its vector.

- **Investigated finding.** The investigator supplies a vector with its reasoning. Spackle validates it and scores it.
- **Invalid vector from a model.** The class has a default vector. Spackle uses it, scores it, and writes in `reasoning` that the model's vector was invalid and the score is an estimate. Weaker models often produce a CVSS 3 shaped vector, and that alone should not discard a finding whose evidence checks out.
- **Reviewer correction.** A reviewer may supply a corrected vector. If it is valid it replaces the investigator's.
- **Lead with no investigation.** The class default vector is scored. When the result is within one level of the seeder's own severity hint, the vector stands. When they differ by two levels or more, the class default describes a different situation, so the finding is `unscored`: it carries the seeder's label, no vector and a score of 0.
- **Running-target assessment.** A valid vector from the model replaces the probe's severity. An invalid one leaves the probe's severity in place.
- **Debug mode.** A functional bug is `unscored` with label `none`. It is not scored as a vulnerability.

The label is the CVSS 4.0 qualitative rating of the score, in lower case.

Reports rank open findings first, then those with a patch available, then fixed, then dismissed. Within a group the order is severity label, score, confidence, then id.

## How a draft becomes a finding

Nothing in a model's draft is trusted. Before a draft becomes a finding, Spackle checks every claim it can against the target:

- The class is one of the known classes.
- The file exists inside the target. Paths that leave the target, including through a symbolic link, are refused.
- The start line is inside the file.
- The flow is not empty, and every step has a quote.
- Every quote really appears in the file it cites. Whitespace differences are ignored. The file is compared as the model's tools show it, with secrets replaced by redaction markers, so a quote of a line that holds a secret carries the marker and never the value. A quote must have at least 12 non-space characters, or at least half of the line it matches when that line is shorter: a fragment such as `)` is refused. When the quote is found on another line of the same file, the line number is corrected to the real one and the step's note says so.
- The CVSS vector is valid, or the class default is used as described above.
- The title, the description, the fix summary and the confidence reason are all present.
- CWE entries that are not of the form `CWE-<number>` are dropped.

A draft that fails is sent back to the model once with the specific problems. If the second answer also fails, the draft is rejected, the reason is written to the ledger as a `draft.reject` event, and the run continues. The lead behind it is still reported, as an unconfirmed lead that says why. Every rejected draft, failed investigation and lead dropped at validation is also listed under "What was skipped" in the terminal, Markdown and HTML reports and in the `rejected` array of the JSON report, so a report never reads as full coverage when part of the plan produced nothing.

The same holds for the other model stages. A plan is checked against the real map and leads. A proof is checked before it runs. A patch is rebuilt as a diff from whole files and checked in the sandbox. A chain that names an unknown finding id is ignored.

Findings with the same id are merged. The stronger one is kept and the origins are combined.

## Classes

Each class has a default CVSS 4.0 vector. Standard text for the class (OWASP category, preconditions, attack steps, remediation) is used when no model has written something specific.

`auth-bypass`, `broken-access-control`, `ci-injection`, `ci-permissions`, `code-injection`, `command-injection`, `container-hardening`, `container-privilege`, `cors-misconfiguration`, `debug-enabled`, `denial-of-service`, `directory-listing`, `exposed-file`, `hardcoded-secret`, `information-disclosure`, `insecure-cookie`, `insecure-random`, `jwt-verification`, `mass-assignment`, `missing-security-header`, `network-exposure`, `open-redirect`, `path-traversal`, `prototype-pollution`, `public-storage`, `race-condition`, `sql-injection`, `ssrf`, `supply-chain`, `template-injection`, `tls-verification`, `unencrypted-storage`, `unsafe-deserialization`, `vulnerable-dependency`, `weak-crypto`, `weak-hash`, `xss`, `xxe`.

Debug mode uses one more class, `bug`, for a functional failure.

## Verifying a fix

`spackle verify <run-id>` re-runs the stored proof of concept of every finding the scan demonstrated against the code as it is now. A proof that ran during the scan and did not show the flaw is skipped, and its finding is left as it is. A proof succeeds when it prints its marker and exits with code 0. One that times out, is killed, or prints its marker and then fails is inconclusive: the finding keeps its status. The run id may be a unique prefix, or `latest`. Use it after you apply a patch or merge the fix branch, or after you fix a finding by hand.

- **What it needs.** A container runtime: proofs run only in the sandbox, and without one the command refuses instead of guessing. The run must have stored proofs, which a scan keeps for each finding it demonstrated.
- **Which runs.** Runs of a local directory only. A run of a git URL scanned a clone, and a run of a running target has no code to re-run a proof against; both are refused.
- **Where it runs.** Against the directory that was scanned, whose absolute path is stored in the run, so you can run it from anywhere. A run stored by an older version only has the target as it was typed: run verify from the directory the scan was run from, and it says so.
- **What it changes.** The stored run. Each outcome is appended to the run's ledger and the run's reports are rewritten. A proof that no longer succeeds sets the finding to `fixed`. A proof that still succeeds sets it to `open`, and if the finding has a patch the report says the patch is not applied. A proof that times out or is killed changes nothing and is reported as not verified.
- **Exit code.** 1 when at least one proof still succeeds or could not be verified, 0 when none does, 2 when the command is refused.

## A worked example

This finding comes from a deterministic scan of the demo application in this repository, with no model configured:

```shell
spackle scan examples/demo-app
```

It is `findings/SPK-790860CA/finding.json` from that run, verbatim. The block is pasted in by `tools/readme` from the scan's output, not typed by hand:

<!-- finding-json:start -->
```json
{
  "id": "SPK-790860CA",
  "title": "SQL statement built with an f-string",
  "surface": "code",
  "class": "sql-injection",
  "cwe": [
    "CWE-89"
  ],
  "owasp": [
    "A03:2021 Injection"
  ],
  "location": {
    "file": "db.py",
    "start_line": 50
  },
  "severity": {
    "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    "cvss_score": 9.3,
    "label": "critical",
    "reasoning": "Default CVSS 4.0 vector for this class, assuming the flaw is reachable as it typically is. Not refined by investigation."
  },
  "flaw": {
    "description": "A SQL statement is assembled from program values instead of being parameterized. If any of those values is influenced by a caller, the caller can change the meaning of the query.",
    "flow": [
      {
        "role": "sink",
        "file": "db.py",
        "line": 50,
        "quote": "sql = f\"SELECT id, title FROM notes WHERE shared = 1 AND title LIKE '%{q}%'\""
      }
    ]
  },
  "exploitation": {
    "preconditions": [
      "A request parameter, header, or stored value reaches a SQL query that is built by string concatenation",
      "The attacker can send requests to the affected endpoint"
    ],
    "steps": [
      "Send a request whose parameter closes the string literal and appends SQL (these steps are typical for this class of flaw; they were not confirmed for this code)",
      "Confirm the injection from error messages, changed results, or response timing",
      "Use UNION or boolean conditions to read other tables",
      "Modify or delete rows where the database account has write access"
    ],
    "chains_into": [
      "Authentication bypass or account takeover using extracted credentials and session data",
      "Remote code execution when the database account can write files or run operating system commands"
    ]
  },
  "proof": {
    "status": "not-run",
    "reason": "No model is configured, so this lead was not investigated or demonstrated."
  },
  "blast_radius": {
    "gains": [
      "Read access to every table the database account can reach",
      "The ability to change or delete application records"
    ]
  },
  "remediation": {
    "summary": "Pass values as bound parameters (placeholders) and keep the SQL text constant. Validate identifiers such as table or column names against a fixed allowlist.",
    "verification": "unverified"
  },
  "confidence": {
    "level": "plausible",
    "reason": "Reported by builtin-code rule py-sql-fstring-var. Not confirmed: reachability and impact were not investigated."
  },
  "origin": [
    "builtin-code:py-sql-fstring-var"
  ],
  "status": "open"
}
```
<!-- finding-json:end -->

The same finding in `reports/report.md`, verbatim and pasted in the same way:

<!-- finding-md:start -->
````markdown
### SPK-790860CA: SQL statement built with an f-string

**Severity:** CRITICAL 9.3. **Confidence:** plausible. **Status:** open.

#### Identity

- **Id:** `SPK-790860CA`
- **Title:** SQL statement built with an f-string
- **Location:** `db.py:50`
- **Class:** sql-injection
- **Surface:** code
- **CWE:** CWE-89
- **OWASP:** A03:2021 Injection
- **Status:** open

#### Severity

- **Label:** critical
- **Score:** 9.3 (CVSS 4.0)
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`

**Reasoning**

Default CVSS 4.0 vector for this class, assuming the flaw is reachable as it typically is. Not refined by investigation.

#### The flaw

A SQL statement is assembled from program values instead of being parameterized. If any of those values is influenced by a caller, the caller can change the meaning of the query.

- **Flow step 1, sink:** `db.py:50`

```text
sql = f"SELECT id, title FROM notes WHERE shared = 1 AND title LIKE '%{q}%'"
```

#### Exploitation scenario

**Preconditions**

- A request parameter, header, or stored value reaches a SQL query that is built by string concatenation
- The attacker can send requests to the affected endpoint

**Steps**

1. Send a request whose parameter closes the string literal and appends SQL (these steps are typical for this class of flaw; they were not confirmed for this code)
1. Confirm the injection from error messages, changed results, or response timing
1. Use UNION or boolean conditions to read other tables
1. Modify or delete rows where the database account has write access

**Chains into**

- Authentication bypass or account takeover using extracted credentials and session data
- Remote code execution when the database account can write files or run operating system commands

#### Proof of concept

- **Status:** not-run (no proof of concept was run)
- **Reason:** No model is configured, so this lead was not investigated or demonstrated.

#### Blast radius

**What the attacker gains**

- Read access to every table the database account can reach
- The ability to change or delete application records

#### Remediation

Pass values as bound parameters (placeholders) and keep the SQL text constant. Validate identifiers such as table or column names against a fixed allowlist.

- **Verification:** unverified

#### Confidence

- **Level:** plausible (a lead that was not confirmed)
- **Reason:** Reported by builtin-code rule py-sql-fstring-var. Not confirmed: reachability and impact were not investigated.

#### Origin

- **Found by:** builtin-code:py-sql-fstring-var
````
<!-- finding-md:end -->

### How to read it

This is a deterministic lead. A built-in rule matched one line, and everything else in the finding says so:

- The flow has one step, the sink. Nobody traced where `q` comes from.
- The severity is the default vector for the class, and the reasoning says it was not refined.
- The first exploitation step ends with "(these steps are typical for this class of flaw; they were not confirmed for this code)".
- The proof status is `not-run` and the confidence is `plausible`, each with its reason.
- The remediation is the standard advice for the class, marked `unverified`.

A run with a model configured would add what is missing here: the flow traced from the request to the query with each step quoted from the file, a severity vector argued for this code, an independent review, a proof of concept run in the sandbox when a container runtime is present, and a patch checked against that proof. This page does not show such a finding, because none was produced for it.
