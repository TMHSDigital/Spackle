# Spackle report

## Run summary

- **Run id:** `20261122T120000Z-demo`
- **Command:** scan
- **Target:** `examples/demo-app`
- **Target kind:** path
- **Commit:** `3850163c0ffee`
- **Mode:** agentic
- **Provider:** openai-compatible
- **Model:** local-coder-14b
- **Offline:** yes
- **Authorized scope:** `http://127.0.0.1:8080`
- **Scope given by:** scope-file
- **Sandbox isolation:** container, no network egress, read-only root
- **Started:** 2026-11-22T12:00:00Z
- **Ended:** 2026-11-22T12:07:31Z
- **Outcome:** budget-exhausted
- **Spackle version:** 0.1.0

**Counts:** 3 open, 0 with a patch available, 1 fixed, 1 dismissed. By severity, all but dismissed: 1 critical, 1 high, 1 medium, 1 low, 0 none. Demonstrated by a proof of concept: 1.

## Findings summary

| Id | Severity | Score | Confidence | Status | Title | Location |
| --- | --- | --- | --- | --- | --- | --- |
| `SPK-D1927AC6` | critical | 9.3 | demonstrated | open | SQL injection in the order lookup lets any visitor read the whole database | `app/routes/orders.py:42-44` |
| `SPK-EDF9331B` | high | 7.1 | high | open | Reflected cross-site scripting in the search page | `GET /search (parameter q)` |
| `SPK-F1B384CB` | medium | unscored (estimate) | plausible | open | The application container runs as root | `deploy/Dockerfile:1` |
| `SPK-13D0D5BE` | low | 1.0 | high | fixed | Password reset tokens are derived with MD5 | `app/auth/tokens.py:17-19` |

## Findings

### SPK-D1927AC6: SQL injection in the order lookup lets any visitor read the whole database

**Severity:** CRITICAL 9.3. **Confidence:** demonstrated. **Status:** open.

#### Identity

- **Id:** `SPK-D1927AC6`
- **Title:** SQL injection in the order lookup lets any visitor read the whole database
- **Location:** `app/routes/orders.py:42-44`
- **Symbol:** `get_order`
- **Class:** sql-injection
- **Surface:** code
- **CWE:** CWE-89
- **OWASP:** A03:2021 Injection
- **Status:** open

#### Severity

- **Label:** critical
- **Score:** 9.3 (CVSS 4.0)
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`

**Reasoning**

Reachable over the network with no login, and it exposes and can alter every table the application account can reach.

#### The flaw

The order id from the URL is formatted straight into a SQL string. Nothing between the route and the query parses or binds it, so the caller controls the statement.

- **Flow step 1, source:** `app/routes/orders.py:40`
- **Note:** Attacker-controlled query parameter.

```text
order_id = request.args.get("id")
```

- **Flow step 2, propagation:** `app/routes/orders.py:42`
- **Note:** Interpolated without binding.

```text
sql = f"SELECT * FROM orders WHERE id = {order_id}"
```

- **Flow step 3, sink:** `app/db.py:17`
- **Note:** Executed as written.

```text
def run(sql):
	return conn.execute(sql).fetchall()
```

#### Exploitation scenario

**Preconditions**

- Network access to the application.
- No account is needed.

**Steps**

1. Request /orders?id=1 to confirm the endpoint answers.
1. Request /orders?id=1 UNION SELECT email, password\_hash, 3, 4 FROM users.
1. Read every user's email and password hash from the response body.

**Chains into**

- Offline cracking of the unsalted hashes, then account takeover.

#### Proof of concept

- **Status:** demonstrated (the flaw's effect was observed: a proof of concept ran in the sandbox, or a recorded exchange shows it)
- **Kind:** script

**Summary**

The script sends the UNION payload and checks that a seeded user's email comes back.

**Command**

```text
python poc.py --base http://app:8080
```

**Captured result**

```text
HTTP/1.1 200 OK
[{"id": "alice@example.test", "total": "5f4dcc3b5aa765d61d8327deb882cf99"}]
POC OK: leaked 1 seeded credential row
```

- **Isolation:** container, no network egress, read-only root, 512 MiB, 60 s

**Artifacts**

- `poc/SPK-D1927AC6/poc.py`
- `poc/SPK-D1927AC6/output.txt`

#### Blast radius

**What the attacker gains**

- Read access to every table the application account can read.
- Write access through stacked statements.

**Exposed**

- users.email
- users.password\_hash
- orders

**Kill chain**

Unauthenticated request, then database read, then credential cracking, then login as any user.

- **Related findings:** `SPK-EDF9331B`

#### Remediation

Bind the order id as a query parameter and reject non-numeric ids at the route.

**Patch**

```diff
--- a/app/routes/orders.py
+++ b/app/routes/orders.py
@@ -40,5 +40,5 @@
     order_id = request.args.get("id")
-    sql = f"SELECT * FROM orders WHERE id = {order_id}"
-    rows = db.run(sql)
+    rows = db.run("SELECT * FROM orders WHERE id = ?", (int(order_id),))
     return jsonify(rows)
```

**Why this fixes it**

A bound parameter is sent as data, so the database never parses it as SQL.

**Defense in depth**

- Give the application a database account that cannot read the users table.
- Hash passwords with a slow, salted algorithm.

- **Verification:** verified
- **Branch:** `spackle/fix-SPK-D1927AC6`

#### Confidence

- **Level:** demonstrated (the flaw's effect was observed, by a sandboxed proof or a recorded exchange)
- **Reason:** The proof of concept ran in the sandbox and returned a seeded credential row.

#### Origin

- **Found by:** hunter, semgrep

### SPK-EDF9331B: Reflected cross-site scripting in the search page

**Severity:** HIGH 7.1. **Confidence:** high. **Status:** open.

#### Identity

- **Id:** `SPK-EDF9331B`
- **Title:** Reflected cross-site scripting in the search page
- **Location:** `GET /search (parameter q)`
- **Class:** reflected-xss
- **Surface:** running-target
- **CWE:** CWE-79
- **OWASP:** A03:2021 Injection
- **Status:** open

#### Severity

- **Label:** high
- **Score:** 7.1 (CVSS 4.0)
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Reasoning**

Needs a logged-in victim's session to be worth anything, and then reads what that session can read.

#### The flaw

The q parameter is echoed into the results heading without encoding.

- **Flow step 1, source:** no file location recorded
- **Note:** Marker sent in the query string.

```text
GET /search?q=spackle7391<i>
```

- **Flow step 2, sink:** no file location recorded
- **Note:** Marker reflected with the tag intact.

```text
<h2>Results for spackle7391<i></h2>
```

#### Exploitation scenario

**Preconditions**

- The victim is logged in and follows a link the attacker supplies.

**Steps**

1. Send the victim a link to /search with a script payload in q.
1. The payload runs in the victim's session.

#### Proof of concept

- **Status:** reasoned (the exploit path was argued from code or traffic and was not run)
- **Reason:** The scope file allows passive checks only, so no script payload was sent.
- **Kind:** http-sequence

**Summary**

A harmless marker with angle brackets was reflected unencoded.

#### Blast radius

**What the attacker gains**

- Actions and reads as the victim.

- **Related findings:** `SPK-D1927AC6`

#### Remediation

HTML-encode q where the template writes it, and send a Content-Security-Policy that forbids inline script.

#### Confidence

- **Level:** high (traced end to end, not run)
- **Reason:** The reflection was observed in a live response; script execution was not tested.

#### Origin

- **Found by:** dast

### SPK-F1B384CB: The application container runs as root

**Severity:** MEDIUM unscored (estimate). **Confidence:** plausible. **Status:** open.

#### Identity

- **Id:** `SPK-F1B384CB`
- **Title:** The application container runs as root
- **Location:** `deploy/Dockerfile:1`
- **Class:** container-runs-as-root
- **Surface:** infrastructure
- **CWE:** CWE-250
- **Status:** open

#### Severity

- **Label:** medium
- **Score:** unscored (estimate): no valid CVSS vector was available, so the label is carried over from a scanner or rule

**Reasoning**

Label carried over from the scanner rule; it matters only after another flaw gives code execution.

#### The flaw

The Dockerfile never sets USER, so the process runs as uid 0 inside the container.

- **Flow step 1, sink:** `deploy/Dockerfile:1`

```text
FROM python:3.12-slim
```

#### Exploitation scenario

No exploitation scenario was recorded.

#### Proof of concept

- **Status:** not-run (no proof of concept was run)
- **Reason:** A configuration weakness with no direct trigger; there is nothing to run.

#### Blast radius

No blast radius was recorded.

#### Remediation

Create an unprivileged user in the image and switch to it with USER.

#### Confidence

- **Level:** plausible (a lead that was not confirmed)
- **Reason:** Reported by one scanner rule and not checked against the deployed runtime settings.

#### Origin

- **Found by:** trivy

### SPK-13D0D5BE: Password reset tokens are derived with MD5

**Severity:** LOW 1.0. **Confidence:** high. **Status:** fixed.

#### Identity

- **Id:** `SPK-13D0D5BE`
- **Title:** Password reset tokens are derived with MD5
- **Location:** `app/auth/tokens.py:17-19`
- **Class:** weak-hash
- **Surface:** code
- **CWE:** CWE-328, CWE-327
- **Status:** fixed

#### Severity

- **Label:** low
- **Score:** 1.0 (CVSS 4.0)
- **Vector:** `CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Reasoning**

Needs local access and a privileged position to observe tokens.

#### The flaw

Reset tokens are the MD5 of the user id and a timestamp, which is guessable.

#### Exploitation scenario

No exploitation scenario was recorded.

#### Proof of concept

- **Status:** reasoned (the exploit path was argued from code or traffic and was not run)
- **Reason:** The token recipe is visible in the code; no token was forged.

#### Blast radius

No blast radius was recorded.

#### Remediation

Generate reset tokens from the operating system's random source.

**Patch**

```diff
--- a/app/auth/tokens.py
+++ b/app/auth/tokens.py
@@ -17,3 +17,1 @@
-    raw = f"{user.id}{time.time()}"
-    return hashlib.md5(raw.encode()).hexdigest()
+    return secrets.token_urlsafe(32)
```

- **Verification:** verified
- **Branch:** `spackle/fix-SPK-13D0D5BE`

#### Confidence

- **Level:** high (traced end to end, not run)
- **Reason:** Traced from the reset handler to the token function.

#### Origin

- **Found by:** hunter

## Dismissed by review

- `SPK-CB299C00` \[MEDIUM 5.1\] Path traversal in the file download handler at `app/files.py:88`. **Reason:** The caller passes the name through secure\_filename two lines earlier, so no separator reaches the join.

## What was skipped

- Cap reached: max model calls (40). Not examined: app/admin/reports.py; app/payments/webhook.py.
- Investigation not completed: I3 Check the export job for path traversal (the investigation failed: the provider returned HTTP 500).
- Lead dropped at validation: L-9f2c (location has neither a file nor an endpoint).
- Note: Live testing was limited to passive checks by the scope file.

## Coverage

- **Files mapped:** 48
- **Files not read:** 3
- **Languages:** python, dockerfile
- **Frameworks:** flask
- **Entry points:** 9
- **Infrastructure files:** 2
- **Endpoints:** 6
- **Test command:** `pytest -q`
- **Leads from seeders:** 9

| Seeder | Status | Leads | Note |
| --- | --- | --- | --- |
| gitleaks | missing | 0 | not installed; secrets were searched with built-in patterns only |
| semgrep | available | 7 |  |
| trivy | available | 2 | configuration checks only |

## Usage

- **Model calls:** 40
- **Tokens:** 182400 input, 21950 output (estimated)
- **Cost:** unknown for this model
- **Sandbox runs:** 3
