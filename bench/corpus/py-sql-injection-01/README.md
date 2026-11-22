# py-sql-injection-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The /items endpoint in app.py interpolates the q parameter into a SQL string with an f-string and executes it.

## Planted

- `sql-injection` (CWE-89) at `app.py` line 22, sink `cursor.execute`: f-string query built from the q parameter

## Tests

`python -m unittest discover -s .` runs a test of the `clamp_limit` helper only.
