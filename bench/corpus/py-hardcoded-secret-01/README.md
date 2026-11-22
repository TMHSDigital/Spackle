# py-hardcoded-secret-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

config.py embeds an API key and a database password as string literals; both are fake fixture values.

## Planted

- `hardcoded-secret` (CWE-798) at `config.py` line 5, sink `api_key`: API key literal assigned in source
- `hardcoded-secret` (CWE-798) at `config.py` line 13, sink `DB_PASSWORD`: database password literal assigned in source

## Tests

`python -m unittest discover -s .` runs a test of the `retry_delays` helper only.
