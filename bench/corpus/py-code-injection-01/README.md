# py-code-injection-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

calc.py evaluates an expression taken from the request body with eval(); the emptied builtins do not make that safe.

## Planted

- `code-injection` (CWE-95) at `calc.py` line 10, sink `eval`: expression from the JSON request body evaluated with eval
