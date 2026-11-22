# py-jwt-verification-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

tokens.py computes whether the token signature matches but discards the result, so decode() accepts tokens with any signature.

## Planted

- `jwt-verification` (CWE-347) at `tokens.py` line 41, sink `tokens.decode`: return value of the signature check is ignored, so forged tokens are accepted

## Why this is a hard case

The verification code exists, is correct in isolation (HMAC-SHA256 with a constant-time compare), and is called on the right inputs. The flaw is that the boolean it returns is never checked. There is no dangerous API on the line and no `verify=False` flag to match; the bug is a missing `if not ...: raise`.

## Tests

`python -m unittest discover -s .` runs a test of the base64 helpers only. tokens.py reads its key from the TOKEN_SIGNING_KEY environment variable, which the test sets to a throwaway value.
