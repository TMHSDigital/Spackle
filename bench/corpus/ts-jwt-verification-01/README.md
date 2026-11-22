# ts-jwt-verification-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

verifyToken in auth.ts only checks the signature when the token header says HS256, so a token whose header names any other algorithm (for example none) is accepted unsigned.

## Planted

- `jwt-verification` (CWE-347) at `auth.ts` line 29, sink `verifyToken`: signature verified only for the HS256 branch; other alg values skip verification and fall through to accept the claims

## Why this is a hard case

The signature check is implemented correctly, with HMAC-SHA256 and a constant-time compare, and it runs for every normally issued token. The flaw is the branch around it: the algorithm is read from the attacker-controlled header and there is no else branch that rejects. Nothing on any single line is a known-bad call.
