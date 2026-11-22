# js-insecure-random-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

Password reset tokens in tokens.js are generated with Math.random.

## Planted

- `insecure-random` (CWE-338) at `tokens.js` line 9, sink `Math.random`: password reset token characters chosen with Math.random

## Tests

`node --test` runs tests of `isExpired` and `maskEmail` in tokens.js only.
