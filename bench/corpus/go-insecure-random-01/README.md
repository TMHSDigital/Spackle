# go-insecure-random-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

Password reset tokens in main.go are generated with math/rand instead of a cryptographic source.

## Planted

- `insecure-random` (CWE-338) at `main.go` line 29, sink `math/rand.Intn`: password reset token drawn from math/rand
