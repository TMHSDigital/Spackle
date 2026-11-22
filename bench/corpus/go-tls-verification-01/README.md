# go-tls-verification-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The HTTP client built in main.go disables TLS certificate verification with InsecureSkipVerify.

## Planted

- `tls-verification` (CWE-295) at `main.go` line 19, sink `tls.Config.InsecureSkipVerify`: certificate verification disabled on the client used for the rates API
