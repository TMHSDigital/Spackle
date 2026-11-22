# go-command-injection-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The /lookup handler passes the host query parameter into a shell command line run with sh -c in main.go.

## Planted

- `command-injection` (CWE-78) at `main.go` line 20, sink `exec.Command`: host parameter concatenated into a sh -c command string
