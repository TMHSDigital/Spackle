# go-auth-bypass-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The admin check in the /flags handler in main.go only runs for POST, while the same handler also mutates state for PUT and DELETE.

## Planted

- `auth-bypass` (CWE-287) at `main.go` line 31, sink `flagsHandler`: admin check is gated on POST only; PUT and DELETE reach the mutating switch unauthenticated

## Why this is a hard case

An authentication check is present, uses a constant-time comparison, and is called from the handler, so a rule that looks for a missing check finds nothing. The flaw is the method condition on the guard: it does not cover every state-changing branch of the switch below it.
