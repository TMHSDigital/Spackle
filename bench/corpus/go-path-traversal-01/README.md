# go-path-traversal-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The name query parameter read in handler.go travels through two functions into store.go, where it is joined to the base directory and read without any containment check.

## Planted

- `path-traversal` (CWE-22) at `store.go` line 40, sink `os.ReadFile`: name from the request is joined to the base directory with no prefix check; source is in handler.go

## Why this is a hard case

The source (handler.go, `requestedDocument`) and the sink (store.go, `Load`) are in different files and separated by two calls. The sink line itself contains no request data and the join happens in a third helper, so a line-based rule sees only `os.ReadFile(s.resolve(name))`.

## Tests

`go test ./...` runs a test of the `contentType` helper only.
