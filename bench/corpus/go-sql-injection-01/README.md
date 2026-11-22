# go-sql-injection-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The /products handler formats the category query parameter into a SQL string with fmt.Sprintf and runs it in main.go.

## Planted

- `sql-injection` (CWE-89) at `main.go` line 37, sink `sql.DB.Query`: query string built with fmt.Sprintf from the category parameter

## Tests

`go test ./...` runs a small test of the `clampLimit` helper. It does not touch the query.
