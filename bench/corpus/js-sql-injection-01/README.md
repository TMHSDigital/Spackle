# js-sql-injection-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

Filter values read in routes.js are concatenated into a WHERE clause in filters.js and that clause is spliced into the statement prepared in db.js.

## Planted

- `sql-injection` (CWE-89) at `db.js` line 19, sink `DatabaseSync.prepare`: where clause concatenated in filters.js from the status and customer parameters read in routes.js

## Why this is a hard case

The taint crosses three files: source in routes.js, string building in filters.js, execution in db.js. The sink uses `prepare` with a `?` placeholder for the limit, so it looks parameterized. The same statement also splices in a sort column, but that one is safe because `normalizeSort` restricts it to an allowlist; a tool has to tell the two spliced values apart.

## Tests

`node --test` runs a test of `normalizeSort` in filters.js only. It does not load db.js.
