# js-open-redirect-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The /login/complete handler in server.js redirects to the next query parameter without restricting it to local paths.

## Planted

- `open-redirect` (CWE-601) at `server.js` line 20, sink `res.writeHead`: Location header set from the next parameter with no validation

## Tests

`node --test` runs a test of the cookie helpers in cookies.js only.
