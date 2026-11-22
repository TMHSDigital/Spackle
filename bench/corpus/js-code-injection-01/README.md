# js-code-injection-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

server.js compiles a pricing formula taken from the JSON request body with the Function constructor and runs it.

## Planted

- `code-injection` (CWE-94) at `server.js` line 29, sink `Function constructor`: formula string from the request body compiled and executed
