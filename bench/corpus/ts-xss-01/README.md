# ts-xss-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The /search handler in server.ts writes the q parameter into an HTML response without escaping it.

## Planted

- `xss` (CWE-79) at `server.ts` line 39, sink `res.end`: q parameter interpolated into the HTML body unescaped (the list items next to it are escaped)
