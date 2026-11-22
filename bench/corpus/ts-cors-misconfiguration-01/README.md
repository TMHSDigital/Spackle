# ts-cors-misconfiguration-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

server.ts reflects any request Origin into Access-Control-Allow-Origin and also allows credentials on a cookie-authenticated endpoint.

## Planted

- `cors-misconfiguration` (CWE-942) at `server.ts` line 25, sink `res.setHeader`: arbitrary Origin reflected together with Access-Control-Allow-Credentials: true
