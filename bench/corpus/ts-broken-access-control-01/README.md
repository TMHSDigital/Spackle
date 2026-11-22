# ts-broken-access-control-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

canEdit in policy.ts compares the session user to an owner id supplied in the request body instead of the stored document owner, so any member can edit any document.

## Planted

- `broken-access-control` (CWE-639) at `policy.ts` line 21, sink `canEdit`: authorization compares against the ownerId field sent by the client in server.ts, not doc.ownerId

## Why this is a hard case

An authorization check is present, is called before the write, and returns 403 on failure, so nothing looks missing. It is logically wrong: it compares `session.userId` with a client-controlled value and never reads `doc.ownerId`. The correct sibling check `canView` sits right above it. The check and its caller are in different files, and no dangerous API is involved.
