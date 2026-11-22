# ts-clean-01

Part of the intentionally vulnerable Spackle test corpus. This fixture is test
data for a security scanner and must never be deployed, even though this
particular one is a clean decoy.

Clean decoy: a server that reflects a query parameter into HTML, redirects to a request-supplied target and sets credentialed CORS headers, all done safely.

## Planted

Nothing. Ground truth is empty, so every finding reported in this directory
counts as a false positive.

## What looks risky but is correct

- The q parameter is interpolated into HTML, but only after `escapeHtml`.
- The redirect target comes from the request, but `safeNext` only returns values that are members of a fixed set of local paths.
- `Access-Control-Allow-Origin` echoes the request origin with credentials, but only when the origin is in `ALLOWED_ORIGINS`.
