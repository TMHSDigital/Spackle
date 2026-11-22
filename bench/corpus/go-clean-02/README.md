# go-clean-02

Part of the intentionally vulnerable Spackle test corpus. This fixture is test
data for a security scanner and must never be deployed, even though this
particular one is a clean decoy.

Clean decoy: an authenticated fetch proxy that uses MD5, random tokens, a secret comparison and a server-side HTTP request, all done safely.

## Planted

Nothing. Ground truth is empty, so every finding reported in this directory
counts as a false positive.

## What looks risky but is correct

- `crypto/md5` is used only to derive an HTTP ETag for cache validation. It protects nothing, so it is not a weak-hash finding.
- Tokens come from `crypto/rand`, not `math/rand`.
- The API key comparison uses `subtle.ConstantTimeCompare`, and the expected key comes from the environment, not from source.
- The handler fetches a URL taken from the request, but only over https, only to hosts in `allowedHosts`, and with redirects disabled, so it is not SSRF.
