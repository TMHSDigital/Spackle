# py-clean-02

Part of the intentionally vulnerable Spackle test corpus. This fixture is test
data for a security scanner and must never be deployed, even though this
particular one is a clean decoy.

Clean decoy: a feed fetcher that uses MD5, secret comparison, random identifiers and a server-side URL fetch, all done safely.

## Planted

Nothing. Ground truth is empty, so every finding reported in this directory
counts as a false positive.

## What looks risky but is correct

- `hashlib.md5` is used only as a cache key for fetched feeds (and is marked `usedforsecurity=False`). It protects nothing, so it is not a weak-hash finding.
- The webhook signature is HMAC-SHA256 compared with `hmac.compare_digest`, and the key comes from the environment.
- Session identifiers come from `secrets`, not `random`.
- `fetch_feed` requests a caller-supplied URL, but only if it matches a strict https pattern, its host is in `ALLOWED_HOSTS`, and redirects are refused, so it is not SSRF.
