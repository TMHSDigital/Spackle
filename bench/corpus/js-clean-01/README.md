# js-clean-01

Part of the intentionally vulnerable Spackle test corpus. This fixture is test
data for a security scanner and must never be deployed, even though this
particular one is a clean decoy.

Clean decoy: helpers that run a child process, read request-named files, compare tokens, hash with MD5 and query SQL, all done safely.

## Planted

Nothing. Ground truth is empty, so every finding reported in this directory
counts as a false positive.

## What looks risky but is correct

- `execFile` is used (no shell) with a fixed program; the only variable argument must be in the `SERVICES` allowlist.
- `readUpload` takes a request-supplied name, but resolves it and requires the upload root plus a separator as prefix before reading.
- API tokens come from `crypto.randomBytes`, and comparison uses `crypto.timingSafeEqual` over fixed-length digests.
- MD5 appears only in `contentEtag`, an HTTP cache validator. It protects nothing, so it is not a weak-hash finding.
- The SQL statement uses `?` placeholders for both request values.
