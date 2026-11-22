# go-clean-01

Part of the intentionally vulnerable Spackle test corpus. This fixture is test
data for a security scanner and must never be deployed, even though this
particular one is a clean decoy.

Clean decoy: a small service that queries SQL, runs an external program and reads files named by the request, all done safely.

## Planted

Nothing. Ground truth is empty, so every finding reported in this directory
counts as a false positive.

## What looks risky but is correct

- `db.QueryRow` receives a request value, but through a `?` placeholder, not string building.
- `exec.Command` is called with a fixed program and fixed first argument; the only variable argument must be a key of the `allowedUnits` allowlist, and no shell is involved.
- The file read takes a request-supplied name, but the path goes through `filepath.Clean` and must keep the document root plus a separator as its prefix before it is opened.
