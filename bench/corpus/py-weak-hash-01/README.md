# py-weak-hash-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

accounts.py stores and verifies account passwords as unsalted MD5 digests.

## Planted

- `weak-hash` (CWE-328) at `accounts.py` line 21, sink `hashlib.md5`: unsalted MD5 used as the password hash
