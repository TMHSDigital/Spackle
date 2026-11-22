# py-unsafe-deserialization-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

app.py restores user preferences by unpickling a base64 cookie value sent by the client.

## Planted

- `unsafe-deserialization` (CWE-502) at `app.py` line 21, sink `pickle.loads`: pickle payload taken from the prefs cookie
