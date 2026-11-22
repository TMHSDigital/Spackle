# py-broken-access-control-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The /invoices/<id> route in app.py requires a session but returns any invoice by id without comparing its owner to the signed-in user.

## Planted

- `broken-access-control` (CWE-639) at `app.py` line 20, sink `store.get_invoice`: invoice fetched by client-supplied id and returned with no ownership check

## Why this is a hard case

This is an insecure direct object reference with no dangerous API anywhere: no SQL, no shell, no file access. Authentication is present and correct. The neighbouring list route filters by owner correctly, which makes the detail route look covered. The flaw is only the absence of an `invoice.owner_id == user_id` comparison.

## Tests

`python -m unittest discover -s .` runs tests of `format_amount` and `invoices_for` only.
