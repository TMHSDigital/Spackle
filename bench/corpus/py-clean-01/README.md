# py-clean-01

Part of the intentionally vulnerable Spackle test corpus. This fixture is test
data for a security scanner and must never be deployed, even though this
particular one is a clean decoy.

Clean decoy: a small service that queries SQL with request data, runs tar, and loads YAML, all done safely.

## Planted

Nothing. Ground truth is empty, so every finding reported in this directory
counts as a false positive.

## What looks risky but is correct

- An f-string sits right next to the SQL call, but it only builds the LIKE pattern value, which is passed as a bound `?` parameter.
- `subprocess.run` receives request data, but in list form with no shell, and the only variable argument must match a strict lowercase name pattern first.
- YAML is parsed with `yaml.safe_load`, not `yaml.load`, and the path is fixed by the operator, not the request.
