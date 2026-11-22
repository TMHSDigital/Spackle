# demo-app

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The bundled Spackle demo target: a tiny standard-library notes web app with one planted flaw per route, plus a deliberately weak Dockerfile, Kubernetes manifest, Terraform file and CI workflow.

## Planted

- `hardcoded-secret` (CWE-798) at `app.py` line 17, sink `SECRET_KEY`: token signing key hardcoded in source (fake fixture value)
- `xss` (CWE-79) at `app.py` line 57, sink `handle_search`: GET /search reflects q into the HTML response unescaped
- `broken-access-control` (CWE-639) at `app.py` line 64, sink `db.get_note`: GET /note returns any note by id to any signed-in user, with no ownership check
- `command-injection` (CWE-78) at `app.py` line 72, sink `subprocess.run`: GET /ping concatenates host into a shell command
- `path-traversal` (CWE-22) at `app.py` line 78, sink `open`: GET /file joins name to NOTES_DIR with no containment check
- `ssrf` (CWE-918) at `app.py` line 84, sink `urllib.request.urlopen`: GET /fetch requests an arbitrary url server-side
- `unsafe-deserialization` (CWE-502) at `app.py` line 91, sink `pickle.loads`: POST /import unpickles the request body
- `information-disclosure` (CWE-209) at `app.py` line 117, sink `traceback.format_exc`: error responses include the full Python traceback
- `weak-hash` (CWE-328) at `db.py` line 19, sink `hashlib.md5`: passwords stored as unsalted MD5
- `sql-injection` (CWE-89) at `db.py` line 51, sink `sqlite3.Connection.execute`: GET /search builds the query with an f-string from q
- `supply-chain` (CWE-829) at `Dockerfile` line 1, sink `FROM`: base image uses the mutable latest tag
- `hardcoded-secret` (CWE-798) at `Dockerfile` line 5, sink `ENV`: secret value baked into an image layer (fake fixture value)
- `container-hardening` (CWE-250) at `Dockerfile` line 7, sink `CMD`: no USER instruction, so the app runs as root; anchored on the CMD line
- `container-hardening` (CWE-770) at `deploy/k8s.yaml` line 18, sink `containers`: container has no resource limits; anchored on the container entry
- `supply-chain` (CWE-829) at `deploy/k8s.yaml` line 19, sink `image`: container image referenced by the latest tag
- `container-privilege` (CWE-250) at `deploy/k8s.yaml` line 26, sink `securityContext.privileged`: container runs privileged
- `supply-chain` (CWE-829) at `.github/workflows/ci.yml` line 15, sink `uses`: action referenced by a mutable tag instead of a commit SHA
- `ci-injection` (CWE-829) at `.github/workflows/ci.yml` line 17, sink `actions/checkout ref`: pull_request_target workflow checks out and then runs untrusted pull request code
- `ci-injection` (CWE-78) at `.github/workflows/ci.yml` line 23, sink `run`: pull request title expanded directly into a shell script
- `public-storage` (CWE-732) at `infra/main.tf` line 22, sink `aws_s3_bucket_acl.acl`: bucket ACL grants public read
- `network-exposure` (CWE-284) at `infra/main.tf` line 34, sink `aws_security_group.ingress`: SSH (port 22) open to the whole internet

## Layout

- `app.py`: routing and request handlers.
- `db.py`: sqlite schema, seed data and queries.
- `Dockerfile`, `deploy/k8s.yaml`, `infra/main.tf`: deliberately weak deployment files.
- `.github/workflows/ci.yml`: a deliberately unsafe workflow. It sits under this directory, not the repository root, so GitHub never runs it.
- `truth.json`: ground truth for every planted flaw, in the same format as `bench/corpus/`.

The vulnerable lines carry no marker comments. The scanner has to find them unaided; this README and `truth.json` are the only documentation of what is planted.

## Running it

Only for local experiments, and only on a machine you do not mind breaking:

    python app.py

It binds 127.0.0.1 only, on the port in the `PORT` environment variable (default 8081), uses an in-memory sqlite database, and prints the randomly generated passwords of its two seeded users at startup.

## Tests

`python -m unittest discover -s tests` runs two tests of safe helper functions. They do not start the server and do not exercise any planted flaw.
