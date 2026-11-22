# go-ssrf-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The /node-status handler builds an outbound URL from the node query parameter through a formatting helper and fetches it server-side in main.go.

## Planted

- `ssrf` (CWE-918) at `main.go` line 34, sink `http.Client.Get`: target URL assembled from the node parameter by statusProbe.endpoint with no host allowlist

## Why this is a hard case

No full URL is ever taken from the request. Only a host fragment is, and it is assembled into a URL by a struct method three lines before the fetch. The fetch line reads `client.Get(target)` with no request reference, and the fixed scheme, port and path make the call look constrained even though the host (and, with a `/` or `?`, the rest of the URL) is attacker-chosen.
