# infra-container-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

A Dockerfile and a Kubernetes Deployment with unpinned images, a baked-in secret, a root container, a privileged pod, host networking and the Docker socket mounted from the host.

## Planted

- `supply-chain` (CWE-829) at `Dockerfile` line 1, sink `FROM`: base image uses the mutable latest tag instead of a pinned version or digest
- `hardcoded-secret` (CWE-798) at `Dockerfile` line 7, sink `ENV`: secret value baked into an image layer (fake fixture value)
- `container-hardening` (CWE-250) at `Dockerfile` line 9, sink `CMD`: no USER instruction anywhere, so the process runs as root; anchored on the CMD line
- `container-hardening` (CWE-668) at `k8s/deployment.yaml` line 17, sink `hostNetwork`: pod shares the node network namespace
- `supply-chain` (CWE-829) at `k8s/deployment.yaml` line 20, sink `image`: container image referenced by the latest tag
- `container-privilege` (CWE-250) at `k8s/deployment.yaml` line 31, sink `securityContext.privileged`: container runs privileged
- `container-privilege` (CWE-250) at `k8s/deployment.yaml` line 38, sink `hostPath`: host Docker socket mounted into the container
