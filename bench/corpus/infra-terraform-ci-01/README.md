# infra-terraform-ci-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

A Terraform module with a public bucket, SSH open to the internet and an unencrypted database, plus a GitHub Actions workflow with write-all permissions, an unpinned third-party action and an issue title interpolated into a shell step.

## Planted

- `public-storage` (CWE-732) at `main.tf` line 26, sink `aws_s3_bucket_acl.acl`: bucket ACL grants public read
- `network-exposure` (CWE-284) at `main.tf` line 39, sink `aws_security_group.ingress`: SSH (port 22) open to the whole internet
- `unencrypted-storage` (CWE-311) at `main.tf` line 51, sink `aws_db_instance.storage_encrypted`: database storage encryption explicitly disabled
- `ci-permissions` (CWE-732) at `.github/workflows/triage.yml` line 7, sink `permissions`: workflow token granted every write scope
- `supply-chain` (CWE-829) at `.github/workflows/triage.yml` line 17, sink `uses`: third-party action referenced by a mutable branch and handed the token
- `ci-injection` (CWE-78) at `.github/workflows/triage.yml` line 25, sink `run`: attacker-controlled issue title expanded directly into a shell script

The workflow file lives under this fixture directory, not the repository root, so GitHub never runs it.
