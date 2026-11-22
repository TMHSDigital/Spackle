# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository foundation: license, security policy, contribution guide, CI, release pipeline configuration, and project documentation.
- `spackle scan` for local directories and git URLs, with no model required: a target mapper (languages, frameworks, entry points, trust boundaries, test command), built-in seeders for code, secrets, Dockerfiles, Kubernetes, Terraform and GitHub workflows, and adapters for Semgrep, gitleaks, osv-scanner, Trivy and hadolint.
- The finding schema with CVSS 4.0 scoring computed from the vector, validation, deduplication and ranking.
- The append-only evidence ledger, and `spackle report`, which rebuilds terminal, Markdown, HTML, JSON and SARIF reports from the ledger alone.
- `spackle doctor`, which reports the container runtime, sandbox images, scanners and model configuration.
- Secret detection and redaction: reports and the ledger name the rule, location and a short hash, never the value.
- `examples/demo-app` and the benchmark corpus under `bench/corpus`, both intentionally vulnerable test data.
