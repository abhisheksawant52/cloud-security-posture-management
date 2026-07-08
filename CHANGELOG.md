# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-08

### Added

- `cspm` CLI with `scan`, `list-checks`, and `report` subcommands.
- Pluggable check framework with a shared registry.
- Built-in CIS checks for S3 (public access, encryption, versioning), IAM
  (root MFA, password policy, unused access keys), and EC2 security groups.
- Scanner that runs checks over an injected/mocked resource inventory.
- Text, JSON, and SARIF 2.1.0 report renderers.
- Terraform deployment (read-only audit IAM role, reports S3 bucket) with a
  reusable `audit-role` module and `dev`/`prod` environments.
- Documentation, CI pipeline, pre-commit hooks, and open-source project files.
