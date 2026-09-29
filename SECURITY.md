# Security policy

White Tower governs AI agents, so its own security comes first. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Do not open public issues, pull requests or discussions for security vulnerabilities.**

Report them privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Include what you found, how to reproduce it, the affected version or commit, and its impact as you understand it.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement of your report | Within 3 working days |
| First assessment (confirmed or not, severity) | Within 10 working days |
| Fix and coordinated disclosure | Within 90 days of the report, or sooner for actively exploited issues |

We keep you informed along the way. Unless you ask otherwise, we credit you in the security advisory.

## Supported versions

White Tower is pre-alpha and has no release yet. Security fixes land on `main`. Once releases exist, the latest minor release receives security fixes.

## Scope

- **In scope:** the core, the CLI, the web console, the adapters, the container images, the Helm chart and the release pipeline.
- **Out of scope:** the development credentials in `deploy/compose/dev`, which are public on purpose and must never be used outside a local machine.

## Verifying releases

Every release is signed, and ships with SBOMs and build provenance. See [docs/verify-release.md](docs/verify-release.md).
