# Security Policy

LokiRed is a security tool, so vulnerability reports and reports of scanner bypasses are welcome.

## Supported Versions

Security fixes target the latest tagged 0.1.x release and the current `main` branch. LokiRed is pre-1.0, so older 0.1.x tags do not have long-term support guarantees; please upgrade to the latest patch release when fixes are available.

## Reporting A Vulnerability

Please do not open a public issue with vulnerability details, real credentials, private repository contents, or customer configuration.

Preferred reporting path:

1. Use GitHub private vulnerability reporting for this repository if it is enabled.
2. If private reporting is not available, open a minimal public issue asking for a private disclosure path. Do not include exploit details or sensitive data in that issue.

Helpful reports include:

- Affected LokiRed version or commit.
- The command you ran.
- A minimal synthetic config that reproduces the behavior.
- Expected result and actual result.
- Whether the issue is a false negative, false positive, crash, or unsafe output behavior.

Maintainers should acknowledge valid private reports promptly, avoid requesting real secrets, and publish fixes with clear release notes when a release process exists.
