# Governance

YubiWatch is currently maintained as a small owner-led project.

## Decision Making

Project direction is decided by the maintainer. Security-sensitive changes should be reviewed with extra care and must include tests and documentation.

## Maintainer Responsibilities

- Keep the default configuration safe for a personal Windows laptop.
- Avoid claiming tamper resistance the project does not provide.
- Review changes that affect locking, disabling, dashboard control, startup, or trusted-device enrollment.
- Keep recovery instructions easy to find.
- Keep the native Rust implementation healthy as the primary runtime.

## Contributor Responsibilities

- Follow `CODE_OF_CONDUCT.md`.
- Follow `CONTRIBUTING.md`.
- Keep pull requests focused.
- Explain security tradeoffs clearly.

## Changing Governance

If the project becomes multi-maintainer, update this file with:

- maintainer list
- voting or approval rules
- private security contact
- release authority
