# Repository agent instructions

## Scope and precedence

These instructions apply to the entire repository. If a future directory contains a more specific `AGENTS.md`, follow that file for work inside its directory. Direct maintainer instructions take precedence.

## Project context

- **Project:** YubiWatch
- **Repository shape:** Python, Node.js, Rust
- Read `README.md` before changing behaviour, architecture, data handling, or public claims.
- Treat `CONTRIBUTING.md` as the authoritative development workflow and command reference.
- Follow `SECURITY.md` for vulnerability reporting and `CODE_OF_CONDUCT.md` for collaboration.
- Use the workflows under `.github/workflows/` as the final cross-platform CI contract.

## Working agreement

1. Keep each change focused on a clear problem; avoid unrelated cleanup.
2. Inspect nearby tests, configuration, documentation, and generated artifacts before editing.
3. Add or update tests for behavioural changes, including failure and boundary cases.
4. Preserve public APIs and file formats unless the change explicitly includes a documented migration.
5. Never commit credentials, personal data, local environments, caches, or unlicensed datasets.
6. Do not weaken lint, coverage, security, or dependency gates merely to obtain a passing run.
7. After code or architecture changes, run `graphify update .` and review the graph diff; do not commit cache-only churn.
8. Do not stage, commit, push, or publish changes unless the maintainer explicitly requests that action.

## Required validation

Run commands from the repository root. Use a clean environment when dependency or packaging behaviour changes.

### Standard development gate

```text
python -m venv .venv
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m ruff format --check .
python -m pytest
python -m compileall tests yubikey_watchdog.py yubiwatch
npm ci
npm run test:e2e
npm audit --omit=dev --audit-level=moderate
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

### Repository-specific CI-equivalent checks

```text
# No additional repository-specific command beyond the development gate above.
```

Also run `git diff --check`. Record exactly which commands ran, their outcomes, and any documented prerequisite that prevented a check. Do not describe an unexecuted check as passing.

### Conditional or integration setup

- Install Chromium with `npx playwright install chromium` before browser tests when it is not already present.
- Native runtime, release builds, workstation locking, and scheduled-task installation are Windows-specific; use foreground dry-run mode for observation.

## Managed artifacts and data

- Keep Cargo `target/`, `.dist/`, logs, Playwright reports, and watchdog runtime files out of Git.
- Treat `.env` as machine-local security state containing key identifiers and PIN-related configuration; never commit or overwrite a user's real file during tests.

## Integration and claim boundaries

- Use isolated test configuration and dry-run behavior because the real watchdog can lock the workstation.
- `install_task.ps1` mutates Task Scheduler or the per-user Startup folder and requires explicit authorization.
- The implemented boundary is a user-mode YubiKey watchdog; broader USB, network, application, data, clipboard, tamper, service, and administrator hardening remain previews.
- **Verified local capability:** 41 Rust, 11 Python, and 24 browser tests across four viewports.
- **Known boundary:** Implemented user-mode watchdog; broader hardening controls are previews.

## Code, documentation, and evidence standards

- For Python, follow PEP 8, PEP 257, and Google-style docstrings in the production scopes configured by Ruff.
- For JavaScript or TypeScript, follow the repository's ESLint and Prettier configuration and avoid untyped or silently coerced inputs.
- For Rust, require `rustfmt`, resolve Clippy findings, and document public or safety-sensitive interfaces.
- Prefer small, typed, testable units and explicit error handling. Avoid silent fallbacks that hide invalid data, missing models, credentials, or services.
- Update README, architecture, data/model documentation, examples, and changelog material when interfaces or behaviour change.
- Every quantitative claim must retain its denominator, dataset/version, split, date range, run/configuration, and calculation method.
- Distinguish measured results from targets, examples, heuristics, previews, and prior runs. Do not infer deployment, accuracy, security, causality, or impact from tests or scaffolding alone.
- Update generated files through their source script. If no generator exists, document the manual process and verify semantic equivalence.

## Review and handoff

Before handing off a change, provide a concise summary, list changed files, report validation evidence, and call out residual risks or unavailable integrations. Keep commits imperative and scoped; do not add tool-attribution or automated co-author trailers.
