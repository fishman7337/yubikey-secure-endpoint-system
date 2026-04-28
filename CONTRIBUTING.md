# Contributing

Thanks for helping improve YubiWatch. This project is security-adjacent, so changes should be small, testable, and explicit about their operational impact.

## Development Setup

```powershell
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo test
cargo clippy --all-targets -- -D warnings
python -m unittest discover -s tests
npm install
npx playwright install chromium
npm run test:e2e
```

Use `--dry-run` before testing behavior that could lock the workstation:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground --dry-run
```

## Expectations

- Keep the Rust native watchdog as the primary implementation.
- Keep the Python implementation as a reference/fallback unless intentionally removing it.
- Do not add network-facing control surfaces. Dashboard endpoints must stay localhost-only.
- Do not add unbounded logs, telemetry, or background file growth.
- Add tests for config, security state, dashboard actions, and lock timing changes.
- Document security tradeoffs honestly.

## Pull Request Checklist

- `cargo fmt --all -- --check`
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `python -m unittest discover -s tests`
- `npm run test:e2e`
- Docs updated when behavior, setup, or security posture changes
- Manual `--check` and `--dry-run` completed for watchdog changes

## Commit Style

Use short imperative commit messages:

```text
Add guarded dashboard device enrollment
Fix relock cooldown test
Document service hardening limits
```

## Security-Sensitive Changes

For changes that affect disabling, locking, dashboard control, or trusted-device enrollment, include:

- what attack or misuse path the change addresses
- what it does not protect against
- how it was tested
