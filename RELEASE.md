# Release Process

Use this checklist when cutting a YubiWatch release.

## Pre-Release

```powershell
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
python -m unittest discover -s tests
npm run test:e2e
cargo build --release
.\target\release\yubiwatch.exe --env-file .\.env --check
```

## Manual Verification

1. Run `--foreground --dry-run`.
2. Confirm the dashboard opens at `http://127.0.0.1:8765/`.
3. Confirm the original security key is detected.
4. Confirm **Turn On** and **Always On** require the key to be inserted.
5. Confirm adding another key requires the original key.
6. Confirm emergency task removal instructions still work.

## Versioning

Use semantic versioning:

- Patch: tests, docs, small fixes
- Minor: new dashboard or config features
- Major: incompatible config, startup, or security-model changes

## Release Notes

Update `CHANGELOG.md` with:

- user-visible changes
- security posture changes
- migration notes
- known limitations
