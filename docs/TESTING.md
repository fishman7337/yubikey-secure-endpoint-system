# Testing

## GitHub Actions

The repository includes `.github/workflows/ci.yml`. It runs on
`windows-latest` for pushes and pull requests to `main`, and can also be
started manually from GitHub Actions. The workflow checks Rust formatting,
Rust tests, clippy, Python tests, and Playwright dashboard E2E tests.

## Rust Tests

Run the native test suite:

```powershell
cargo test
```

These tests cover:

- `.env` parsing defaults and product-ID pinning
- duplicate and invalid product-ID handling
- timing minimums
- hardware-ID matching
- Windows `MULTI_SZ` parsing
- dashboard request parsing and token generation
- dashboard trusted-device rendering
- Security PIN validation, verifier storage, verification, and reset clearing
- one-minute Security PIN authorization tokens and three-failure lock requests
- Protected Mode module registry, posture JSON, and recent activity logging
- protected product-ID addition and `.env` persistence helpers
- runtime security gate enable/disable behavior
- grace-period locking behavior
- relock cooldown behavior
- state reset after key reinsertion
- fail-safe behavior when USB detection fails

## Rust Manual Checks

Build and check live security-key detection:

```powershell
cargo build --release
.\target\release\yubiwatch.exe --env-file .\.env --check
```

Run the watchdog without locking:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground --dry-run
```

Check the dashboard manually:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground
```

Then open `http://127.0.0.1:8765/` and verify that enabling requires the
configured key to be inserted.

## Dashboard E2E Tests

Install the browser test dependency once:

```powershell
npm install
npx playwright install chromium
```

Run the E2E suite:

```powershell
npm run test:e2e
```

The E2E tests build an isolated native executable under `target\e2e`, start the
dashboard on a test port, and verify desktop, tablet, phone, and very narrow
layouts. They check that core controls render, the classification banner,
Security PIN panel, Protection Settings, and Recent Activity are visible,
dashboard API fields are present, protection and Protected Mode endpoints reject
when the configured key is absent, confirmed PIN sessions unlock controls for 1
minute, expired PIN sessions relock protected controls, action buttons remain
usable, empty protection views explain what to do next, and the page has no
horizontal overflow.

## Python Reference Tests

The Python implementation remains testable:

```powershell
python -m unittest discover -s tests
```

The Python tests cover equivalent policy behavior and PyUSB filtering.

## What Is Not Automated

The tests do not call the real Windows lock action. Live locking should be checked manually only after `--check` and `--dry-run` behave correctly.
