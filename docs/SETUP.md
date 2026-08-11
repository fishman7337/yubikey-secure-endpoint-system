# Setup Notes

Run commands from the repository root.

## Rust Toolchain

The repository pins Rust 1.95.0, with Clippy and rustfmt, in
`rust-toolchain.toml`. Rustup-aware commands automatically select that toolchain
so local and CI checks use the same compiler release.

Rust is installed at:

```powershell
$env:USERPROFILE\.cargo\bin
```

If `cargo` is not recognized in a new shell, add it for the current session:

```powershell
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
```

## Native Build

```powershell
cargo test
cargo build --release
.\target\release\yubiwatch.exe --env-file .\.env --check
```

The release binary is:

```powershell
.\target\release\yubiwatch.exe
```

## Dry Run

Use this before allowing the program to lock the laptop:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground --dry-run
```

Remove and reinsert the key while watching the terminal output.

## Dashboard

The watchdog starts a localhost dashboard by default:

```text
http://127.0.0.1:8765/
```

This laptop's `.env` sets `YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP=true`, so the
startup launcher opens that local control panel in the default browser after
logon. Set it to `false` if you want the watchdog to run quietly in the
background.

Protection starts off unless `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`. On first
use, insert the configured security key and set the Security PIN. After that,
turning protection on or off requires both the configured key and the PIN. Use `--no-dashboard`
for a run without the dashboard.

## Startup

The existing VBS and batch launcher can stay. `start_watchdog.bat` now starts
the side-by-side Rust binary in `.dist` when it exists, then falls back to
`target\release\yubiwatch.exe`.

Install or refresh the scheduled task:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_task.ps1
```

If Windows denies scheduled-task registration, the installer falls back to a
per-user Startup folder shortcut:

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\YubiWatch.lnk
```

## Python Fallback

The Python implementation is optional now:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe .\yubikey_watchdog.py --check
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

## Common Tuning

- `YUBIWATCH_MISSING_GRACE_SECONDS=0`: lock immediately when the key disappears.
- `YUBIWATCH_MISSING_GRACE_SECONDS=2`: default; avoids locks from tiny USB glitches.
- `YUBIWATCH_RELOCK_SECONDS=5`: re-lock every 5 seconds while the key is absent.
- `YUBIWATCH_PRESENT_POLL_SECONDS=5`: lower CPU use, slower reaction.
- `YUBIWATCH_PRODUCT_IDS=0x0402`: only accept the original detected key product ID.
- `YUBIWATCH_FAIL_SAFE_LOCK=false`: do not lock when USB detection itself fails.
- `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`: start protection enabled after every launch.
- `YUBIWATCH_DASHBOARD_ENABLED=false`: run without the localhost dashboard.
- `YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP=false`: keep startup headless while the dashboard server still runs.
- `YUBIWATCH_PIN_FILE=`: leave blank to use the per-user default PIN verifier path.
- `YUBIWATCH_SECURE_MODE_ENABLED=false`: start with modular Protected Mode off.
- `YUBIWATCH_AUDIT_LOG_FILE=`: leave blank to use the per-user default audit log path.
- `YUBIWATCH_DISABLE_PROOF_TIMEOUT_SECONDS=60`: legacy proof timeout; retained for compatibility.
