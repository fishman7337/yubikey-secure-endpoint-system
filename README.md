# YubiWatch

[![CI](https://github.com/fishman7337/yubikey-secure-endpoint-system/actions/workflows/ci.yml/badge.svg)](https://github.com/fishman7337/yubikey-secure-endpoint-system/actions/workflows/ci.yml)

YubiWatch is a Windows laptop-protection app that locks the laptop when the configured security key is removed.

The primary implementation is now the native Rust executable at `target\release\yubiwatch.exe`. The Python version remains in the repo as a readable reference and fallback during migration.

## Why Rust

- Native executable with no interpreter, virtual environment, or Python background process.
- Constant watchdog state: `O(1)` space while running.
- Constant policy work per tick: `O(1)` outside the Windows USB device lookup.
- Very small release binary; the current optimized executable is about 241 KB.
- Windows-native detection through SetupAPI and locking through `LockWorkStation`.
- No disk logs by default, so there is no unbounded file growth.
- Localhost dashboard for turning protection on only when the key is inserted.
- Native protection starts off unless `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`.
- Native single-instance guard prevents a second watchdog for the same `.env`.

## Current Defaults

- Vendor ID: `0x1050`
- Product ID: `0x0402`, your original detected security-key product ID
- Present polling: every 2 seconds
- Missing polling: every 0.5 seconds
- Missing grace period: 2 seconds
- Relock cooldown while absent: 5 seconds
- Fail-safe mode: USB detector errors are treated as key absence
- Startup policy: off until **Always On** is selected with the key and Security PIN
- Startup trigger: current-user logon only
- Startup dashboard: the native watchdog opens it in the default browser after logon
- Duplicate process policy: Task Scheduler ignores duplicate starts and the native mutex exits duplicate manual launches
- Security PIN: required for protection changes, set once on first use
- Protected Mode: modular hardening controller, off by default and protected by the PIN plus security key

## Build And Check

If Cargo is not on this shell's `PATH`, run:

```powershell
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
```

Build and test the native executable:

```powershell
cargo test
python -m unittest discover -s tests -v
npm run test:e2e
cargo build --release
.\target\release\yubiwatch.exe --env-file .\.env --check
```

The Python fallback unit tests pass without installing PyUSB. Install
`requirements.txt` only when running the Python fallback against real USB
hardware, then run the same tests again if you are validating that path.

Run without locking while you observe behavior:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground --dry-run
```

## Dashboard

The native watchdog serves a local dashboard by default:

```text
http://127.0.0.1:8765/
```

This laptop's `.env` also sets `YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP=true`, so
the native watchdog opens the control panel in the default browser after it
starts. The VBS launcher only starts the hidden watchdog process.

The dashboard shows the centered classification banner
`Official (Closed), Non-Sensitive.` and uses a dark command-panel theme with
cyan, amber, and violet status cues.

On first use, insert the configured security key and set a 6 to 12 digit Security
PIN. The PIN is set once and stored as a salted verifier, not plaintext.
Press **Confirm PIN** after entering the PIN. That unlocks protected dashboard
changes for 1 minute, clears the visible PIN field, and then expires. **Turn On**
and **Always On** require that confirmed PIN session plus the key. **Turn Off**
also requires both, then saves the startup posture as off. Three consecutive
failed PIN confirmations lock the laptop.

If the PIN is forgotten, the dashboard recovery action requires the configured
key plus the exact reset phrase. It locks the laptop first, then turns
protection off and clears the PIN. After signing back into Windows, set a new PIN.

The dashboard can also add another inserted Yubico product ID, but only while
the original key is present. The new ID is added live and saved back to `.env`.

The dashboard now includes **Protection Settings**. It shows protection
modules, score, items needing attention, and recent activity. The security-key,
laptop-session, activity-history, and health modules are active today. Deeper
USB allow-listing, network, app, file, clipboard, and tamper modules are preview
or planned controls only until a Windows service or admin policy backend is
added.

This protects the supported disable path, but it is not magic. A Windows admin
can still kill processes, unregister scheduled tasks, or edit files offline.
See `SECURITY.md` for the hard boundary and hardening notes.

## Startup

`start_watchdog.bat` now prefers the Rust executable:

1. `.dist\yubiwatch-current.exe`
2. `.dist\yubiwatch-latest.exe`
3. `.dist\yubiwatch.exe`
4. `target\release\yubiwatch.exe`
5. Python virtual environment fallback
6. system Python fallback

Install or refresh the logon scheduled task:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_task.ps1
```

On the next user logon, Task Scheduler starts `watchdog_launcher.vbs`, which
starts the watchdog through `start_watchdog.bat`. The task is logon-only: it
does not register boot, unlock, or session-change triggers. It also uses
`MultipleInstances IgnoreNew`, and the native executable has a per-`.env` mutex,
so duplicate starts reuse the existing dashboard instead of launching another
watchdog.

If Windows denies scheduled-task registration, the installer falls back to a
per-user Startup shortcut that runs the same launcher. When scheduled-task
registration succeeds, the installer removes that fallback shortcut.

## Documentation

- `docs\INDEX.md`: documentation map
- `docs\SETUP.md`: install and startup flow
- `docs\CONFIGURATION.md`: every `.env` setting
- `docs\ARCHITECTURE.md`: runtime design and complexity
- `docs\DASHBOARD.md`: local dashboard and startup policy controls
- `docs\SECURE_MODE_PRD.md`: modular secure-mode product requirements
- `docs\OPERATIONS.md`: day-to-day operation
- `docs\TROUBLESHOOTING.md`: common problems and fixes
- `docs\RUST_NATIVE.md`: Rust-specific notes
- `docs\TESTING.md`: Rust and Python test commands
- `docs\STYLE_GUIDE.md`: code and docs style
- `docs\FAQ.md`: quick answers
- `docs\DECISIONS.md`: architecture decisions
- `SECURITY.md`: security posture and recovery
- `THREAT_MODEL.md`: scope and limits
- `PRIVACY.md`: local data and network behavior
- `CONTRIBUTING.md`: contribution workflow
- `CODE_OF_CONDUCT.md`: conduct expectations
- `SUPPORT.md`: support checklist
- `RELEASE.md`: release checklist
- `GOVERNANCE.md`: decision making
- `MAINTAINERS.md`: maintainer responsibilities
- `CHANGELOG.md`: notable changes
- `LICENSE`: MIT license
- `.github\ISSUE_TEMPLATE\...`: issue templates
- `.github\PULL_REQUEST_TEMPLATE.md`: pull request template

## Emergency Recovery

Insert the key, sign in, then use the dashboard to turn protection off with the Security PIN.
If the watchdog itself needs to be removed for maintenance, disable the task:

```powershell
Unregister-ScheduledTask -TaskName YubiWatchTask -Confirm:$false
```

For debugging, set `YUBIWATCH_ALWAYS_KEEP_ENABLED=false` in `.env` or run with `--dry-run`.
