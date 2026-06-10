# Operations

This page is for day-to-day use of YubiWatch on the laptop.

## Start Manually

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground
```

## Dry Run

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground --dry-run
```

## Dashboard

```text
http://127.0.0.1:8765/
```

At laptop logon, the scheduled task starts the VBS launcher, and the launcher
starts the hidden watchdog process. Because `.env` sets
`YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP=true`, the native watchdog opens this URL
in the default browser. Set it to `false` to keep startup headless.

Use the dashboard to:

- view protection state
- verify the security key is detected
- set the Security PIN on first use while the key is inserted
- turn protection on only while the key is inserted and the Security PIN is entered
- choose **Always On** when you want future startups protected
- turn protection off with the key inserted and the Security PIN entered
- reset a forgotten PIN through the lock-first recovery flow
- start or stop Protected Mode
- toggle individual protection modules
- review items needing attention and recent activity
- add another inserted Yubico product ID while the original key is present

Policy changes require the configured security key and Security PIN. Active
modules cover security-key access, laptop auto-lock, local activity history, and
dashboard health checks. Modules marked preview or planned are visible
placeholders; they do not block USB devices, networks, apps, files, clipboard
activity, or deeper tampering until a service-backed enforcement backend is
added.

## Scheduled Task

Install or refresh:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_task.ps1
```

After the next user logon, the control panel should open automatically if the
native watchdog starts and the dashboard port is free. The task is logon-only;
it does not run at boot before sign-in, unlock, or session-change events.

Duplicate starts are intentionally ignored. Task Scheduler uses
`MultipleInstances IgnoreNew`, and the native executable uses a named mutex for
the configured `.env` path so a second copy exits and points you back to the
existing dashboard.

If Windows blocks scheduled-task registration, the installer creates a per-user
Startup shortcut instead. That shortcut is a fallback only; when the scheduled
task installs successfully, the installer removes the fallback shortcut.

Remove:

```powershell
Unregister-ScheduledTask -TaskName YubiWatchTask -Confirm:$false
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\YubiWatch.lnk" -ErrorAction SilentlyContinue
```

## After Changes

After changing Rust code:

```powershell
cargo test
cargo build --release
```

If `target\release\yubiwatch.exe` is in use, stop the running watchdog or reboot before rebuilding the primary release binary.
As a no-downtime workaround, build to another target directory and place the
fresh executable at `.dist\yubiwatch-current.exe`; `start_watchdog.bat` prefers
that path on the next logon, then falls back to `.dist\yubiwatch-latest.exe`
and `.dist\yubiwatch.exe`.
