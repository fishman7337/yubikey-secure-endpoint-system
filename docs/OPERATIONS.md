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

At laptop logon, the scheduled task starts the VBS launcher. Because `.env`
sets `YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP=true`, the launcher also opens this
URL in the default browser. Set it to `false` to keep startup headless.

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

Policy changes require the configured security key and Security PIN. Modules
marked preview are safe placeholders until a service-backed
enforcement backend is added.

## Scheduled Task

Install or refresh:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_task.ps1
```

After the next logon, the control panel should open automatically if the native
watchdog starts and the dashboard port is free.
If Windows blocks scheduled-task registration, the installer creates a per-user
Startup shortcut instead.

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
fresh executable at `.dist\yubiwatch-latest.exe`; `start_watchdog.bat` prefers
that path on the next logon, then falls back to `.dist\yubiwatch.exe`.
