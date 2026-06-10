# Troubleshooting

## `cargo` Is Not Recognized

```powershell
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo --version
```

## The Release Binary Cannot Be Rebuilt

If Cargo reports access denied when replacing `target\release\yubiwatch.exe`, the watchdog is probably running.

Check:

```powershell
Get-Process yubiwatch -ErrorAction SilentlyContinue
```

Stop the running watchdog from an elevated terminal or reboot, then rebuild:

```powershell
cargo build --release
```

## Dashboard Does Not Open

The native watchdog owns dashboard browser startup. The VBS launcher should only
start `start_watchdog.bat`.

Confirm browser startup is enabled:

```powershell
Select-String YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP .\.env
```

Check the configured port:

```powershell
Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue
```

Run in foreground to see startup messages:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground
```

Force one manual browser open:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground --open-dashboard
```

If the foreground run says another copy is already running, use the existing
dashboard or stop the running `yubiwatch` process before starting a new one.

## YubiWatch Is Already Running

The scheduled task uses `MultipleInstances IgnoreNew`, and the native executable
uses a named mutex keyed to the configured `.env` path. A second manual launch
prints that YubiWatch is already running and exits successfully.

Check the running process:

```powershell
Get-Process yubiwatch -ErrorAction SilentlyContinue
```

Use the existing dashboard at `http://127.0.0.1:8765/`, or stop the process if
you are intentionally replacing the running executable.

## Security Key Is Not Detected

Run:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --check
```

Verify:

- the key is physically inserted
- `.env` has the expected `YUBIWATCH_VENDOR_ID`
- `.env` has the expected `YUBIWATCH_PRODUCT_IDS`
- the key appears in Windows Device Manager

## Accidental Lockouts

Disable scheduled-task startup:

```powershell
Unregister-ScheduledTask -TaskName YubiWatchTask -Confirm:$false
```

Disable any old Startup-folder fallback:

```powershell
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\YubiWatch.lnk" -ErrorAction SilentlyContinue
```

Startup is intended to be logon-only. If the watchdog appears to start after
unlock or session changes, check for an older task or shortcut and rerun
`install_task.ps1`; successful task registration removes the fallback shortcut.

Then test with:

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --foreground --dry-run
```

## Add-Device Candidate Does Not Appear

The dashboard only shows untrusted Yubico product IDs when:

- the original configured key is inserted
- another Yubico device is inserted
- the other device has a product ID not already listed in `.env`

This feature trusts product IDs, not unique serial numbers.

## Preview Module Does Not Block Activity

This is expected for modules marked preview or planned. The current user-mode
build actively enforces security-key access, laptop auto-lock, local activity
history, and dashboard health checks. USB device control, network rules, app
allow-lists, file protection, copy/paste controls, and deeper tamper blocking
need a future service or administrator policy backend before they can enforce
outside the dashboard.
