# Support

YubiWatch is a local laptop security helper. Support should prioritize safe recovery and avoiding accidental lockouts.

## Quick Checks

```powershell
.\target\release\yubiwatch.exe --env-file .\.env --check
.\target\release\yubiwatch.exe --env-file .\.env --foreground --dry-run
```

## Recovery

Disable the scheduled task:

```powershell
Unregister-ScheduledTask -TaskName YubiWatch -Confirm:$false
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\YubiWatch.lnk" -ErrorAction SilentlyContinue
```

Then debug in dry-run mode before reinstalling startup.

## Where To Look

- Setup help: `docs\SETUP.md`
- Dashboard help: `docs\DASHBOARD.md`
- Troubleshooting: `docs\TROUBLESHOOTING.md`
- Security model: `SECURITY.md`
- Threat model: `THREAT_MODEL.md`

## Before Asking For Help

Collect:

- Windows version
- Rust version from `cargo --version`
- output from `.\target\release\yubiwatch.exe --env-file .\.env --check`
- current `.env` values with secrets removed, if any are later added
- whether the scheduled task or Startup shortcut is installed and running
