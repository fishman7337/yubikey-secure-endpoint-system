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

Disable Startup-folder fallback:

```powershell
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\YubiWatch.lnk" -ErrorAction SilentlyContinue
```

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
