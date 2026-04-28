# Security Notes

YubiWatch is a local convenience control, not a replacement for full-disk encryption, Windows Hello, strong passwords, or device management policy.

## Current Defaults

- Accept only the original detected product ID: `YUBIWATCH_PRODUCT_IDS=0x0402`.
- Lock when USB detection fails: `YUBIWATCH_FAIL_SAFE_LOCK=true`.
- Keep logs disabled by default to avoid leaking activity patterns and filling disk.
- Re-lock while the key remains absent.
- Prefer the native Rust executable over the Python fallback.
- Start disabled unless `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`.
- Require the configured key and command PIN before the dashboard can arm or disarm enforcement.
- Store the command PIN as a salted PBKDF2-HMAC-SHA256 verifier, never as plaintext.
- Keep Secure Mode off by default until the user engages it with key and PIN.
- Record dashboard security actions in a structured local audit log.

## Hardening Ideas

- Keep the folder writable only by your Windows account.
- Build the release executable locally with `cargo build --release`.
- Keep `YUBIWATCH_PRODUCT_IDS` pinned unless you rotate to a new key.
- Test changes with `--dry-run` before installing the task.
- Keep Windows sign-in and disk encryption enabled; this tool only locks an already running session.
- Use a standard Windows account for daily work and reserve administrator access
  for maintenance.
- For stronger tamper resistance, migrate the watchdog to a Windows service with
  restricted service ACLs and recovery policy.

## Dashboard Command Policy

The dashboard does not allow a plain button click to change enforcement. It
first checks that the configured key is inserted, then verifies the command PIN.

First use requires the configured YubiKey to be inserted before a 6 to 12 digit
PIN can be set. The PIN file is created once with an exclusive create operation;
normal setup requests cannot overwrite it.

There are three normal command paths:

- **Arm Guard**: arms the current process only.
- **Keep Armed**: arms the current process and saves
  `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`.
- **Disarm Guard**: disarms the current process and saves
  `YUBIWATCH_ALWAYS_KEEP_ENABLED=false`.

All three require the configured YubiKey and the command PIN. Repeated bad PIN
attempts are throttled in memory.

Secure Mode and individual module toggles also require the configured YubiKey
and command PIN. Standing Secure Mode down disarms the guard and persists Secure
Mode as off.

## Modular Hardening Boundary

The current build actively enforces:

- YubiKey and command PIN protected dashboard commands
- workstation lock on key removal while armed
- structured dashboard audit logging
- compliance scoring and risk visibility

The current build models these modules but does not deeply enforce them yet:

- USB storage blocking
- network route or firewall lockdown
- application execution allowlisting
- sensitive file movement controls
- clipboard and remote transfer controls
- system tamper response

Those controls require a Windows service, administrator policy, or enterprise
device-management layer to enforce safely and reversibly.

## PIN Reset Flow

The forgotten-PIN flow is intentionally disruptive:

1. The configured YubiKey must be inserted.
2. The user must type the exact confirmation phrase `LOCK RESET PIN`.
3. YubiWatch calls the real Windows lock action first.
4. After the lock request succeeds, YubiWatch disarms the guard, saves startup
   as disarmed, and clears the PIN verifier.
5. After signing back into Windows, the user can set a new command PIN.

This makes reset a physical-presence plus Windows-sign-in recovery path instead
of a quiet browser-only bypass.

## Adding Devices

The dashboard can add another inserted Yubico product ID only while the original
configured key is present. This prevents a random inserted key from becoming
trusted by itself. The added product ID is active immediately and persisted to
`.env`.

The current trust model is product-ID based, not serial-number based. A future
hardening step would be reading a stable YubiKey serial or requiring a
cryptographic challenge through PIV/FIDO before adding or disabling.

## Hard Limits

No process running as your user can guarantee that "no one can disable it" on a
laptop where the attacker has administrator rights or offline disk access. An
administrator can stop processes, remove scheduled tasks, alter binaries, or
boot another environment. This project hardens the normal supported control
path; it is not a tamper-proof endpoint security product.

## Recovery

If the settings are too strict, insert the YubiKey and disable the scheduled task:

```powershell
Unregister-ScheduledTask -TaskName YubiWatch -Confirm:$false
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\YubiWatch.lnk" -ErrorAction SilentlyContinue
```

Then run the native executable with `--dry-run` while debugging.
