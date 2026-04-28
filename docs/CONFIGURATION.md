# Configuration

Settings live in `.env`. The Rust executable reads the same core settings as the Python fallback.

## USB Identity

| Setting | Default | Meaning |
| --- | --- | --- |
| `YUBIWATCH_VENDOR_ID` | `0x1050` | Yubico USB vendor ID. |
| `YUBIWATCH_PRODUCT_IDS` | `0x0402` | Pinned original security-key product ID. Blank means accept any Yubico product ID. |

The dashboard can append product IDs to `YUBIWATCH_PRODUCT_IDS` when the
original configured key is inserted. The first product ID remains the original
key used to authorize adding more devices.

## Timing

| Setting | Default | Meaning |
| --- | --- | --- |
| `YUBIWATCH_PRESENT_POLL_SECONDS` | `2.0` | Poll interval while the key is present. Higher saves a little more idle work. |
| `YUBIWATCH_MISSING_POLL_SECONDS` | `0.5` | Poll interval during the grace period after the key disappears. |
| `YUBIWATCH_MISSING_GRACE_SECONDS` | `2.0` | Time to wait before locking after the key first disappears. |
| `YUBIWATCH_POST_LOCK_POLL_SECONDS` | `2.0` | Poll interval after a lock while waiting for reinsertion. |
| `YUBIWATCH_RELOCK_SECONDS` | `5.0` | Minimum time between repeated locks while the key remains absent. |
| `YUBIWATCH_STARTUP_GRACE_SECONDS` | `5.0` | Delay after startup before enforcing the lock policy. |

## Security Behavior

| Setting | Default | Meaning |
| --- | --- | --- |
| `YUBIWATCH_FAIL_SAFE_LOCK` | `true` | Treat detector errors as key absence. |
| `YUBIWATCH_ALWAYS_KEEP_ENABLED` | `false` | Native startup policy. When false, protection starts off until enabled from the dashboard with the key inserted. |
| `YUBIWATCH_LOCK_ENABLED` | `false` | Python fallback compatibility setting. The dashboard keeps this in sync with `YUBIWATCH_ALWAYS_KEEP_ENABLED`. |
| `YUBIWATCH_DASHBOARD_ENABLED` | `true` | Start the localhost dashboard with the native watchdog. |
| `YUBIWATCH_DASHBOARD_PORT` | `8765` | Localhost dashboard port. |
| `YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP` | `false` | Open the localhost dashboard in the default browser when the native watchdog starts. This laptop's `.env` sets it to `true`. |
| `YUBIWATCH_PIN_FILE` | `%LOCALAPPDATA%\YubiWatch\pin.dat` | Optional override for the Security PIN verifier file. Leave blank to use the per-user local default. |
| `YUBIWATCH_SECURE_MODE_ENABLED` | `false` | Persisted global Protected Mode state. When true, enabled modules become active where enforcement exists. |
| `YUBIWATCH_AUDIT_LOG_FILE` | `%LOCALAPPDATA%\YubiWatch\audit.jsonl` | Optional override for the structured audit log. |
| `YUBIWATCH_AUDIT_MAX_BYTES` | `1048576` | Rotates the current audit log after this size. Minimum is 64 KiB. |
| `YUBIWATCH_DISABLE_PROOF_TIMEOUT_SECONDS` | `45` | Legacy disable-proof timeout retained for compatibility. |

The Security PIN verifier file contains a salted PBKDF2-HMAC-SHA256 hash and
metadata. It does not contain the plaintext PIN. Keep the default path unless
you have a specific backup or profile-management reason to move it.

## Protected Mode Modules

Each module is independently toggleable and persisted with a boolean `.env`
setting:

| Setting | Default | Current capability |
| --- | --- | --- |
| `YUBIWATCH_MODULE_IDENTITY_ACCESS` | `true` | Active security-key and Security PIN controls. |
| `YUBIWATCH_MODULE_DEVICE_CONTROL` | `false` | Observe-ready USB policy module. |
| `YUBIWATCH_MODULE_NETWORK_SECURITY` | `false` | Policy-ready network module. |
| `YUBIWATCH_MODULE_APPLICATION_CONTROL` | `false` | Policy-ready app allowlist module. |
| `YUBIWATCH_MODULE_DATA_PROTECTION` | `false` | Policy-ready data boundary module. |
| `YUBIWATCH_MODULE_CLIPBOARD_TRANSFER` | `false` | Policy-ready clipboard/transfer module. |
| `YUBIWATCH_MODULE_SESSION_PROTECTION` | `true` | Active key-removal lock behaviour. |
| `YUBIWATCH_MODULE_TAMPER_DETECTION` | `false` | Observe-ready tamper module. |
| `YUBIWATCH_MODULE_AUDIT_LOGGING` | `true` | Active local audit stream. |
| `YUBIWATCH_MODULE_COMPLIANCE_MONITORING` | `true` | Active posture scoring and warnings. |

Preview modules are visible and reversible today. Deep blocking of USB
storage, unknown applications, network routes, cloud sync, or clipboard transfer
requires an admin-backed Windows service or enterprise policy layer.

## Python-Only Settings

The native Rust executable does not need libusb and does not write logs. These settings remain for the Python fallback:

| Setting | Meaning |
| --- | --- |
| `YUBIWATCH_LIBUSB_DLL` | Optional PyUSB/libusb path override. |
| `YUBIWATCH_LOG_FILE` | Optional Python rotating log path. |
| `YUBIWATCH_LOG_LEVEL` | Python logging level. |
| `YUBIWATCH_CONSOLE_LOG` | Python console logging toggle. |
| `YUBIWATCH_MAX_LOG_BYTES` | Python log rotation size. |
| `YUBIWATCH_LOG_BACKUP_COUNT` | Python log rotation backup count. |
