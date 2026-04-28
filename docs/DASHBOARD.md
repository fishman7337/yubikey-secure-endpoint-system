# Dashboard

The native Rust watchdog serves a small dashboard on localhost:

```text
http://127.0.0.1:8765/
```

The server binds only to `127.0.0.1`; it is not exposed on the network.

This laptop is configured to open the dashboard automatically after logon with
`YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP=true`. The setting only opens the browser;
the dashboard server still remains localhost-only.

## Layout

The dashboard shows:

- centered classification text: `Official (Closed), Non-Sensitive.`
- safety-center header with a protection score and quick status
- live refresh status
- laptop lock and security-key state
- startup policy state
- Security PIN state
- Protected Mode posture and protection settings
- recent activity
- simple on/off controls
- matching Windows hardware IDs for the configured key
- allowed key IDs
- untrusted inserted Yubico candidates that can be added

The layout is responsive across desktop, tablet, phone, and narrow 320px-style
viewports. E2E tests check for usable controls and no horizontal overflow.
The visual treatment uses a dark tactical command-center style with a protection
ring, local security-key check, compact KPI strip, and cyan, amber, violet, and
red status cues for protection, key, PIN, and startup state.

## Controls

- **Create PIN**: creates the Security PIN on first use. The configured key must be inserted.
- **Confirm PIN**: verifies the Security PIN and unlocks protected changes for 1 minute.
- **Turn On**: turns laptop lock protection on for the current app session. The configured key and confirmed PIN session are required.
- **Always On**: turns protection on now and after future restarts. The configured key and confirmed PIN session are required.
- **Turn Off**: turns protection off now and after future restarts. The configured key and confirmed PIN session are required.
- **Start Protected Mode**: turns on the modular hardening controller. The configured key and confirmed PIN session are required.
- **Stop Protected Mode**: turns Protected Mode off and lifts restrictions. The configured key and confirmed PIN session are required.
- **Forgot PIN**: exposes the lock-first PIN reset confirmation.
- **Add**: adds an inserted Yubico product ID when the original key is also present.

## Protection Settings

The controller lists every hardening module in the product requirements:

- Sign-In & Access
- Devices
- Network
- Apps
- Files
- Copy & Paste
- Laptop Session
- Safety Checks
- Activity
- Health

Every module can be toggled independently. The dashboard labels each module as
on, ready, or preview so the interface stays honest about what the current
user-mode build can enforce. The security-key/session, activity, and health
modules are active now. Deep OS controls require a future Windows service or
administrator policy backend.

The health panel shows a posture label, score, and warnings. It is meant to
make risks visible, not to hide gaps behind a perfect-looking status.
Module filters default to enabled modules so the panel stays compact. The user
can switch to all modules or current gaps when reviewing the full framework. If
no protections are currently on, the dashboard explains that the **All** view is
where protections can be selected.

## Security PIN

The PIN is a 6 to 12 digit Security PIN. It is set once during first use while
the configured security key is inserted. YubiWatch stores a salted PBKDF2-HMAC-SHA256
verifier, not the plaintext PIN.

When the PIN is typed into the dashboard, press **Confirm PIN**. The dashboard
clears the visible PIN field immediately, starts a 1-minute authorization timer,
and uses a short-lived local token for protected actions. After the timer
expires, enter and confirm the PIN again before changing protection settings.
Three consecutive failed PIN confirmations request the Windows lock screen.

If the PIN is forgotten:

1. Insert the configured security key.
2. Open **Forgot PIN**.
3. Type `LOCK RESET PIN`.
4. Confirm the reset.

YubiWatch locks the laptop first. Only after the Windows lock request succeeds
does it turn protection off, save startup as off, and clear the PIN verifier.
After signing back into Windows, set a new PIN from the dashboard.

## Add Another Key

The dashboard can add another Yubico product ID without editing `.env` by hand.
The logic is intentionally conservative:

1. The original configured key, currently `0x0402`, must be inserted.
2. The new Yubico device must be inserted at the same time.
3. The dashboard shows the new untrusted product ID as a candidate.
4. Click **Add** for that candidate.

The new product ID is added to the running watchdog immediately and saved back
to `.env` as `YUBIWATCH_PRODUCT_IDS=...`, so it survives restarts.

This allows a Yubico USB product ID, not a cryptographic serial number. That
matches the current detection model and is convenient for this laptop, but it is
not the same as authenticating a unique physical key.

## Startup Policy

Protection starts off unless `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`.

1. Insert the configured security key.
2. Create the Security PIN if this is first use.
3. Enter the Security PIN.
4. Click **Turn On** to protect only this running session.
5. Click **Always On** to protect this session and future startups.
6. Click **Turn Off** to pause enforcement and save startup as off.

## Security Properties

- Dashboard requests require a per-process CSRF token embedded in the served page.
- The dashboard is local-only.
- Turning protection on or off requires the configured key and a confirmed PIN session.
- First-use PIN setup requires the configured key.
- PIN reset requires the configured key, an explicit confirmation phrase, and a successful Windows lock request.
- Protected Mode and module changes require the configured key plus a confirmed PIN session.
- Audit entries are local JSON Lines records and are visible from the dashboard.

## Limits

This does not make a consumer Windows laptop tamper-proof. A user or attacker
with administrative control can still stop the process, disable the scheduled
task, boot another OS, or edit files offline. To resist that class of attack,
the next step is a proper Windows service with locked-down ACLs, service
recovery, code signing, and device-management policy.
