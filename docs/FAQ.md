# FAQ

## Is YubiWatch Tamper-Proof?

No. It is a local watchdog for an already-running Windows session. A Windows administrator or someone with offline disk access can still disable or replace it.

## Why Rust?

Rust gives a small native executable, no interpreter dependency, strong memory safety, and direct Windows API access.

## Why Keep Python?

The Python version is a readable fallback/reference and still has tests. The Rust executable is the primary runtime.

## Does Add Device Add A Unique Physical Key?

Not yet. It adds a Yubico USB product ID. That is convenient but not the same as cryptographic identity or serial-number trust.

## Why Do Protection Changes Require A PIN?

The configured security key proves physical possession, and the Security PIN proves
local authorization. Requiring both makes the dashboard harder to abuse from an
already-unlocked browser session.

## What If I Forget The PIN?

Use **Forgot PIN** from the dashboard while the configured security key is
inserted. After you type `LOCK RESET PIN`, YubiWatch locks Windows first, then
turns protection off and clears the PIN verifier. Sign back into Windows and set
a new PIN.

## What If I Lose The Key?

Disable the scheduled task from an authenticated Windows session:

```powershell
Unregister-ScheduledTask -TaskName YubiWatchTask -Confirm:$false
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\YubiWatch.lnk" -ErrorAction SilentlyContinue
```

Then update `.env` after replacing the key.

## Does The Dashboard Work Remotely?

No. It binds to `127.0.0.1` only.

## Are All Protected Mode Modules Enforced Today?

No. The security-key/session, activity, and health modules are active. USB, network,
app, data, clipboard, and deeper tamper controls are preview placeholders
until a Windows service or administrator policy backend is added.
