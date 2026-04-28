# Privacy

YubiWatch is designed to run locally on this laptop.

## Data Collected

The native Rust watchdog reads:

- configured `.env` settings
- Windows hardware IDs for present devices
- local dashboard requests from `127.0.0.1`
- local dashboard security actions for the audit stream

## Data Not Collected

YubiWatch does not intentionally collect:

- browsing history
- keystrokes
- file contents outside its project/config files
- network traffic
- remote telemetry

## Network Behavior

The dashboard binds to localhost only:

```text
127.0.0.1
```

It is not intended to accept remote connections.

## Logs And Audit

Native Rust diagnostic logging to disk is disabled by design. Secure Mode writes
a small structured audit log for policy changes and security actions. The audit
log is local JSON Lines data and rotates the current file at the configured size.
The Python fallback can write rotating logs only if explicitly configured.

## Device Information

The dashboard displays Windows hardware IDs for matching Yubico devices. These stay local in the browser and watchdog process.
