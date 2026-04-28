# Changelog

All notable project changes should be recorded here.

## Unreleased

- Added native Rust watchdog as the primary implementation.
- Added localhost dashboard for status, key-gated enablement, persistent startup policy, and guarded device enrollment.
- Added shared trusted-product store so newly trusted device product IDs apply immediately.
- Added `.env` persistence for trusted product IDs.
- Added Python fallback tests and Rust unit tests.
- Added expanded documentation set.
- Added startup dashboard launch support with a Startup-folder fallback when Task Scheduler is unavailable.
- Changed the native guard to start disabled unless `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`.
- Restyled the dashboard as a responsive tactical command panel with clearer action hierarchy.
- Updated dashboard wording to use armed/disarmed command language.
- Added the `Official (Closed), Non-Sensitive.` dashboard classification banner.
- Added a one-time command PIN gate for arm/disarm commands and a lock-first PIN reset flow.
- Changed disarm to require both the configured YubiKey and command PIN.
- Added the modular Secure Mode Controller with independent module toggles, compliance scoring, and audit stream.
- Added local structured audit logging with bounded current-log rotation.

## 1.0.0

- Initial watchdog behavior: detect configured YubiKey and lock the Windows workstation when absent.
- Added configurable timings, fail-safe behavior, and startup scripts.
