# Architecture

## Primary Runtime

The primary runtime is the Rust binary:

1. `src/main.rs` parses CLI flags and loads `.env`.
2. `src/config.rs` converts settings into typed durations, booleans, and USB IDs.
3. `src/detector.rs` asks Windows SetupAPI for present hardware IDs.
4. `src/security.rs` maintains the runtime protection state.
5. `src/dashboard.rs` serves the localhost control dashboard.
6. `src/mode.rs` manages Protected Mode and modular hardening state.
7. `src/audit.rs` writes structured local audit events.
8. `src/pin.rs` stores and verifies the Security PIN verifier.
9. `src/watchdog.rs` evaluates one monitoring tick at a time.
10. `src/locker.rs` calls Windows `LockWorkStation`.

The Python implementation under `yubiwatch\` is retained as a reference/fallback, but the startup script prefers `target\release\yubiwatch.exe`.

## Runtime State

The watchdog keeps only:

- `missing_since`: when the key first disappeared.
- `last_lock_at`: when the current absence last triggered a lock.

No event history, large buffers, or unbounded logs are kept in memory.

The security gate keeps one additional constant-size state machine:

- enabled or paused
- optional legacy proof stage
- proof deadline

Trusted product IDs are kept in a small shared list. The dashboard and watchdog
use the same store, so adding a device takes effect immediately without waiting
for the process to restart.

The Security PIN gate keeps only constant-size in-memory attempt counters. The
PIN verifier is a small per-user file containing version, iteration count, salt,
and hash.

Protected Mode keeps a small module-state map keyed by stable module IDs. The map
contains booleans only; module definitions are static code. Audit logging appends
small JSON Lines records and rotates the current file once it exceeds the
configured size.

## Complexity

The watchdog policy is `O(1)` time and `O(1)` space per tick.

USB detection has the cost of querying Windows for present device hardware IDs. The matching step is:

- `O(d)` for one pinned product ID, where `d` is the number of hardware IDs returned by Windows.
- `O(d * p)` if multiple product IDs are configured, where `p` is the small configured product-ID count.
- `O(d)` if product IDs are blank and all Yubico devices are accepted.

In this laptop configuration, `p = 1` because `.env` pins `YUBIWATCH_PRODUCT_IDS=0x0402`.

Space use during detection is `O(d)` for the short list of hardware ID strings returned by SetupAPI. Long-running watchdog state remains `O(1)`.

Dashboard state, PIN verification state, and protection-control state are also
`O(1)`. Each HTTP request is capped to a small fixed read buffer. PIN
verification has fixed work for the configured PBKDF2 iteration count, so it
does not grow with project data size.

Protected Mode status is `O(m)` where `m` is the fixed number of registered
modules. With the current static module list, this is effectively constant for
the running product.

Adding a device is `O(p + d)`: `p` trusted product IDs are deduplicated and `d`
present Yubico hardware IDs are scanned to ensure the candidate and original key
are both inserted.

## Operational Tradeoff

The current Rust build is polling-based because it is simple, testable, and reliable through Task Scheduler. Polling every 2 seconds while the key is present is already light for a laptop.

The theoretical lowest-idle design is event-driven Windows device notification. That would remove routine polling and wake only when USB devices change. It is a good future hardening step, but it adds a hidden window/message loop or Windows service plumbing.

## Command Flow

Native protection starts off unless `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`.
The dashboard can arm or disarm enforcement only when the configured key is
currently inserted and the Security PIN verifies. One-session protection is in
memory only; **Always On** persists the startup policy to `.env`.

The Security PIN is set once on first use while the configured key is inserted.
Forgotten-PIN recovery requires the key, an exact confirmation phrase, and a
successful Windows lock request before the verifier is cleared.

## Why Not Python As Primary

Python is readable and useful as a fallback, but it carries interpreter startup, virtual environment, PyUSB/libusb dependency, and larger idle memory overhead. Rust is the better primary language for this always-on laptop protection app.
