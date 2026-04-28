# Rust Native Implementation

## Files

- `Cargo.toml`: native build settings.
- `src/main.rs`: CLI entry point.
- `src/config.rs`: `.env` parsing and typed settings.
- `src/detector.rs`: Windows SetupAPI device detection.
- `src/security.rs`: runtime protection state.
- `src/dashboard.rs`: local browser dashboard.
- `src/watchdog.rs`: lock policy and timing state.
- `src/locker.rs`: Windows workstation lock call.

## Windows APIs

The Rust build uses direct FFI and no third-party crates:

- `SetupDiGetClassDevsW`
- `SetupDiEnumDeviceInfo`
- `SetupDiGetDeviceRegistryPropertyW`
- `SetupDiDestroyDeviceInfoList`
- `LockWorkStation`
- `BCryptGenRandom`

That keeps the binary small and avoids shipping libusb for the native path.

## Release Profile

`Cargo.toml` enables:

- thin LTO
- one codegen unit
- symbol stripping
- aborting panics

Those settings favor a smaller optimized binary for an always-on helper.

## Detection Behavior

The detector normalizes Windows hardware IDs and checks:

```text
VID_1050
PID_0402
```

If `YUBIWATCH_PRODUCT_IDS` is blank, it accepts any Yubico device with vendor ID `0x1050`. Keeping `0x0402` pinned is stricter for this laptop.

## Documentation Style

Rust public modules and public items use rustdoc comments:

```rust
//! Module-level documentation.
/// Public item documentation.
```

Run these before release builds:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## PATH Note

This machine has Rust installed, but this shell may not inherit Cargo's PATH. Use:

```powershell
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
```

Then `cargo`, `rustc`, and `rustfmt` should resolve normally.
