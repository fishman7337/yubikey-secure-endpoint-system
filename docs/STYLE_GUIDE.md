# Style Guide

## Rust

- Run `cargo fmt --all -- --check`.
- Run `cargo clippy --all-targets -- -D warnings`.
- Use rustdoc for public modules and public items:

  ```rust
  //! Module documentation.
  /// Public item documentation.
  ```

- Keep `unsafe` blocks small and close to Windows FFI calls.
- Keep dashboard endpoints local-only.
- Prefer explicit state machines for security behavior.

## Python

- Follow PEP 8 and PEP 257.
- Use Google-style docstrings.
- Keep the Python implementation as a fallback/reference.
- Avoid adding dependencies unless the native Rust path also needs a clear equivalent.

## Documentation

- Be direct about security limits.
- Include recovery steps for lock-related behavior.
- Prefer PowerShell examples because this project targets Windows.
- Keep markdown headings short.

## Dashboard UI

- Keep controls task-oriented.
- Avoid hidden destructive actions.
- Show state before action.
- Disable buttons that cannot currently succeed.
- Keep text readable on light and dark themes.
