"""Provide the compatibility entry point for the YubiKey watchdog CLI."""

from yubiwatch.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
