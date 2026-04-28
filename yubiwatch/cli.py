"""Command-line interface for the Python fallback watchdog."""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path

from .config import DEFAULT_ENV_FILE, load_config
from .detector import UsbDetectionError, YubiKeyDetector
from .locker import WorkstationLocker
from .logging_setup import configure_logging
from .watchdog import YubiWatchdog


def build_parser() -> argparse.ArgumentParser:
    """Create the Python fallback argument parser.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="yubikey_watchdog.py",
        description="Lock Windows when the configured YubiKey is absent.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_FILE,
        help="Path to .env settings file.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check for a matching YubiKey once and exit without locking.",
    )
    parser.add_argument(
        "--foreground",
        action="store_true",
        help="Print status to the terminal while running.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the watchdog but skip the Windows lock call.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the Python fallback CLI.

    Args:
        argv: Optional argument list. Defaults to `sys.argv`.

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    config = load_config(args.env_file)
    if args.dry_run:
        config = replace(config, lock_enabled=False)

    logger = configure_logging(config, foreground=args.foreground)
    detector = YubiKeyDetector(config)

    if args.check:
        return _check_once(detector)

    locker = WorkstationLocker(enabled=config.lock_enabled)
    watchdog = YubiWatchdog(config, detector, locker, logger)
    try:
        watchdog.run_forever()
    except KeyboardInterrupt:
        logger.info("YubiWatch stopped by user.")
        return 130

    return 0


def _check_once(detector: YubiKeyDetector) -> int:
    """Check for a matching YubiKey once.

    Args:
        detector: Configured USB detector.

    Returns:
        Process exit code.
    """
    try:
        devices = detector.connected_devices()
    except UsbDetectionError as exc:
        print(f"USB detection failed: {exc}")
        return 2

    if not devices:
        print("No matching YubiKey detected.")
        return 1

    print("Matching YubiKey detected:")
    for device in devices:
        print(f"  {device.label}")
    return 0
