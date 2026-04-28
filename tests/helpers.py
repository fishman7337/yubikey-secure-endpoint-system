from __future__ import annotations

from pathlib import Path

from yubiwatch.config import AppConfig


def make_config(**overrides) -> AppConfig:
    values = {
        "vendor_id": 0x1050,
        "product_ids": (0x0402,),
        "present_poll_seconds": 2.0,
        "missing_poll_seconds": 0.5,
        "missing_grace_seconds": 2.0,
        "post_lock_poll_seconds": 2.0,
        "relock_seconds": 5.0,
        "startup_grace_seconds": 0.0,
        "fail_safe_lock": True,
        "lock_enabled": True,
        "libusb_dll": None,
        "log_level": "INFO",
        "log_file": None,
        "console_log": False,
        "max_log_bytes": 262144,
        "log_backup_count": 2,
    }
    values.update(overrides)
    if isinstance(values["libusb_dll"], str):
        values["libusb_dll"] = Path(values["libusb_dll"])
    return AppConfig(**values)
