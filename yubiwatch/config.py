"""Configuration helpers for the Python fallback.

The native Rust executable is the primary runtime. This module remains as a
PEP 8/PEP 257-compliant fallback and testable reference implementation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_LOCAL_LIBUSB = PROJECT_ROOT / "libusb-1.0.dll"


def load_env_file(path: Path = DEFAULT_ENV_FILE) -> None:
    """Load settings from a dotenv-style file.

    Existing process environment variables win over file values.

    Args:
        path: Dotenv file path to read.
    """
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue

        os.environ[key] = _clean_env_value(value)


def _clean_env_value(value: str) -> str:
    """Strip quotes and inline comments from one dotenv value.

    Args:
        value: Raw value from the right side of a `KEY=VALUE` line.

    Returns:
        Cleaned value with comments outside quotes removed.
    """
    value = value.strip()
    quote: str | None = None
    for index, char in enumerate(value):
        if char in {"'", '"'}:
            quote = None if quote == char else char
            continue
        if char == "#" and quote is None and (index == 0 or value[index - 1].isspace()):
            value = value[:index].strip()
            break

    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_bool(name: str, default: bool) -> bool:
    value = _get_str(name)
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "y", "on"}


def _get_float(name: str, default: float, minimum: float = 0.0) -> float:
    value = _get_str(name)
    if not value:
        return default
    try:
        return max(float(value), minimum)
    except ValueError:
        return default


def _get_int(name: str, default: int, minimum: int = 0) -> int:
    value = _get_str(name)
    if not value:
        return default
    try:
        return max(int(value), minimum)
    except ValueError:
        return default


def _parse_int(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value)


def _get_hex_int(name: str, default: int) -> int:
    value = _get_str(name)
    if not value:
        return default
    try:
        return _parse_int(value)
    except ValueError:
        return default


def _get_hex_tuple(name: str) -> tuple[int, ...]:
    value = _get_str(name)
    if not value:
        return ()

    parsed: list[int] = []
    for item in value.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            parsed.append(_parse_int(item))
        except ValueError:
            continue
    return tuple(dict.fromkeys(parsed))


def _get_optional_path(name: str, default: Path | None = None) -> Path | None:
    value = _get_str(name)
    if value:
        return Path(value).expanduser()
    return default


@dataclass(frozen=True)
class AppConfig:
    """Typed settings for the Python fallback watchdog.

    Attributes:
        vendor_id: USB vendor ID to match.
        product_ids: USB product IDs to accept. Empty accepts any product.
        present_poll_seconds: Poll interval while the key is present.
        missing_poll_seconds: Poll interval while the key is newly missing.
        missing_grace_seconds: Grace period before locking.
        post_lock_poll_seconds: Poll interval after a lock.
        relock_seconds: Minimum seconds between repeated lock requests.
        startup_grace_seconds: Startup grace period before enforcement.
        fail_safe_lock: Treat detector errors as key absence.
        lock_enabled: Disable the actual lock call when false.
        libusb_dll: Optional libusb DLL path.
        log_level: Python logging level name.
        log_file: Optional rotating log file path.
        console_log: Whether to emit logs to stderr.
        max_log_bytes: Rotating log size limit.
        log_backup_count: Number of rotated log backups.
    """

    vendor_id: int
    product_ids: tuple[int, ...]
    present_poll_seconds: float
    missing_poll_seconds: float
    missing_grace_seconds: float
    post_lock_poll_seconds: float
    relock_seconds: float
    startup_grace_seconds: float
    fail_safe_lock: bool
    lock_enabled: bool
    libusb_dll: Path | None
    log_level: str
    log_file: Path | None
    console_log: bool
    max_log_bytes: int
    log_backup_count: int


def load_config(env_file: Path = DEFAULT_ENV_FILE) -> AppConfig:
    """Load a complete Python fallback configuration.

    Args:
        env_file: Dotenv file path to read before environment variables.

    Returns:
        Parsed application configuration.
    """
    load_env_file(env_file)

    libusb_default = DEFAULT_LOCAL_LIBUSB if DEFAULT_LOCAL_LIBUSB.exists() else None

    return AppConfig(
        vendor_id=_get_hex_int("YUBIWATCH_VENDOR_ID", 0x1050),
        product_ids=_get_hex_tuple("YUBIWATCH_PRODUCT_IDS"),
        present_poll_seconds=_get_float("YUBIWATCH_PRESENT_POLL_SECONDS", 2.0, 0.2),
        missing_poll_seconds=_get_float("YUBIWATCH_MISSING_POLL_SECONDS", 0.5, 0.2),
        missing_grace_seconds=_get_float("YUBIWATCH_MISSING_GRACE_SECONDS", 2.0, 0.0),
        post_lock_poll_seconds=_get_float("YUBIWATCH_POST_LOCK_POLL_SECONDS", 2.0, 0.5),
        relock_seconds=_get_float("YUBIWATCH_RELOCK_SECONDS", 5.0, 1.0),
        startup_grace_seconds=_get_float("YUBIWATCH_STARTUP_GRACE_SECONDS", 5.0, 0.0),
        fail_safe_lock=_get_bool("YUBIWATCH_FAIL_SAFE_LOCK", True),
        lock_enabled=_get_bool(
            "YUBIWATCH_LOCK_ENABLED",
            _get_bool("YUBIWATCH_ALWAYS_KEEP_ENABLED", False),
        ),
        libusb_dll=_get_optional_path("YUBIWATCH_LIBUSB_DLL", libusb_default),
        log_level=_get_str("YUBIWATCH_LOG_LEVEL", "INFO").upper(),
        log_file=_get_optional_path("YUBIWATCH_LOG_FILE", None),
        console_log=_get_bool("YUBIWATCH_CONSOLE_LOG", False),
        max_log_bytes=_get_int("YUBIWATCH_MAX_LOG_BYTES", 262144, 4096),
        log_backup_count=_get_int("YUBIWATCH_LOG_BACKUP_COUNT", 2, 0),
    )
