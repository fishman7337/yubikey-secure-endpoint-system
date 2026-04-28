"""Logging setup for the Python fallback watchdog."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from .config import AppConfig


def configure_logging(config: AppConfig, foreground: bool = False) -> logging.Logger:
    """Configure the fallback logger.

    Args:
        config: Parsed watchdog configuration.
        foreground: Whether to force console logging for this run.

    Returns:
        Configured logger.
    """
    logger = logging.getLogger("yubiwatch")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, config.log_level, logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if foreground or config.console_log:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    if config.log_file is not None:
        config.log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            config.log_file,
            maxBytes=config.max_log_bytes,
            backupCount=config.log_backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if not logger.handlers:
        logger.addHandler(logging.NullHandler())

    return logger
