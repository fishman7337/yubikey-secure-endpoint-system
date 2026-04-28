"""Policy loop for the Python fallback watchdog."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from .config import AppConfig
from .detector import UsbDetectionError, YubiKeyDetector
from .locker import WorkstationLocker


@dataclass(slots=True)
class WatchdogState:
    """Mutable timing state for the fallback watchdog.

    Attributes:
        missing_since: Monotonic timestamp when the key first disappeared.
        last_lock_at: Monotonic timestamp of the latest lock request.
    """

    missing_since: float | None = None
    last_lock_at: float | None = None


class YubiWatchdog:
    """Monitor YubiKey presence and lock Windows when absent."""

    def __init__(
        self,
        config: AppConfig,
        detector: YubiKeyDetector,
        locker: WorkstationLocker,
        logger: logging.Logger,
    ):
        """Initialize the watchdog.

        Args:
            config: Parsed watchdog configuration.
            detector: Configured USB detector.
            locker: Workstation lock wrapper.
            logger: Logger for status and errors.
        """
        self.config = config
        self.detector = detector
        self.locker = locker
        self.logger = logger
        self.state = WatchdogState()

    def run_forever(self) -> None:
        """Run the watchdog loop until interrupted."""
        self.logger.info("YubiWatch started.")
        if self.config.startup_grace_seconds:
            self.logger.info(
                "Waiting %.1f seconds before enforcing lock policy.",
                self.config.startup_grace_seconds,
            )
            time.sleep(self.config.startup_grace_seconds)

        while True:
            time.sleep(self.tick(time.monotonic()))

    def tick(self, now: float) -> float:
        """Evaluate one watchdog tick.

        Args:
            now: Current monotonic timestamp.

        Returns:
            Number of seconds to sleep before the next tick.
        """
        present = self._is_yubikey_present()

        if present:
            if self.state.missing_since is not None or self.state.last_lock_at is not None:
                self.logger.info("YubiKey detected. Monitoring resumed.")
            self.state = WatchdogState()
            return self.config.present_poll_seconds

        if self.state.missing_since is None:
            self.state.missing_since = now
            self.logger.warning("YubiKey not detected. Starting grace timer.")

        missing_for = now - self.state.missing_since
        if (
            missing_for >= self.config.missing_grace_seconds
            and (
                self.state.last_lock_at is None
                or now - self.state.last_lock_at >= self.config.relock_seconds
            )
        ):
            self._lock_workstation()
            self.state.last_lock_at = now

        if self.state.last_lock_at is not None:
            return self.config.post_lock_poll_seconds
        return self.config.missing_poll_seconds

    def _is_yubikey_present(self) -> bool:
        try:
            return self.detector.is_connected()
        except UsbDetectionError as exc:
            message = str(exc)
            self.logger.error("USB detection failed: %s", message)
            return not self.config.fail_safe_lock

    def _lock_workstation(self) -> None:
        if not self.config.lock_enabled:
            self.logger.warning("Lock skipped because YUBIWATCH_LOCK_ENABLED=false.")
            return

        self.logger.warning("YubiKey absent. Locking workstation.")
        try:
            self.locker.lock()
        except Exception as exc:
            self.logger.error("Failed to lock workstation: %s", exc)
            raise
