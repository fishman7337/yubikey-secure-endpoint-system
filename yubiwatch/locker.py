"""Workstation locking for the Python fallback watchdog."""

from __future__ import annotations

import ctypes
import os


class WorkstationLocker:
    """Windows workstation locker wrapper."""

    def __init__(self, enabled: bool = True):
        """Initialize the locker.

        Args:
            enabled: When false, `lock` returns without locking.
        """
        self.enabled = enabled

    def lock(self) -> bool:
        """Lock the current Windows workstation.

        Raises:
            RuntimeError: If the platform is unsupported or Windows rejects
                the lock request.

        Returns:
            True when the lock call was issued, false in disabled mode.
        """
        if not self.enabled:
            return False

        if os.name != "nt":
            raise RuntimeError("LockWorkStation is only available on Windows.")

        result = ctypes.windll.user32.LockWorkStation()  # type: ignore[attr-defined]
        if not result:
            raise RuntimeError("Windows rejected the LockWorkStation request.")
        return True
