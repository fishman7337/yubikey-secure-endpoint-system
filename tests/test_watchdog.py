from __future__ import annotations

import logging
import unittest

from tests.helpers import make_config
from yubiwatch.detector import UsbDetectionError
from yubiwatch.watchdog import YubiWatchdog


class FakeDetector:
    def __init__(self, states):
        self.states = list(states)
        self.last_state = True

    def is_connected(self) -> bool:
        if self.states:
            self.last_state = self.states.pop(0)
        state = self.last_state
        if isinstance(state, Exception):
            raise state
        return bool(state)


class FakeLocker:
    def __init__(self) -> None:
        self.lock_count = 0

    def lock(self) -> bool:
        self.lock_count += 1
        return True


def make_logger() -> logging.Logger:
    logger = logging.getLogger("tests.yubiwatch")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    return logger


class WatchdogTests(unittest.TestCase):
    def test_present_key_uses_slow_polling_and_does_not_lock(self) -> None:
        config = make_config(present_poll_seconds=3.0)
        locker = FakeLocker()
        watchdog = YubiWatchdog(config, FakeDetector([True]), locker, make_logger())

        sleep_for = watchdog.tick(now=10.0)

        self.assertEqual(sleep_for, 3.0)
        self.assertEqual(locker.lock_count, 0)

    def test_missing_key_waits_for_grace_period_before_locking(self) -> None:
        config = make_config(missing_grace_seconds=2.0)
        locker = FakeLocker()
        watchdog = YubiWatchdog(
            config, FakeDetector([False, False]), locker, make_logger()
        )

        self.assertEqual(watchdog.tick(now=10.0), config.missing_poll_seconds)
        self.assertEqual(locker.lock_count, 0)

        self.assertEqual(watchdog.tick(now=12.0), config.post_lock_poll_seconds)
        self.assertEqual(locker.lock_count, 1)

    def test_absent_key_relocks_after_cooldown(self) -> None:
        config = make_config(missing_grace_seconds=0.0, relock_seconds=5.0)
        locker = FakeLocker()
        watchdog = YubiWatchdog(
            config, FakeDetector([False, False, False]), locker, make_logger()
        )

        watchdog.tick(now=10.0)
        watchdog.tick(now=14.0)
        watchdog.tick(now=15.0)

        self.assertEqual(locker.lock_count, 2)

    def test_reinserted_key_resets_absence_state(self) -> None:
        config = make_config(missing_grace_seconds=0.0)
        locker = FakeLocker()
        watchdog = YubiWatchdog(
            config, FakeDetector([False, True]), locker, make_logger()
        )

        watchdog.tick(now=10.0)
        sleep_for = watchdog.tick(now=11.0)

        self.assertEqual(sleep_for, config.present_poll_seconds)
        self.assertEqual(locker.lock_count, 1)
        self.assertIsNone(watchdog.state.missing_since)
        self.assertIsNone(watchdog.state.last_lock_at)

    def test_fail_safe_detection_error_is_treated_as_missing_key(self) -> None:
        config = make_config(missing_grace_seconds=0.0, fail_safe_lock=True)
        locker = FakeLocker()
        watchdog = YubiWatchdog(
            config,
            FakeDetector([UsbDetectionError("backend unavailable")]),
            locker,
            make_logger(),
        )

        watchdog.tick(now=10.0)

        self.assertEqual(locker.lock_count, 1)


if __name__ == "__main__":
    unittest.main()
