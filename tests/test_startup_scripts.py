from __future__ import annotations

import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def read_script(name: str) -> str:
    return (PROJECT_ROOT / name).read_text(encoding="utf-8")


class StartupScriptStaticTests(unittest.TestCase):
    def test_watchdog_launcher_does_not_handle_startup_dashboard_browser(self) -> None:
        script = read_script("watchdog_launcher.vbs")
        normalized = script.lower()

        forbidden_snippets = (
            "YUBIWATCH_DASHBOARD_PORT",
            "YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP",
            "YUBIWATCH_STARTUP_BROWSER_HANDLED",
            "WScript.Sleep",
            "http://127.0.0.1",
        )
        for snippet in forbidden_snippets:
            with self.subTest(snippet=snippet):
                self.assertNotIn(snippet.lower(), normalized)

        self.assertIsNone(
            re.search(r'WshShell\.Run\s+"https?://', script, re.IGNORECASE),
        )

    def test_install_task_does_not_register_unlock_or_session_change_triggers(self) -> None:
        script = read_script("install_task.ps1")

        forbidden_snippets = ("SessionUnlock", "SessionStateChange")
        for snippet in forbidden_snippets:
            with self.subTest(snippet=snippet):
                self.assertNotIn(snippet, script)


if __name__ == "__main__":
    unittest.main()
