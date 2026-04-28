from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from yubiwatch.config import load_config


class ConfigTests(unittest.TestCase):
    def test_loads_original_product_id_from_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "\n".join(
                    [
                        "YUBIWATCH_VENDOR_ID=0x1050",
                        "YUBIWATCH_PRODUCT_IDS=0x0402",
                        "YUBIWATCH_LOCK_ENABLED=true",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                config = load_config(env_file)

        self.assertEqual(config.vendor_id, 0x1050)
        self.assertEqual(config.product_ids, (0x0402,))
        self.assertTrue(config.lock_enabled)

    def test_product_ids_are_deduplicated_and_invalid_values_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "YUBIWATCH_PRODUCT_IDS=0x0402, 0x0402, 1027, not-a-number",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                config = load_config(env_file)

        self.assertEqual(config.product_ids, (0x0402, 1027))

    def test_environment_values_override_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("YUBIWATCH_PRODUCT_IDS=0x0402", encoding="utf-8")

            with patch.dict(os.environ, {"YUBIWATCH_PRODUCT_IDS": "0x0407"}, clear=True):
                config = load_config(env_file)

        self.assertEqual(config.product_ids, (0x0407,))


if __name__ == "__main__":
    unittest.main()
