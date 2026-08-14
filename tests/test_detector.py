from __future__ import annotations

import unittest
from contextlib import contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.helpers import make_config
from yubiwatch.detector import UsbDetectionError, YubiKeyDetector


@dataclass
class FakeUsbDevice:
    idVendor: int
    idProduct: int
    bus: int = 1
    address: int = 1


@contextmanager
def fake_usb_find(return_value=None, side_effect=None):
    find = Mock(return_value=return_value, side_effect=side_effect)
    fake_usb = SimpleNamespace(core=SimpleNamespace(find=find))

    with patch("yubiwatch.detector.usb", fake_usb), patch(
        "yubiwatch.detector.USB_IMPORT_ERROR",
        None,
    ):
        yield find


class DetectorTests(unittest.TestCase):
    def test_single_product_id_uses_targeted_lookup(self) -> None:
        device = FakeUsbDevice(idVendor=0x1050, idProduct=0x0402)
        config = make_config(product_ids=(0x0402,))

        with fake_usb_find(return_value=device) as find:
            devices = YubiKeyDetector(config).connected_devices()

        find.assert_called_once_with(idVendor=0x1050, idProduct=0x0402)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].product_id, 0x0402)

    def test_multiple_product_ids_enumerate_once_and_filter_in_memory(self) -> None:
        devices = [
            FakeUsbDevice(idVendor=0x1050, idProduct=0x0402),
            FakeUsbDevice(idVendor=0x1050, idProduct=0x0407),
            FakeUsbDevice(idVendor=0x1050, idProduct=0x9999),
        ]
        config = make_config(product_ids=(0x0402, 0x0407))

        with fake_usb_find(return_value=devices) as find:
            connected = YubiKeyDetector(config).connected_devices()

        find.assert_called_once_with(find_all=True, idVendor=0x1050)
        self.assertEqual([device.product_id for device in connected], [0x0402, 0x0407])

    def test_blank_product_ids_accept_all_yubico_devices(self) -> None:
        devices = [
            FakeUsbDevice(idVendor=0x1050, idProduct=0x0402),
            FakeUsbDevice(idVendor=0x1050, idProduct=0x0407),
        ]
        config = make_config(product_ids=())

        with fake_usb_find(return_value=devices) as find:
            connected = YubiKeyDetector(config).connected_devices()

        find.assert_called_once_with(find_all=True, idVendor=0x1050)
        self.assertEqual(len(connected), 2)

    def test_missing_pyusb_raises_detection_error_with_install_hint(self) -> None:
        import_error = ImportError("No module named 'usb'")
        config = make_config()

        with patch("yubiwatch.detector.USB_IMPORT_ERROR", import_error):
            with self.assertRaises(UsbDetectionError) as raised:
                YubiKeyDetector(config).connected_devices()

        self.assertIn("PyUSB is not installed", str(raised.exception))
        self.assertIs(raised.exception.__cause__, import_error)

    def test_backend_errors_are_wrapped_as_detection_errors(self) -> None:
        backend_error = RuntimeError("No backend available")
        config = make_config()

        with fake_usb_find(side_effect=backend_error):
            with self.assertRaises(UsbDetectionError) as raised:
                YubiKeyDetector(config).connected_devices()

        self.assertEqual(str(raised.exception), "No backend available")
        self.assertIs(raised.exception.__cause__, backend_error)


if __name__ == "__main__":
    unittest.main()
