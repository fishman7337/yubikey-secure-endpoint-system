from __future__ import annotations

import unittest
from dataclasses import dataclass
from unittest.mock import patch

from tests.helpers import make_config
from yubiwatch.detector import YubiKeyDetector


@dataclass
class FakeUsbDevice:
    idVendor: int
    idProduct: int
    bus: int = 1
    address: int = 1


class DetectorTests(unittest.TestCase):
    def test_single_product_id_uses_targeted_lookup(self) -> None:
        device = FakeUsbDevice(idVendor=0x1050, idProduct=0x0402)
        config = make_config(product_ids=(0x0402,))

        with patch("yubiwatch.detector.usb.core.find", return_value=device) as find:
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

        with patch("yubiwatch.detector.usb.core.find", return_value=devices) as find:
            connected = YubiKeyDetector(config).connected_devices()

        find.assert_called_once_with(find_all=True, idVendor=0x1050)
        self.assertEqual([device.product_id for device in connected], [0x0402, 0x0407])

    def test_blank_product_ids_accept_all_yubico_devices(self) -> None:
        devices = [
            FakeUsbDevice(idVendor=0x1050, idProduct=0x0402),
            FakeUsbDevice(idVendor=0x1050, idProduct=0x0407),
        ]
        config = make_config(product_ids=())

        with patch("yubiwatch.detector.usb.core.find", return_value=devices) as find:
            connected = YubiKeyDetector(config).connected_devices()

        find.assert_called_once_with(find_all=True, idVendor=0x1050)
        self.assertEqual(len(connected), 2)


if __name__ == "__main__":
    unittest.main()
