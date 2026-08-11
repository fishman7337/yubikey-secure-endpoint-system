"""USB detection for the Python fallback watchdog."""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path

from .config import AppConfig

try:
    import usb.core
except ImportError as exc:  # pragma: no cover - depends on local environment.
    usb = None  # type: ignore[assignment]
    USB_IMPORT_ERROR: ImportError | None = exc
else:
    USB_IMPORT_ERROR = None


class UsbDetectionError(RuntimeError):
    """Raised when USB detection cannot be performed."""


@dataclass(frozen=True)
class UsbDeviceInfo:
    """Normalized USB device information.

    Attributes:
        vendor_id: USB vendor ID.
        product_id: USB product ID.
        bus: Optional USB bus number reported by PyUSB.
        address: Optional USB address reported by PyUSB.
    """

    vendor_id: int
    product_id: int
    bus: int | None
    address: int | None

    @property
    def label(self) -> str:
        """Return a compact display label for CLI output."""
        location = ""
        if self.bus is not None and self.address is not None:
            location = f" bus={self.bus} address={self.address}"
        return f"vid=0x{self.vendor_id:04x} pid=0x{self.product_id:04x}{location}"


class YubiKeyDetector:
    """PyUSB-backed detector for configured YubiKey devices."""

    def __init__(self, config: AppConfig):
        """Initialize the detector.

        Args:
            config: Parsed watchdog configuration.
        """
        self.config = config
        self._dll_directory_handle = self._load_libusb(config.libusb_dll)

    def connected_devices(self) -> list[UsbDeviceInfo]:
        """Return matching currently connected devices.

        Raises:
            UsbDetectionError: If PyUSB or the USB backend cannot enumerate.

        Returns:
            List of matching devices.
        """
        if USB_IMPORT_ERROR is not None:
            raise UsbDetectionError(
                "PyUSB is not installed. Install dependencies with: "
                "pip install -r requirements.txt"
            ) from USB_IMPORT_ERROR

        try:
            devices = self._find_devices()
        except Exception as exc:  # PyUSB raises backend-specific exceptions.
            raise UsbDetectionError(str(exc)) from exc

        return [
            UsbDeviceInfo(
                vendor_id=int(device.idVendor),
                product_id=int(device.idProduct),
                bus=getattr(device, "bus", None),
                address=getattr(device, "address", None),
            )
            for device in devices
        ]

    def is_connected(self) -> bool:
        """Return whether at least one matching device is connected."""
        return bool(self.connected_devices())

    def _find_devices(self):
        if self.config.product_ids:
            if len(self.config.product_ids) == 1:
                device = usb.core.find(  # type: ignore[union-attr]
                    idVendor=self.config.vendor_id,
                    idProduct=self.config.product_ids[0],
                )
                return [] if device is None else [device]

            product_ids = set(self.config.product_ids)
            return [
                device
                for device in usb.core.find(  # type: ignore[union-attr]
                    find_all=True,
                    idVendor=self.config.vendor_id,
                )
                if int(device.idProduct) in product_ids
            ]

        return list(
            usb.core.find(  # type: ignore[union-attr]
                find_all=True,
                idVendor=self.config.vendor_id,
            )
        )

    @staticmethod
    def _load_libusb(dll_path: Path | None):
        """Load a local libusb DLL when the Python fallback needs it.

        Args:
            dll_path: Optional path to a libusb DLL.

        Returns:
            DLL directory handle on modern Windows, otherwise `None`.
        """
        if os.name != "nt" or dll_path is None:
            return None

        dll_path = dll_path.expanduser()
        if not dll_path.exists():
            return None

        handle = None
        dll_dir = str(dll_path.parent)
        if hasattr(os, "add_dll_directory"):
            handle = os.add_dll_directory(dll_dir)

        try:
            ctypes.CDLL(str(dll_path))
        except OSError:
            return handle

        return handle
