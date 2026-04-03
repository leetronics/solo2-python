"""High-level Solo 2 app clients built on top of the core device handle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fido2.ctap2 import Ctap2


@dataclass
class Solo2AdminClient:
    """Thin admin client for vendor-command based operations."""

    device: "Solo2Device"

    def version(self) -> Optional[str]:
        return self.device.firmware_version

    def uuid(self) -> Optional[str]:
        return self.device.device_uuid

    def call(self, command: int, data: bytes = b"") -> bytes:
        if self.device.prefers_ccid():
            connection = self.device.open_pcsc_connection(admin=True)
            try:
                return connection.call_admin(command, data)
            finally:
                connection.close()
        return self.device._call_hid_command(command, data)

    def wink(self) -> None:
        if self.device.prefers_ccid():
            raise RuntimeError("Wink is only available over HID")
        hid_device = self.device.open_hid_device()
        if hid_device is None:
            raise RuntimeError("Device not available")
        hid_device.wink()


@dataclass
class Solo2FidoClient:
    """Thin CTAP2 client wrapper."""

    device: "Solo2Device"

    def open(self) -> Optional[Ctap2]:
        return self.device.open_ctap2()

    def get_info(self):
        ctap2 = self.open()
        if ctap2 is None:
            raise RuntimeError("Device not available")
        return ctap2.get_info()


@dataclass
class Solo2SecretsClient:
    """Thin bridge for Secrets/OATH APDU transport."""

    device: "Solo2Device"

    def send_apdu(self, apdu: bytes) -> bytes:
        if self.device.prefers_ccid():
            connection = self.device.open_pcsc_connection(secrets=True)
            try:
                return connection.call_secrets(apdu)
            finally:
                connection.close()
        return self.device._call_hid_command(0x70, apdu)
