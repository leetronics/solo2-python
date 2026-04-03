"""High-level admin operations for Solo 2 devices."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from fido2.ctap import CtapError

from .device import Solo2Device
from .errors import Solo2CommandError, Solo2TransportError


class AdminCommand(IntEnum):
    """Solo 2 admin app CTAPHID commands."""

    VERSION = 0x61
    UUID = 0x62
    BOOT_TO_BOOTLOADER = 0x51
    REBOOT = 0x53
    LOCKED = 0x63


class RebootMode(IntEnum):
    """Reboot mode options."""

    REGULAR = 0x00
    BOOTLOADER = 0x01


@dataclass
class DeviceDiagnostics:
    """Device diagnostic information."""

    firmware_version: str = ""
    uuid: str = ""
    is_locked: bool = False
    ctap2_options: dict = field(default_factory=dict)


class AdminSession:
    """Synchronous admin session backed by a Solo 2 device."""

    def __init__(self, device: Solo2Device):
        self._device = device

    def version(self) -> str:
        return self._device.firmware_version or "Unknown"

    def get_uuid(self) -> str:
        if self._device.device_uuid:
            return self._device.device_uuid
        response = self._device.admin().call(AdminCommand.UUID)
        if len(response) < 16:
            raise Solo2CommandError("No valid UUID response from device")
        uuid_hex = response[:16].hex()
        return (
            f"{uuid_hex[:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-"
            f"{uuid_hex[16:20]}-{uuid_hex[20:32]}"
        )

    def get_diagnostics(self) -> DeviceDiagnostics:
        diagnostics = DeviceDiagnostics()
        caps = self._device.capabilities
        if caps:
            diagnostics.firmware_version = caps.firmware_version or ""
            diagnostics.ctap2_options = {
                "clientPin": caps.ctap2_pin,
                "credMgmt": caps.ctap2_cred_mgmt,
                "uv": caps.ctap2_uv,
                "rk": caps.ctap2_rk,
                "up": caps.ctap2_up,
            }
        else:
            diagnostics.firmware_version = self._device.firmware_version or ""

        if caps is None or caps.has_uuid:
            try:
                diagnostics.uuid = self.get_uuid()
            except Exception:
                diagnostics.uuid = ""

        if caps is None or caps.has_locked:
            try:
                response = self._device.admin().call(AdminCommand.LOCKED)
                if response:
                    diagnostics.is_locked = response[0] != 0
            except Exception:
                diagnostics.is_locked = False
        return diagnostics

    def wink(self) -> None:
        try:
            self._device.admin().wink()
        except Exception as exc:
            raise Solo2TransportError(str(exc)) from exc

    def reboot(self, mode: RebootMode = RebootMode.REGULAR) -> None:
        caps = self._device.capabilities
        if mode == RebootMode.BOOTLOADER:
            if caps is not None and not caps.has_boot_to_bootloader:
                raise Solo2CommandError("'Boot to bootloader' not supported by this firmware")
            command = AdminCommand.BOOT_TO_BOOTLOADER
        else:
            if caps is not None and not caps.has_reboot:
                raise Solo2CommandError("'Reboot' not supported by this firmware")
            command = AdminCommand.REBOOT

        try:
            self._device.admin().call(command)
        except Exception as exc:
            raise Solo2TransportError(str(exc)) from exc

    def factory_reset(self) -> None:
        ctap2 = self._device.open_ctap2()
        if ctap2 is None:
            raise Solo2TransportError("Device not connected")
        try:
            ctap2.reset()
        except CtapError as exc:
            raise Solo2CommandError(str(exc)) from exc
        except Exception as exc:
            raise Solo2TransportError(str(exc)) from exc
