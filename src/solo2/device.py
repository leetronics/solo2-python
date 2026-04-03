"""Core Solo 2 device models and connection helpers."""

from __future__ import annotations

import logging
import os
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum
from typing import List, Optional

import usb.core
from fido2.ctap2 import Ctap2

from .hid_backend import list_ctap_hid_devices
from .pcsc import open_pcsc_connection

_log = logging.getLogger("solo2device")


def format_firmware_version(semver: Optional[str]) -> str:
    """Convert semver '2.964.0' to calver '2:20220822.0' for display."""
    if not semver:
        return "Unknown"
    try:
        major, minor, patch = (int(x) for x in semver.split("."))
        fw_date = date(2020, 1, 1) + timedelta(days=minor)
        return f"{major}:{fw_date.strftime('%Y%m%d')}.{patch}"
    except Exception:
        return semver


def format_firmware_full(semver: Optional[str]) -> str:
    """Return 'calver (semver)' e.g. '2:20220822.0 (2.964.0)'."""
    if not semver:
        return "Unknown"
    try:
        major, minor, patch = (int(x) for x in semver.split("."))
        fw_date = date(2020, 1, 1) + timedelta(days=minor)
        calver = f"{major}:{fw_date.strftime('%Y%m%d')}.{patch}"
        return f"{calver} ({semver})"
    except Exception:
        return semver


def firmware_supports_extended_applets(semver: Optional[str]) -> bool:
    """Return True for firmware versions that include Secrets, PIV, and OpenPGP."""
    if not semver:
        return False
    try:
        _major, minor, _patch = (int(x) for x in semver.split("."))
        fw_date = date(2020, 1, 1) + timedelta(days=minor)
        return fw_date >= date(2022, 8, 22)
    except Exception:
        return False


class DeviceMode(Enum):
    REGULAR = "regular"
    BOOTLOADER = "bootloader"


class DeviceStatus(Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


@dataclass(frozen=True)
class Solo2Descriptor:
    """A stable descriptor for a Solo 2 connection target."""

    id: str
    mode: DeviceMode
    path: str
    transport: str
    hid_path: object | None = None
    reader_name: Optional[str] = None
    firmware_version: Optional[str] = None
    uuid: Optional[str] = None


@dataclass
class DeviceInfo:
    path: str
    mode: DeviceMode
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None
    battery_level: Optional[int] = None
    capabilities: Optional[List[str]] = None


@dataclass
class FirmwareCapabilities:
    has_version: bool = False
    has_uuid: bool = False
    has_locked: bool = False
    has_reboot: bool = False
    has_boot_to_bootloader: bool = False
    ctap2_pin: bool = False
    ctap2_cred_mgmt: bool = False
    ctap2_uv: bool = False
    ctap2_rk: bool = False
    ctap2_up: bool = False
    has_piv: bool = False
    has_openpgp: bool = False
    variant: str = ""
    firmware_version: Optional[str] = None


class SoloDevice(ABC):
    """Abstract base class for Solo 2 devices."""

    def __init__(self, descriptor: Solo2Descriptor):
        self._descriptor = descriptor
        self.path = descriptor.id
        self.mode = descriptor.mode
        self.status = DeviceStatus.DISCONNECTED

    @property
    def descriptor(self) -> Solo2Descriptor:
        return self._descriptor

    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass

    @abstractmethod
    def get_info(self) -> DeviceInfo:
        pass

    @abstractmethod
    def is_alive(self) -> bool:
        pass

    def open_hid_device(self):
        return None

    def open_ctap2(self) -> Optional[Ctap2]:
        return None


class Solo2Device(SoloDevice):
    """Concrete Solo 2 device object backed by a stable descriptor."""

    SOLOKEYS_VID = 0x1209
    REGULAR_PID = 0xBEEE
    BOOTLOADER_PID = 0xB000
    SOLOKEYS_AAGUIDS = {
        "8bc54968": "Hacker",
        "2369d4d0": "Secure",
    }

    def __init__(self, descriptor: Solo2Descriptor | str, mode: DeviceMode | None = None):
        if isinstance(descriptor, Solo2Descriptor):
            resolved = descriptor
        else:
            if mode is None:
                raise ValueError("mode is required when constructing Solo2Device from a raw path")
            transport = "bootloader" if mode == DeviceMode.BOOTLOADER else "hid"
            resolved = Solo2Descriptor(
                id=descriptor,
                mode=mode,
                path=descriptor,
                transport=transport,
            )
        super().__init__(resolved)
        self._usb_device: Optional[usb.core.Device] = None
        self._hid_path = resolved.hid_path
        self._variant: Optional[str] = None
        self._firmware_version: Optional[str] = resolved.firmware_version
        self._capabilities: Optional[FirmwareCapabilities] = None
        self._device_uuid: Optional[str] = resolved.uuid
        self._reader_name: Optional[str] = resolved.reader_name

    @classmethod
    def from_descriptor(cls, descriptor: Solo2Descriptor) -> "Solo2Device":
        return cls(descriptor)

    def connect(self) -> bool:
        try:
            if self.mode == DeviceMode.REGULAR:
                if self._descriptor.transport == "ccid":
                    connection = self.open_pcsc_connection(admin=True)
                    version = self._get_firmware_version_from_pcsc(connection)
                    device_uuid = self._get_uuid_from_pcsc(connection)
                    connection.close()

                    stable_id = f"uuid:{device_uuid}" if device_uuid else f"ccid:{self._reader_name or self.path}"
                    self.path = stable_id
                    self._descriptor = Solo2Descriptor(
                        id=stable_id,
                        mode=DeviceMode.REGULAR,
                        path=stable_id,
                        transport="ccid",
                        reader_name=self._reader_name or self.path,
                        firmware_version=version,
                        uuid=device_uuid,
                    )
                    self._device_uuid = device_uuid
                    self._firmware_version = version
                    self._variant = "Hacker"
                    self._capabilities = self._detect_capabilities()
                    self.status = DeviceStatus.CONNECTED
                    return True

                matched_hid = self.open_hid_device()
                if matched_hid is None:
                    self.status = DeviceStatus.ERROR
                    return False

                desc = matched_hid.descriptor
                version = self._get_firmware_version_from_hid(matched_hid)
                device_uuid = self._get_uuid_from_hid(matched_hid)
                variant = "Hacker"
                ctap_info = None
                try:
                    ctap = Ctap2(matched_hid)
                    ctap_info = ctap.info
                    aaguid_prefix = ctap_info.aaguid.hex()[:8] if ctap_info.aaguid else ""
                    variant = self.SOLOKEYS_AAGUIDS.get(aaguid_prefix, "Hacker")
                except Exception as exc:
                    _log.debug("connect() CTAP2 GetInfo failed (non-fatal): %s", exc)

                self._hid_path = getattr(desc, "path", None)
                self._device_uuid = device_uuid
                if device_uuid:
                    stable_id = f"uuid:{device_uuid}"
                elif self._hid_path is not None:
                    stable_id = f"hid:{self._hid_path!r}"
                else:
                    stable_id = self.path
                self.path = stable_id
                self._descriptor = Solo2Descriptor(
                    id=stable_id,
                    mode=DeviceMode.REGULAR,
                    path=stable_id,
                    transport="hid",
                    hid_path=self._hid_path,
                    firmware_version=version,
                    uuid=device_uuid,
                )
                self._variant = variant
                self._firmware_version = version
                self._capabilities = self._detect_capabilities(ctap_info=ctap_info)
                self.status = DeviceStatus.CONNECTED
                return True

            devices = usb.core.find(
                idVendor=self.SOLOKEYS_VID,
                idProduct=self.BOOTLOADER_PID,
                find_all=True,
            )
            for dev in devices:
                candidate_id = f"{dev.bus}-{dev.address}"
                if candidate_id == self.path or candidate_id == self._descriptor.id:
                    self._usb_device = dev
                    self.status = DeviceStatus.CONNECTED
                    return True
            self.status = DeviceStatus.DISCONNECTED
            return False
        except Exception:
            self.status = DeviceStatus.ERROR
            return False

    def disconnect(self) -> None:
        self._usb_device = None
        self._hid_path = None
        self._capabilities = None
        self.status = DeviceStatus.DISCONNECTED

    def get_info(self) -> DeviceInfo:
        if self.mode == DeviceMode.BOOTLOADER:
            return DeviceInfo(path=self.path, mode=self.mode, firmware_version="Bootloader")

        product = f"Solo 2 {self._variant}" if self._variant else "Solo 2"
        capabilities = None
        if self._capabilities:
            capabilities = [
                "clientPin" if self._capabilities.ctap2_pin else None,
                "credMgmt" if self._capabilities.ctap2_cred_mgmt else None,
                "uv" if self._capabilities.ctap2_uv else None,
                "rk" if self._capabilities.ctap2_rk else None,
            ]
            capabilities = [cap for cap in capabilities if cap]

        return DeviceInfo(
            path=self.path,
            mode=self.mode,
            firmware_version=self._firmware_version,
            serial_number=product,
            capabilities=capabilities,
        )

    @property
    def firmware_version(self) -> Optional[str]:
        return self._firmware_version

    @property
    def capabilities(self) -> Optional[FirmwareCapabilities]:
        return self._capabilities

    @property
    def device_uuid(self) -> Optional[str]:
        return self._device_uuid

    @property
    def hid_device_path(self):
        return self._hid_path

    def admin(self):
        from .clients import Solo2AdminClient

        return Solo2AdminClient(self)

    def fido(self):
        from .clients import Solo2FidoClient

        return Solo2FidoClient(self)

    def secrets(self):
        from .clients import Solo2SecretsClient

        return Solo2SecretsClient(self)

    def is_alive(self) -> bool:
        if self.mode == DeviceMode.REGULAR:
            return self.status == DeviceStatus.CONNECTED
        try:
            if self._usb_device:
                _ = self._usb_device.get_active_configuration()
                return True
        except Exception:
            pass
        return False

    def _get_firmware_version_from_hid(self, hid_device) -> Optional[str]:
        try:
            resp = self._call_hid_command(0x61, b"", hid_device=hid_device)
            if len(resp) < 4:
                _log.debug(
                    "_get_firmware_version_from_hid short response path=%r len=%d",
                    getattr(getattr(hid_device, "descriptor", None), "path", None),
                    len(resp),
                )
                return None
            version = struct.unpack(">I", resp[:4])[0]
            major = version >> 22
            minor = (version >> 6) & ((1 << 16) - 1)
            patch = version & ((1 << 6) - 1)
            semver = f"{major}.{minor}.{patch}"
            _log.debug(
                "_get_firmware_version_from_hid success path=%r version=%s",
                getattr(getattr(hid_device, "descriptor", None), "path", None),
                semver,
            )
            return semver
        except Exception as exc:
            _log.debug(
                "_get_firmware_version_from_hid failed path=%r err=%s",
                getattr(getattr(hid_device, "descriptor", None), "path", None),
                exc,
            )
            return None

    def _get_uuid_from_hid(self, hid_device) -> Optional[str]:
        try:
            resp = self._call_hid_command(0x62, b"", hid_device=hid_device)
            if len(resp) < 16:
                _log.debug(
                    "_get_uuid_from_hid short response path=%r len=%d",
                    getattr(getattr(hid_device, "descriptor", None), "path", None),
                    len(resp),
                )
                return None
            uuid_hex = resp[:16].hex()
            uuid_str = (
                f"{uuid_hex[:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-"
                f"{uuid_hex[16:20]}-{uuid_hex[20:32]}"
            )
            _log.debug(
                "_get_uuid_from_hid success path=%r uuid=%s",
                getattr(getattr(hid_device, "descriptor", None), "path", None),
                uuid_str,
            )
            return uuid_str
        except Exception as exc:
            _log.debug(
                "_get_uuid_from_hid failed path=%r err=%s",
                getattr(getattr(hid_device, "descriptor", None), "path", None),
                exc,
            )
            return None

    def _detect_capabilities(self, ctap_info=None) -> FirmwareCapabilities:
        caps = FirmwareCapabilities(
            variant=self._variant or "",
            firmware_version=self._firmware_version,
        )
        if self._firmware_version is not None:
            caps.has_version = True
            caps.has_reboot = True
            caps.has_boot_to_bootloader = True
            caps.has_uuid = True
            caps.has_locked = True
        if ctap_info is not None:
            options = getattr(ctap_info, "options", {}) or {}
            caps.ctap2_pin = bool(options.get("clientPin"))
            caps.ctap2_cred_mgmt = bool(options.get("credMgmt") or options.get("credentialMgmtPreview"))
            caps.ctap2_uv = bool(options.get("uv"))
            caps.ctap2_rk = bool(options.get("rk"))
            caps.ctap2_up = bool(options.get("up"))
            extensions = getattr(ctap_info, "extensions", []) or []
            if "piv" in extensions:
                caps.has_piv = True
        if self._variant in ("Hacker", "Secure"):
            caps.has_piv = True
            caps.has_openpgp = True
        return caps

    def _matches_hid_device(self, hid_device) -> bool:
        desc = getattr(hid_device, "descriptor", None)
        if not desc:
            return False
        desc_path = getattr(desc, "path", None)
        if self._hid_path is not None and desc_path == self._hid_path:
            return True
        if self._device_uuid:
            return self._get_uuid_from_hid(hid_device) == self._device_uuid
        if self.path.startswith("uuid:"):
            return self._get_uuid_from_hid(hid_device) == self.path.split(":", 1)[1]
        if self.path.startswith("hid:"):
            return self.path == f"hid:{desc_path!r}"
        return False

    def open_hid_device(self):
        fallback = None
        allow_fallback = self._device_uuid is None and not self.path.startswith("uuid:")
        for hid_device in list_ctap_hid_devices():
            desc = getattr(hid_device, "descriptor", None)
            if not desc:
                continue
            _log.debug(
                "open_hid_device candidate path=%r vid=0x%04x pid=0x%04x",
                getattr(desc, "path", None),
                getattr(desc, "vid", 0) or 0,
                getattr(desc, "pid", 0) or 0,
            )
            if allow_fallback and fallback is None:
                version = self._get_firmware_version_from_hid(hid_device)
                if version:
                    fallback = hid_device
            if self._matches_hid_device(hid_device):
                self._hid_path = getattr(desc, "path", None)
                return hid_device
        if allow_fallback and fallback is not None:
            desc = getattr(fallback, "descriptor", None)
            self._hid_path = getattr(desc, "path", None)
            if self._device_uuid is None:
                self._device_uuid = self._get_uuid_from_hid(fallback)
            return fallback
        return None

    def _should_retry_hid_error(self, exc: Exception) -> bool:
        err = str(exc).lower()
        return (
            "wrong channel" in err
            or "wrong_channel" in err
            or "busy" in err
            or "0x06" in err
            or "6f00" in err
            or "0x6f00" in err
        )

    def _reset_hid_channel(self, hid_device) -> None:
        try:
            hid_device._channel_id = 0xFFFFFFFF  # Broadcast channel
            nonce = os.urandom(8)
            response = hid_device.call(0x06, nonce)
            if response[:8] == nonce:
                (hid_device._channel_id,) = struct.unpack_from(">I", response, 8)
        except Exception as exc:
            _log.debug("_reset_hid_channel failed path=%r err=%s", self._hid_path, exc)

    def _call_hid_command(
        self,
        command: int,
        data: bytes = b"",
        *,
        hid_device=None,
        retries: int = 1,
    ) -> bytes:
        """Send a HID vendor command with one retry for transient transport failures."""
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            device = hid_device if hid_device is not None else self.open_hid_device()
            if device is None:
                raise RuntimeError("Device not available")
            try:
                return bytes(device.call(command, data))
            except Exception as exc:
                last_error = exc
                if attempt >= retries or not self._should_retry_hid_error(exc):
                    break
                self._reset_hid_channel(device)
                time.sleep(0.1 * (attempt + 1))
                if hid_device is None:
                    self._hid_path = None

        if last_error is not None:
            raise last_error
        raise RuntimeError("Device not available")

    def open_pcsc_connection(self, *, secrets: bool = False, admin: bool = False):
        connection = open_pcsc_connection(secrets=secrets, admin=admin)
        self._reader_name = connection.reader_name
        return connection

    def open_ctap2(self) -> Optional[Ctap2]:
        try:
            hid_device = self.open_hid_device()
            if hid_device is None:
                return None
            return Ctap2(hid_device)
        except Exception:
            return None

    def _get_firmware_version_from_pcsc(self, connection) -> Optional[str]:
        try:
            resp = connection.call_admin(0x61)
            if len(resp) < 4:
                return None
            version = struct.unpack(">I", resp[:4])[0]
            major = version >> 22
            minor = (version >> 6) & ((1 << 16) - 1)
            patch = version & ((1 << 6) - 1)
            return f"{major}.{minor}.{patch}"
        except Exception as exc:
            _log.debug("_get_firmware_version_from_pcsc failed reader=%s err=%s", self._reader_name, exc)
            return None

    def _get_uuid_from_pcsc(self, connection) -> Optional[str]:
        try:
            resp = connection.call_admin(0x62)
            if len(resp) < 16:
                return None
            uuid_hex = resp[:16].hex()
            return (
                f"{uuid_hex[:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-"
                f"{uuid_hex[16:20]}-{uuid_hex[20:32]}"
            )
        except Exception as exc:
            _log.debug("_get_uuid_from_pcsc failed reader=%s err=%s", self._reader_name, exc)
            return None

    def prefers_ccid(self) -> bool:
        return self._descriptor.transport == "ccid"
