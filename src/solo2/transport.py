"""Synchronous transport helpers built on the Solo 2 core library."""

from __future__ import annotations

import os
import struct
import time

from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID

from .discovery import list_regular_descriptors, open_device
from .errors import Solo2NotFoundError, Solo2TransportError
from .device import Solo2Device


class DeviceTransport:
    """Open the first available Solo 2 regular-mode device and send browser APDUs."""

    def __init__(self):
        self._device: Solo2Device | None = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()

    def open(self) -> None:
        for descriptor in list_regular_descriptors():
            try:
                device = open_device(descriptor)
                self._device = device
                return
            except Exception:
                continue
        raise Solo2NotFoundError("No SoloKeys device found")

    def close(self) -> None:
        self._device = None

    def send_apdu(self, apdu_bytes: bytes, retries: int = 2) -> bytes:
        if self._device is None:
            raise Solo2TransportError("Device not open")
        if self._device.prefers_ccid():
            try:
                return self._device.secrets().send_apdu(apdu_bytes)
            except Exception as exc:
                raise Solo2TransportError(f"APDU failed: {exc}") from exc

        last_err = None
        for attempt in range(retries + 1):
            try:
                ctap2 = self._device.open_ctap2()
                if ctap2 is None:
                    raise Solo2TransportError("Device not available")
                return bytes(ctap2.device.call(0x70, bytes(apdu_bytes)))
            except Exception as exc:
                last_err = exc
                err_str = str(exc).lower()
                if attempt < retries and ("busy" in err_str or "channel" in err_str or "0x06" in err_str):
                    time.sleep(0.1 * (attempt + 1))
                    self._reset_channel()
                    continue
                break
        raise Solo2TransportError(f"APDU failed: {last_err}")

    def _reset_channel(self) -> None:
        if self._device is None:
            return
        try:
            ctap2 = self._device.open_ctap2()
            if ctap2 is None:
                return
            hid_dev = ctap2.device
            hid_dev._channel_id = 0xFFFFFFFF
            nonce = os.urandom(8)
            response = hid_dev.call(CTAPHID.INIT, nonce)
            if response[:8] == nonce:
                (hid_dev._channel_id,) = struct.unpack_from(">I", response, 8)
        except Exception:
            pass


def call_device_apdu(apdu_bytes: bytes) -> bytes:
    with DeviceTransport() as transport:
        return transport.send_apdu(apdu_bytes)
