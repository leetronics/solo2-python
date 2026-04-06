"""USB HID bootloader session for Solo 2 LPC55 devices.

This implements the MCU Boot USB-HID framing actually used by the Solo 2 ROM
bootloader:

command report -> initial generic response -> optional command-data reports ->
final generic response

Unlike the earlier implementation, there is no per-data-packet ACK step for the
USB-HID transport.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Optional

import usb.core
import usb.util

from .device import Solo2Device

try:
    import hid
except Exception:  # pragma: no cover - optional dependency on some platforms
    hid = None

SOLOKEYS_VID = Solo2Device.SOLOKEYS_VID
BOOTLOADER_PID = Solo2Device.BOOTLOADER_PID
NXP_BOOTLOADER_VID = 0x1FC9
NXP_BOOTLOADER_PID = 0x0021

_REPORT_COMMAND = 0x01
_REPORT_COMMAND_DATA = 0x02
_REPORT_RESPONSE = 0x03
_REPORT_RESPONSE_DATA = 0x04

_COMMAND_PAYLOAD_SIZE = 32
_DATA_PAYLOAD_SIZE = 32
_RESPONSE_TAG_GENERIC = 0xA0

_CMD_FLASH_ERASE_ALL = 0x01
_CMD_FLASH_ERASE_REGION = 0x02
_TAG_READ_MEMORY = 0x03
_CMD_WRITE_MEMORY = 0x04
_CMD_RECEIVE_SB_FILE = 0x08
_CMD_RESET = 0x0B

_FLASH_WRITE_ALIGNMENT = 512


class BootloaderError(Exception):
    """Raised for Solo 2 bootloader communication failures."""


@dataclass(frozen=True)
class _ResponsePacket:
    tag: int
    has_data: bool
    status: int
    parameters: tuple[int, ...]


class BootloaderSession:
    """Synchronous session with a Solo 2 device in ROM bootloader mode."""

    def __init__(self, usb_device: Optional[usb.core.Device] = None, *, hid_path: object = None):
        self._dev = usb_device
        self._hid_path = hid_path
        self._hid_dev = None
        self._ep_out: Optional[usb.core.Endpoint] = None
        self._ep_in: Optional[usb.core.Endpoint] = None
        self._claimed_interface = False

    @classmethod
    def find(cls, timeout: float = 0.0) -> "BootloaderSession":
        """Return a session for the first bootloader device found."""
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            if hid is not None:
                for info in hid.enumerate():
                    vid = info.get("vendor_id")
                    pid = info.get("product_id")
                    if (vid, pid) not in (
                        (SOLOKEYS_VID, BOOTLOADER_PID),
                        (NXP_BOOTLOADER_VID, NXP_BOOTLOADER_PID),
                    ):
                        continue
                    path = info.get("path")
                    if path is None:
                        continue
                    session = cls(hid_path=path)
                    try:
                        session._open()
                        return session
                    except Exception:
                        session.close()
                        continue

            dev = usb.core.find(idVendor=SOLOKEYS_VID, idProduct=BOOTLOADER_PID)
            if dev is None:
                dev = usb.core.find(idVendor=NXP_BOOTLOADER_VID, idProduct=NXP_BOOTLOADER_PID)
            if dev is not None:
                session = cls(dev)
                try:
                    session._open()
                    return session
                except Exception:
                    session.close()
            if time.monotonic() >= deadline:
                raise BootloaderError("No Solo 2 bootloader device found")
            time.sleep(0.4)

    def __enter__(self) -> "BootloaderSession":
        return self

    def __exit__(self, *_exc_info) -> None:
        self.close()

    def _open(self) -> None:
        if self._hid_path is not None:
            if hid is None:
                raise BootloaderError("hid transport is not available")
            dev = hid.device()
            try:
                dev.open_path(self._hid_path)
            except Exception as exc:
                raise BootloaderError(f"Could not open bootloader HID path: {exc}") from exc
            try:
                dev.set_nonblocking(False)
            except Exception:
                pass
            self._hid_dev = dev
            return

        dev = self._dev
        if dev is None:
            raise BootloaderError("No bootloader device selected")
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
        except Exception:
            pass
        try:
            dev.set_configuration()
        except usb.core.USBError:
            pass

        intf = dev.get_active_configuration()[(0, 0)]
        usb.util.claim_interface(dev, 0)
        self._claimed_interface = True

        self._ep_out = usb.util.find_descriptor(
            intf,
            custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress)
            == usb.util.ENDPOINT_OUT,
        )
        self._ep_in = usb.util.find_descriptor(
            intf,
            custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress)
            == usb.util.ENDPOINT_IN,
        )
        if not self._ep_out or not self._ep_in:
            raise BootloaderError("Could not find USB endpoints on bootloader device")

    def close(self) -> None:
        if self._hid_dev is not None:
            try:
                self._hid_dev.close()
            except Exception:
                pass
            finally:
                self._hid_dev = None
        try:
            if self._claimed_interface:
                usb.util.release_interface(self._dev, 0)
        except Exception:
            pass
        finally:
            self._claimed_interface = False
            try:
                usb.util.dispose_resources(self._dev)
            except Exception:
                pass

    def _wrap_usb_error(self, exc: usb.core.USBError, context: str) -> BootloaderError:
        if getattr(exc, "errno", None) == 110:
            return BootloaderError(f"{context} timed out")
        return BootloaderError(f"{context}: {exc}")

    def _write_report(
        self,
        report_id: int,
        payload: bytes,
        *,
        timeout: int = 5000,
        pad_to: Optional[int] = None,
    ) -> None:
        if self._hid_dev is not None:
            packet = bytearray([report_id, 0x00, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF])
            packet.extend(payload)
            if pad_to is not None:
                packet.extend(b"\x00" * max(0, pad_to - len(payload)))
            try:
                written = self._hid_dev.write(bytes(packet))
            except Exception as exc:
                raise BootloaderError(f"Bootloader write: {exc}") from exc
            if written < len(packet):
                raise BootloaderError(f"Bootloader short write: sent {written}/{len(packet)} bytes")
            return

        if self._ep_out is None:
            raise BootloaderError("Bootloader transport is not open")

        packet = bytearray([report_id, 0x00, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF])
        packet.extend(payload)
        if pad_to is not None:
            packet.extend(b"\x00" * max(0, pad_to - len(payload)))
        try:
            written = self._ep_out.write(bytes(packet), timeout=timeout)
        except usb.core.USBError as exc:
            raise self._wrap_usb_error(exc, "Bootloader write") from exc
        if written < len(packet):
            raise BootloaderError(f"Bootloader short write: sent {written}/{len(packet)} bytes")

    def _read_report(self, *, timeout: int = 5000) -> tuple[int, bytes]:
        if self._hid_dev is not None:
            try:
                raw = self._hid_dev.read(256, timeout)
            except Exception as exc:
                raise BootloaderError(f"Bootloader read: {exc}") from exc
            if not raw:
                raise BootloaderError("Bootloader read timed out")
            raw = bytes(raw)
        else:
            if self._ep_in is None:
                raise BootloaderError("Bootloader transport is not open")

            packet_size = max(int(getattr(self._ep_in, "wMaxPacketSize", 64) or 64), 64)
            try:
                raw = bytes(self._ep_in.read(packet_size, timeout=timeout))
            except usb.core.USBError as exc:
                raise self._wrap_usb_error(exc, "Bootloader read") from exc

        if len(raw) < 4:
            raise BootloaderError(f"Short bootloader report: {raw.hex()}")

        report_id = raw[0]
        expected_len = raw[2] | (raw[3] << 8)
        if len(raw) < 4 + expected_len:
            raise BootloaderError(
                f"Short bootloader payload: expected {expected_len} bytes, got {len(raw) - 4}"
            )
        payload = raw[4 : 4 + expected_len]
        return report_id, payload

    def _read_response_packet(self, *, timeout: int = 5000) -> _ResponsePacket:
        report_id, payload = self._read_report(timeout=timeout)
        if report_id == _REPORT_RESPONSE_DATA:
            raise BootloaderError("Unexpected response-data packet")
        if report_id != _REPORT_RESPONSE:
            raise BootloaderError(f"Unexpected bootloader report id: {report_id:#04x}")
        if not payload:
            raise BootloaderError("Bootloader aborted data phase")
        if len(payload) < 4:
            raise BootloaderError(f"Malformed bootloader response: {payload.hex()}")

        tag = payload[0]
        has_data = bool(payload[1] & 0x01)
        param_count = payload[3]
        param_bytes = payload[4:]
        if len(param_bytes) < param_count * 4:
            raise BootloaderError(
                f"Malformed bootloader parameters: expected {param_count}, got {len(param_bytes) // 4}"
            )
        params = tuple(
            struct.unpack_from("<I", param_bytes, offset)[0]
            for offset in range(0, param_count * 4, 4)
        )
        if not params:
            raise BootloaderError(f"Bootloader response without status: {payload.hex()}")
        return _ResponsePacket(
            tag=tag,
            has_data=has_data,
            status=params[0],
            parameters=params[1:],
        )

    def _build_command(self, command_tag: int, params: list[int], *, has_data_phase: bool) -> bytes:
        if len(params) > 7:
            raise BootloaderError(f"Too many bootloader parameters: {len(params)}")
        payload = bytearray([command_tag, 0x01 if has_data_phase else 0x00, 0x00, len(params)])
        for param in params:
            payload.extend(struct.pack("<I", param))
        payload.extend(b"\x00" * (_COMMAND_PAYLOAD_SIZE - len(payload)))
        return bytes(payload)

    def _send_command(
        self,
        context: str,
        command_tag: int,
        params: list[int],
        *,
        has_data_phase: bool = False,
        timeout: int = 5000,
    ) -> _ResponsePacket:
        self._write_report(
            _REPORT_COMMAND,
            self._build_command(command_tag, params, has_data_phase=has_data_phase),
            timeout=timeout,
        )
        response = self._read_response_packet(timeout=timeout)
        if response.status != 0:
            raise BootloaderError(f"{context} failed: status {response.status:#010x}")
        return response

    def _expect_final_generic_success(self, context: str, *, timeout: int = 10000) -> None:
        response = self._read_response_packet(timeout=timeout)
        if response.tag != _RESPONSE_TAG_GENERIC:
            raise BootloaderError(f"{context}: expected generic response, got {response.tag:#04x}")
        if response.status != 0:
            raise BootloaderError(f"{context} failed: status {response.status:#010x}")

    def erase_all(self) -> None:
        """Erase all internal flash."""
        response = self._send_command(
            "FlashEraseAll",
            _CMD_FLASH_ERASE_ALL,
            [],
            timeout=30000,
        )
        if response.tag != _RESPONSE_TAG_GENERIC:
            raise BootloaderError(f"FlashEraseAll: unexpected response tag {response.tag:#04x}")

    def erase_flash(self, start_address: int, length: int) -> None:
        """Erase a flash region aligned to the bootloader's flash block size."""
        if start_address % _FLASH_WRITE_ALIGNMENT != 0:
            raise BootloaderError(
                f"Flash erase address must be a multiple of {_FLASH_WRITE_ALIGNMENT}: {start_address}"
            )
        if length % _FLASH_WRITE_ALIGNMENT != 0:
            raise BootloaderError(
                f"Flash erase length must be a multiple of {_FLASH_WRITE_ALIGNMENT}: {length}"
            )
        response = self._send_command(
            "FlashErase",
            _CMD_FLASH_ERASE_REGION,
            [start_address, length],
            timeout=30000,
        )
        if response.tag != _RESPONSE_TAG_GENERIC:
            raise BootloaderError(f"FlashErase: unexpected response tag {response.tag:#04x}")

    def read_memory(self, address: int, length: int) -> bytes:
        """Read memory via MCUBOOT. Raises BootloaderError if blocked (Secure device)."""
        cmd = self._build_command(_TAG_READ_MEMORY, [address, length], has_data_phase=False)
        self._write_report(_REPORT_COMMAND, cmd)
        response = self._read_response_packet()
        if response.status != 0 or not response.has_data:
            raise BootloaderError(
                f"ReadMemory blocked: status=0x{response.status:08X} has_data={response.has_data}"
            )
        data = bytearray()
        while len(data) < length:
            report_id, payload = self._read_report()
            if report_id != _REPORT_RESPONSE_DATA:
                break
            data.extend(payload)
        try:
            self._read_report(timeout=500)  # drain final generic response
        except Exception:
            pass
        return bytes(data[:length])

    def write_memory(self, start_address: int, data: bytes, progress_cb=None) -> None:
        """Write *data* to internal flash starting at *start_address*."""
        total = len(data)
        response = self._send_command(
            "WriteMemory",
            _CMD_WRITE_MEMORY,
            [start_address, total, 0],
            has_data_phase=True,
            timeout=10000,
        )
        if response.tag != _RESPONSE_TAG_GENERIC:
            raise BootloaderError(f"WriteMemory: unexpected response tag {response.tag:#04x}")

        written = 0
        for chunk in (data[offset : offset + _DATA_PAYLOAD_SIZE] for offset in range(0, total, _DATA_PAYLOAD_SIZE)):
            self._write_report(
                _REPORT_COMMAND_DATA,
                chunk,
                timeout=5000,
                pad_to=_DATA_PAYLOAD_SIZE,
            )
            written += len(chunk)
            if progress_cb is not None:
                progress_cb(written, total)

        self._expect_final_generic_success("WriteMemory", timeout=15000)

    def receive_sb_file(self, data: bytes, progress_cb=None) -> None:
        """Send a signed SB2.1 firmware container via the ReceiveSbFile bootloader command."""
        if len(data) < 96:
            raise BootloaderError(f"SB2.1 file too small: {len(data)} bytes")
        total = len(data)
        response = self._send_command(
            "ReceiveSbFile",
            _CMD_RECEIVE_SB_FILE,
            [total],
            has_data_phase=True,
            timeout=10000,
        )
        if response.tag != _RESPONSE_TAG_GENERIC:
            raise BootloaderError(f"ReceiveSbFile: unexpected response tag {response.tag:#04x}")

        written = 0
        for chunk in (data[off : off + _DATA_PAYLOAD_SIZE] for off in range(0, total, _DATA_PAYLOAD_SIZE)):
            self._write_report(_REPORT_COMMAND_DATA, chunk, timeout=5000, pad_to=_DATA_PAYLOAD_SIZE)
            written += len(chunk)
            if progress_cb is not None:
                progress_cb(written, total)

        # Longer timeout: bootloader verifies signature + executes flash commands internally
        self._expect_final_generic_success("ReceiveSbFile", timeout=60000)

    def reset(self) -> None:
        """Reset the device back into regular firmware mode."""
        try:
            self._write_report(
                _REPORT_COMMAND,
                self._build_command(_CMD_RESET, [], has_data_phase=False),
                timeout=2000,
            )
        except BootloaderError:
            # Disconnect is expected immediately after reset.
            pass

    def write_flash(self, firmware: bytes, progress_cb=None) -> None:
        """Erase all flash and write a raw firmware binary."""
        if len(firmware) < 1024 or len(firmware) > 512 * 1024:
            raise BootloaderError(f"Unexpected firmware size: {len(firmware)} bytes")
        padded = bytearray(firmware)
        overshoot = len(padded) % _FLASH_WRITE_ALIGNMENT
        if overshoot:
            padded.extend(b"\x00" * (_FLASH_WRITE_ALIGNMENT - overshoot))
        self.erase_flash(0x00000000, len(padded))
        self.write_memory(0x00000000, bytes(padded), progress_cb=progress_cb)
