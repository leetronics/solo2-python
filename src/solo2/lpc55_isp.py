"""
Minimal MCUBOOT ISP implementation for LPC55 Hacker/Secure detection.

Implements enough of the MCUBOOT protocol (NXP MCUBOOTRM) to perform a
read-memory command via USB HID. A Secure device blocks this read;
a Hacker device allows it. No dependency on the lpc55 CLI tool.

Protocol reference: https://www.nxp.com/docs/en/reference-manual/MCUBOOTRM.pdf
"""
from __future__ import annotations

import logging
import time

from .bootloader import BootloaderSession, BootloaderError

_log = logging.getLogger("solo2device")

SOLOKEYS_VID = 0x1209
BOOTLOADER_PID = 0xB000

CMPA_ADDRESS = 0x9E400     # Customer Manufacturing Page Area base address
CMPA_SHA256_OFFSET = 0x60  # sha256_digest offset within the CMPA page (32 bytes)
CMPA_SHA256_SIZE = 32
CMPA_SIZE = 512            # CMPA page is one 512-byte flash block


class Lpc55AccessDenied(Exception):
    """Bootrom blocked the memory read — device is Secure."""


class Lpc55Error(Exception):
    """General ISP transport or protocol error."""


class _Bootloader:
    """Context manager for a MCUBOOT HID session with the LPC55 bootloader."""

    def __enter__(self) -> "_Bootloader":
        try:
            self._session = BootloaderSession.find(timeout=0)
        except BootloaderError as exc:
            raise Lpc55Error(str(exc)) from exc
        return self

    def __exit__(self, *_):
        try:
            self._session.close()
        except Exception:
            pass

    def read_memory(self, address: int, length: int) -> bytes:
        try:
            return self._session.read_memory(address, length)
        except BootloaderError as exc:
            raise Lpc55AccessDenied(str(exc)) from exc

    def erase_flash(self, address: int, length: int) -> None:
        try:
            self._session.erase_flash(address, length)
        except BootloaderError as exc:
            raise Lpc55Error(str(exc)) from exc

    def write_memory(self, address: int, data: bytes) -> None:
        try:
            self._session.write_memory(address, data)
        except BootloaderError as exc:
            raise Lpc55Error(str(exc)) from exc

    def reset(self) -> None:
        try:
            self._session.reset()
        except Exception:
            pass


def wait_for_bootloader(timeout_s: float = 10.0) -> bool:
    """
    Poll until a bootloader device (1209:b000) appears on USB or timeout expires.
    Returns True if found, False on timeout.
    """
    from .bootloader import hid as _hid

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _hid is not None:
            if any(
                d.get("vendor_id") == SOLOKEYS_VID and d.get("product_id") == BOOTLOADER_PID
                for d in _hid.enumerate()
            ):
                return True
        else:
            try:
                BootloaderSession.find(timeout=0)
                return True
            except BootloaderError:
                pass
        time.sleep(0.2)
    return False


def detect_variant() -> str:
    """
    Detect device variant via MCUBOOT ISP. Device must be in bootloader mode (1209:b000).

    Returns one of:
      "Secure"          — bootrom blocks memory reads (genuine Secure device)
      "Hacker (locked)" — reads allowed (bootrom does not enforce SB) → Hacker with SB active

    Note: "Hacker (unlocked)" is not returned here — call the firmware locked() check
    instead (it is cheaper and does not require a reboot). Only call this function when
    the firmware-reported status is ambiguous (i.e. device appears locked/Secure).

    Raises Lpc55Error if no bootloader device is found or a transport error occurs.
    After the check the device is sent a Reset command to return to firmware mode.
    """
    with _Bootloader() as bl:
        try:
            bl.read_memory(CMPA_ADDRESS, 4)
        except Lpc55AccessDenied as exc:
            _log.debug("lpc55_isp: access denied → Secure: %s", exc)
            bl.reset()
            return "Secure"

        # ISP read succeeded → bootrom does not enforce Secure Boot → Hacker (locked)
        _log.debug("lpc55_isp: access allowed → Hacker (locked)")
        bl.reset()
        return "Hacker (locked)"


def disable_secure_boot() -> None:
    """
    Disable Secure Boot on a Hacker (locked) device.

    Reads the 512-byte CMPA page, zeroes the 32-byte SHA256 digest field at
    offset 0x60, then erases and rewrites the page.  The bootloader uses the
    digest to verify CMPA integrity; a zero digest means "no seal" → Secure
    Boot disabled.

    Device must be in bootloader mode (1209:b000).  Raises Lpc55Error if the
    device is Secure (ISP read blocked) or if the write fails.  Resets the
    device back to firmware mode on success.

    If the digest is already all-zeros the page is not rewritten.
    """
    with _Bootloader() as bl:
        try:
            cmpa = bl.read_memory(CMPA_ADDRESS, CMPA_SIZE)
        except Lpc55AccessDenied as exc:
            raise Lpc55Error(
                f"Cannot read CMPA — device is Secure (ISP blocked): {exc}"
            ) from exc

        digest = cmpa[CMPA_SHA256_OFFSET : CMPA_SHA256_OFFSET + CMPA_SHA256_SIZE]
        if not any(digest):
            _log.debug("lpc55_isp: CMPA digest already zero — already unlocked")
            bl.reset()
            return

        cmpa_new = bytearray(cmpa)
        cmpa_new[CMPA_SHA256_OFFSET : CMPA_SHA256_OFFSET + CMPA_SHA256_SIZE] = bytes(
            CMPA_SHA256_SIZE
        )

        _log.debug("lpc55_isp: erasing CMPA page at 0x%X", CMPA_ADDRESS)
        bl.erase_flash(CMPA_ADDRESS, CMPA_SIZE)

        _log.debug("lpc55_isp: writing CMPA with zeroed digest")
        bl.write_memory(CMPA_ADDRESS, bytes(cmpa_new))

        bl.reset()
