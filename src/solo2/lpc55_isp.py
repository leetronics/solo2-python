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
from typing import Callable, Optional

from .bootloader import BootloaderSession, BootloaderError

_log = logging.getLogger("solo2device")

SOLOKEYS_VID = 0x1209
BOOTLOADER_PID = 0xB000

CMPA_ADDRESS = 0x9E400     # Customer Manufacturing Page Area base address
CMPA_SHA256_OFFSET = 0x60  # sha256_digest offset within the CMPA page (32 bytes)
CMPA_SHA256_SIZE = 32
CMPA_SIZE = 512            # CMPA page is one 512-byte flash block

CFPA_SCRATCH_ADDRESS = 0x9DE00  # CFPA Scratch (staging area for next CFPA write)
CFPA_PING_ADDRESS    = 0x9E000  # CFPA Ping (active CFPA, ping-pong pair)
CFPA_PONG_ADDRESS    = 0x9E200  # CFPA Pong (active CFPA, ping-pong pair)
CFPA_SIZE            = 512
PFR_BACKUP_SIZE      = CFPA_SIZE * 4  # Scratch + Ping + Pong + CMPA = 2048 bytes

# SECURE_BOOT_CFG register layout (lpc55-0.2.1/src/protected_flash.rs):
#   Word offset 0x1C in CMPA (7th u32).  SECURE_BOOT_EN = bits [31:30].
#   In the little-endian byte array that is byte 0x1F, bits [7:6].
#   Enabled = 0b11, disabled = 0b00.  Clearing is a valid 1→0 NOR flash write.
CMPA_SECURE_BOOT_EN_BYTE = 0x1F   # MSB byte of SECURE_BOOT_CFG word
CMPA_SECURE_BOOT_EN_MASK = 0xC0   # bits [7:6] = SECURE_BOOT_EN[31:30]

CMPA_ROTKH_OFFSET = 0x50          # Root of Trust Key Hash: 32 bytes at CMPA[0x50:0x70]


class Lpc55AccessDenied(Exception):
    """Bootrom blocked the memory read — device is Secure."""


class Lpc55Error(Exception):
    """General ISP transport or protocol error."""


class _Bootloader:
    """Context manager for a MCUBOOT HID session with the LPC55 bootloader."""

    def __enter__(self) -> "_Bootloader":
        try:
            self._session = BootloaderSession.find(timeout=3.0)
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

    def erase_all(self) -> None:
        try:
            self._session.erase_all()
        except BootloaderError as exc:
            raise Lpc55Error(str(exc)) from exc

    def receive_sb_file(self, data: bytes, progress_cb=None) -> None:
        try:
            self._session.receive_sb_file(data, progress_cb=progress_cb)
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


def cmpa_to_pfr_yaml(cmpa: bytes) -> str:
    """Generate a human-readable YAML backup string from a 512-byte CMPA binary."""
    rot_fingerprint = cmpa[CMPA_ROTKH_OFFSET : CMPA_ROTKH_OFFSET + CMPA_SHA256_SIZE].hex()
    secure_boot_enabled = bool(cmpa[CMPA_SECURE_BOOT_EN_BYTE] & CMPA_SECURE_BOOT_EN_MASK)
    cmpa_hex = cmpa.hex()
    return (
        "# SoloKeys Solo2 PFR backup — created by SoloKeys GUI\n"
        "# Compare with device state using: lpc55 pfr yaml\n"
        "# Restore CMPA manually:\n"
        "#   python3 -c \"import binascii; open('cmpa.bin','wb').write(binascii.unhexlify('<cmpa-raw-hex value>'))\"\n"
        "#   lpc55 write-memory 0x9E400 cmpa.bin\n"
        "\n"
        "version: 1\n"
        "\n"
        "factory-settings:\n"
        f"  rot-fingerprint: {rot_fingerprint}\n"
        "  secure-boot-configuration:\n"
        f"    secure-boot-enabled: {str(secure_boot_enabled).lower()}\n"
        "\n"
        f'cmpa-raw-hex: "{cmpa_hex}"\n'
    )


def pfr_yaml_to_cmpa(yaml_str: str) -> bytes:
    """Extract the CMPA binary from a PFR YAML backup string."""
    import re
    m = re.search(r'cmpa-raw-hex:\s*["\']?([0-9a-fA-F]{1024})["\']?', yaml_str)
    if not m:
        raise Lpc55Error("cmpa-raw-hex not found in PFR YAML backup")
    return bytes.fromhex(m.group(1))


def detect_variant(*, reset_after: bool = True) -> str:
    """
    Detect device variant via MCUBOOT ISP. Device must be in bootloader mode (1209:b000).

    Returns one of:
      "Secure"             — bootrom blocks memory reads (genuine Secure device)
      "Hacker (locked)"    — reads allowed; SHA256 non-zero or SECURE_BOOT_EN set → SB active
      "Hacker (unlocked)"  — reads allowed; SHA256 all-zero and SECURE_BOOT_EN cleared → SB off

    Raises Lpc55Error if no bootloader device is found or a transport error occurs.

    reset_after: if True (default), send a Reset command to return to firmware mode
                 after the probe.  Pass False to leave the device in bootloader mode
                 so the caller can perform follow-up operations (e.g. disable_secure_boot).
    """
    with _Bootloader() as bl:
        try:
            cmpa = bl.read_memory(CMPA_ADDRESS, CMPA_SIZE)
        except Lpc55AccessDenied as exc:
            _log.debug("lpc55_isp: access denied → Secure: %s", exc)
            if reset_after:
                bl.reset()
            return "Secure"

        digest = cmpa[CMPA_SHA256_OFFSET : CMPA_SHA256_OFFSET + CMPA_SHA256_SIZE]
        secure_boot_en = cmpa[CMPA_SECURE_BOOT_EN_BYTE] & CMPA_SECURE_BOOT_EN_MASK
        if reset_after:
            bl.reset()
        if not any(digest) and not secure_boot_en:
            _log.debug("lpc55_isp: digest all-zero, SECURE_BOOT_EN clear → Hacker (unlocked)")
            return "Hacker (unlocked)"
        _log.debug(
            "lpc55_isp: locked (digest_nonzero=%s secure_boot_en=0x%02x)",
            any(digest), secure_boot_en,
        )
        return "Hacker (locked)"


def _read_firmware_from_flash(
    bl: "_Bootloader",
    progress_cb: Optional[Callable[[int, str], None]] = None,
    pct_start: int = 5,
    pct_end: int = 25,
) -> bytes:
    """
    Read user firmware from flash in 4 KB chunks.

    Returns the firmware bytes (extent from address 0 to the last non-0xFF
    byte, padded to 512-byte alignment).  Raises Lpc55Error if flash appears
    blank (< 1 KB of non-0xFF data).
    """
    def _p(pct: int, msg: str) -> None:
        if progress_cb:
            progress_cb(pct, msg)

    FLASH_USER_MAX = 640 * 1024   # LPC55S69: 640 KB user flash
    CHUNK = 4096
    firmware_buf: bytearray = bytearray()
    last_data_end = 0

    for offset in range(0, FLASH_USER_MAX, CHUNK):
        chunk = bl.read_memory(offset, CHUNK)
        firmware_buf.extend(chunk)
        if any(b != 0xFF for b in chunk):
            last_data_end = offset + CHUNK
        elif last_data_end > 0:
            # First all-0xFF chunk after firmware data — firmware is contiguous,
            # so it ends here.  Stop immediately to avoid reading into PFR area.
            break
        elif offset >= CHUNK:
            # Two all-0xFF chunks from the start — flash is blank.
            break
        pct = pct_start + int(offset / FLASH_USER_MAX * (pct_end - pct_start))
        _p(pct, f"Reading flash: {offset // 1024} KB…")

    _log.debug(
        "_read_firmware_from_flash: read %d B, firmware extent = %d B",
        len(firmware_buf), last_data_end,
    )

    if last_data_end < 1024:
        raise Lpc55Error(
            "Flash appears to be blank (no firmware found at address 0x00000000)."
        )

    firmware = bytes(firmware_buf[:last_data_end])
    if len(firmware) % 512:
        firmware += b"\xff" * (512 - len(firmware) % 512)
    return firmware


def disable_secure_boot(
    progress_cb: Optional[Callable[[int, str], None]] = None,
) -> tuple:
    """
    Disable Secure Boot on a Hacker (locked) device.

    Reads the 512-byte CMPA page and makes two changes, then rewrites it:

    1. Zeroes the 32-byte SHA256 digest at offset 0x60 — this unseals the CMPA
       page so the bootrom skips integrity verification.
    2. Clears SECURE_BOOT_EN (bits [31:30] of the SECURE_BOOT_CFG word at
       CMPA offset 0x1C, i.e. bits [7:6] of byte 0x1F) — this disables
       signature verification of the firmware image.

    Both changes only flip bits from 1→0, which NOR flash allows without
    prior erasure (LPC55 PFR pages cannot be erased via ISP Flash Erase
    Region — status 0x8c).

    Device must be in bootloader mode (1209:b000).  Raises Lpc55Error if the
    device is Secure (ISP read blocked) or if the write fails.  Resets the
    device back to firmware mode on success.

    Skips the write if both fields are already cleared.

    Returns (pfr_yaml, firmware) where:
      pfr_yaml — YAML string (PFR backup) containing the original CMPA data,
                 for use with relock_device().
      firmware — bytes of the signed firmware read from flash before unlock,
                 for use with relock_device() to restore factory state.
                 Empty bytes if flash was blank or unreadable.
    """
    def _p(pct: int, msg: str) -> None:
        if progress_cb:
            progress_cb(pct, msg)

    with _Bootloader() as bl:
        # Read firmware backup BEFORE modifying CMPA so the caller can save it
        # for later use with relock_device().
        _p(5, "Reading firmware backup from flash…")
        try:
            firmware = _read_firmware_from_flash(bl, progress_cb, pct_start=5, pct_end=35)
            _log.debug("disable_secure_boot: firmware backup %d B", len(firmware))
        except (Lpc55Error, Lpc55AccessDenied) as exc:
            # Flash is blank, unreadable, or access denied — proceed without firmware backup.
            _log.warning("disable_secure_boot: could not read firmware backup: %s", exc)
            firmware = b""

        _p(40, "Reading CMPA…")
        try:
            cmpa = bl.read_memory(CMPA_ADDRESS, CMPA_SIZE)
        except Lpc55AccessDenied as exc:
            raise Lpc55Error(
                f"Cannot read CMPA — device is Secure (ISP blocked): {exc}"
            ) from exc

        pfr_yaml = cmpa_to_pfr_yaml(bytes(cmpa))

        digest = cmpa[CMPA_SHA256_OFFSET : CMPA_SHA256_OFFSET + CMPA_SHA256_SIZE]
        secure_boot_en = cmpa[CMPA_SECURE_BOOT_EN_BYTE] & CMPA_SECURE_BOOT_EN_MASK
        if not any(digest) and not secure_boot_en:
            _log.debug("lpc55_isp: CMPA already fully unlocked — nothing to do")
            bl.reset()
            return pfr_yaml, firmware

        cmpa_new = bytearray(cmpa)
        # Zero SHA256 digest → unseal CMPA
        cmpa_new[CMPA_SHA256_OFFSET : CMPA_SHA256_OFFSET + CMPA_SHA256_SIZE] = bytes(
            CMPA_SHA256_SIZE
        )
        # Clear SECURE_BOOT_EN bits [7:6] of byte 0x1F (bits [31:30] of SECURE_BOOT_CFG)
        cmpa_new[CMPA_SECURE_BOOT_EN_BYTE] &= ~CMPA_SECURE_BOOT_EN_MASK & 0xFF

        _p(80, "Writing CMPA…")
        _log.debug(
            "lpc55_isp: writing CMPA — zeroing SHA256 + clearing SECURE_BOOT_EN "
            "(no erase — PFR is write-only via ISP)"
        )
        bl.write_memory(CMPA_ADDRESS, bytes(cmpa_new))

        _p(95, "Resetting device…")
        bl.reset()
        return pfr_yaml, firmware


def relock_device(
    pfr_yaml: str,
    firmware: bytes = b"",
    *,
    progress_cb: Optional[Callable[[int, str], None]] = None,
) -> None:
    """
    Re-enable Secure Boot on a previously unlocked Hacker device.

    Requires:
      pfr_yaml — YAML string returned by disable_secure_boot() (contains
                 the full 512-byte CMPA in hex under cmpa-raw-hex).
      firmware — signed firmware bytes saved during unlock (from
                 disable_secure_boot()).  If empty, the firmware is read
                 from the device's flash at relock time (only works if the
                 device currently has the original signed firmware in flash;
                 fails if custom unsigned firmware is present).

    Procedure (single bootloader session):
      1. If firmware provided: use it.  Otherwise read from device flash.
         The firmware must be a SoloKeys-signed build so that secure boot
         can verify it after CMPA is re-locked.
      2. erase_all() — erases user flash + CMPA (CMPA → 0xFF).
         CMPA must be erased to flip the cleared bits back to 1 (NOR flash
         cannot flip 0→1 without erase).
      3. write_memory(0x00000000, firmware) — restore the firmware.
      4. write_memory(CMPA, cmpa_backup) — restore locked CMPA (all bits
         can be written since CMPA = 0xFF after erase_all).
      5. read_memory(CMPA) → verify SECURE_BOOT_EN set and seal non-zero.
      6. reset().

    Device must be in bootloader mode (1209:b000) AND in DEV mode
    (ROTKH second half = 0, i.e. after disable_secure_boot()).
    Raises Lpc55Error on failure.
    """
    def _p(pct: int, msg: str) -> None:
        if progress_cb:
            progress_cb(pct, msg)

    cmpa_backup = pfr_yaml_to_cmpa(pfr_yaml)

    secure_boot_en = cmpa_backup[CMPA_SECURE_BOOT_EN_BYTE] & CMPA_SECURE_BOOT_EN_MASK
    if not secure_boot_en:
        raise Lpc55Error(
            "CMPA backup does not have Secure Boot enabled — "
            "this does not appear to be a valid locked-state backup"
        )
    sha256_seal = cmpa_backup[CMPA_SHA256_OFFSET : CMPA_SHA256_OFFSET + CMPA_SHA256_SIZE]
    if not any(sha256_seal):
        raise Lpc55Error(
            "CMPA backup has all-zero SHA256 seal — "
            "this looks like a post-unlock state, not a locked-state backup"
        )
    if all(b == 0xFF for b in sha256_seal):
        raise Lpc55Error(
            "CMPA backup appears to be from a blank/erased device (SHA256 seal is all 0xFF). "
            "The backup must be saved while the device is in its original factory-locked state. "
            "Please unlock the device, save a fresh backup, then relock."
        )

    # ── Single session: firmware → erase → restore firmware → restore CMPA ──
    with _Bootloader() as bl:
        # ── Step 1: obtain firmware ─────────────────────────────────────────
        if firmware:
            fw_to_flash = firmware
            _log.debug("relock: using provided firmware backup (%d B)", len(fw_to_flash))
            _p(25, f"Using firmware backup: {len(fw_to_flash) // 1024} KB — erasing flash…")
        else:
            # Fallback: read from flash.  Only works if device has signed firmware.
            _p(5, "Reading firmware from flash…")
            fw_to_flash = _read_firmware_from_flash(bl, progress_cb, pct_start=5, pct_end=25)
            _p(25, f"Firmware: {len(fw_to_flash) // 1024} KB — erasing flash…")

        # ── Step 2: erase_all ───────────────────────────────────────────────
        # This is the only way to reset CMPA bits from 0→1 on NOR flash.
        # Also clears user flash so we can write back the firmware.
        bl.erase_all()
        _p(30, "Flash erased — restoring firmware…")

        # ── Step 3: restore firmware ────────────────────────────────────────
        bl.write_memory(0x00000000, fw_to_flash)
        _p(70, "Firmware restored — writing locked CMPA…")

        # ── Step 4: restore locked CMPA ────────────────────────────────────
        # CMPA = 0xFF after erase_all → all bits can be written.
        bl.write_memory(CMPA_ADDRESS, cmpa_backup)

        # ── Step 5: verify CMPA ────────────────────────────────────────────
        _p(85, "Verifying CMPA…")
        cmpa_rb     = bl.read_memory(CMPA_ADDRESS, CMPA_SIZE)
        sbe_written = cmpa_backup[CMPA_SECURE_BOOT_EN_BYTE] & CMPA_SECURE_BOOT_EN_MASK
        sbe_actual  = cmpa_rb[CMPA_SECURE_BOOT_EN_BYTE]     & CMPA_SECURE_BOOT_EN_MASK
        seal_actual = cmpa_rb[CMPA_SHA256_OFFSET : CMPA_SHA256_OFFSET + CMPA_SHA256_SIZE]
        if sbe_actual != sbe_written or not any(seal_actual):
            raise Lpc55Error(
                f"CMPA write verification failed "
                f"(SECURE_BOOT_EN: expected 0x{sbe_written:02x}, got 0x{sbe_actual:02x}; "
                f"SHA256 seal all-zero: {not any(seal_actual)}). "
                "Try power-cycling and relocking again."
            )

        # ── Step 6: reset ───────────────────────────────────────────────────
        _p(98, "Resetting device…")
        bl.reset()

    _p(100, "Done — device relocked")


def relock_with_device(
    device,
    pfr_yaml: str,
    firmware: bytes = b"",
    progress_cb: Optional[Callable[[int, str], None]] = None,
) -> None:
    """
    Relock a device from regular firmware mode.

    Reboots to bootloader, waits, then calls relock_device().

    firmware — signed firmware bytes from disable_secure_boot() backup.
               If empty, firmware is read from device flash at relock time.
    """
    from .admin import AdminSession, RebootMode
    from .device import DeviceMode

    def _p(pct: int, msg: str) -> None:
        if progress_cb:
            progress_cb(pct, msg)

    try:
        already_in_bootloader = device.get_info().mode == DeviceMode.BOOTLOADER
    except Exception:
        already_in_bootloader = False

    if not already_in_bootloader:
        _p(5, "Rebooting to bootloader…")
        try:
            AdminSession(device).reboot(RebootMode.BOOTLOADER)
        except Exception:
            pass

    _p(10, "Waiting for bootloader…")
    if not wait_for_bootloader(timeout_s=10.0):
        raise Lpc55Error(
            "Bootloader device did not appear within 10 s.\n"
            "Make sure the device is connected and try again."
        )

    relock_device(pfr_yaml, firmware, progress_cb=progress_cb)


def check_variant_with_device(
    device,
    progress_cb: Optional[Callable[[int, str], None]] = None,
) -> str:
    """
    Detect the hardware variant of a Solo 2 device via MCUBOOT ISP.

    If the device is in regular firmware mode it is rebooted to bootloader mode
    first.  If it is already in bootloader mode the reboot step is skipped.

    On success, ``device.confirm_lock_status()`` is called to update the
    device's cached lock state:
      False  — "Hacker (unlocked)"
      True   — "Hacker (locked)" or "Secure"

    Returns one of: "Hacker (unlocked)", "Hacker (locked)", "Secure"
    Raises Lpc55Error on transport or protocol failure.
    """
    from .admin import AdminSession, RebootMode
    from .device import DeviceMode

    def _progress(pct: int, msg: str) -> None:
        if progress_cb is not None:
            progress_cb(pct, msg)

    try:
        already_in_bootloader = device.get_info().mode == DeviceMode.BOOTLOADER
    except Exception:
        already_in_bootloader = False

    if not already_in_bootloader:
        _progress(10, "Rebooting to bootloader…")
        try:
            AdminSession(device).reboot(RebootMode.BOOTLOADER)
        except Exception:
            pass  # device disconnects during reboot — expected

    _progress(30, "Waiting for bootloader…")
    if not wait_for_bootloader(timeout_s=10.0):
        raise Lpc55Error(
            "Bootloader device did not appear within 10 s.\n"
            "Make sure the device is connected and try again."
        )

    _progress(60, "Probing CMPA via ISP…")
    # If the device was already in bootloader mode, leave it there so the caller
    # can perform follow-up operations (e.g. disable_secure_boot / unlock).
    # If we rebooted it from regular mode, send it back to firmware.
    result = detect_variant(reset_after=not already_in_bootloader)

    try:
        device.confirm_lock_status(result != "Hacker (unlocked)")
    except Exception:
        pass

    _progress(100, "Done")
    return result
