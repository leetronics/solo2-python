"""CTAP HID backend helpers for Solo 2 devices."""

from __future__ import annotations

import logging
import sys
from typing import Iterator

from fido2.hid import CtapHidDevice, list_descriptors as list_fido2_descriptors, open_connection

_log = logging.getLogger("solo2device")


def list_ctap_hid_descriptors():
    """Enumerate CTAP HID descriptors without opening a CTAP session."""
    if sys.platform == "win32":
        _log.debug("list_ctap_hid_descriptors using native fido2 Windows backend")
    else:
        _log.debug("list_ctap_hid_descriptors using generic fido2 backend")

    descriptors = list(list_fido2_descriptors())
    _log.debug("list_ctap_hid_descriptors returned %d device(s)", len(descriptors))

    for descriptor in descriptors:
        _log.debug(
            "fido2 descriptor path=%r vid=0x%04x pid=0x%04x in=%s out=%s "
            "product=%r serial=%r",
            descriptor.path,
            descriptor.vid,
            descriptor.pid,
            descriptor.report_size_in,
            descriptor.report_size_out,
            descriptor.product_name,
            descriptor.serial_number,
        )
        yield descriptor


def list_ctap_hid_devices() -> Iterator[CtapHidDevice]:
    """Open CTAP HID devices from passive descriptor discovery."""
    for descriptor in list_ctap_hid_descriptors():
        try:
            yield CtapHidDevice(descriptor, open_connection(descriptor))
        except Exception as exc:
            _log.exception(
                "failed to open CTAP device path=%r: %s",
                descriptor.path,
                exc,
            )
