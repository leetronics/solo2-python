"""Discovery helpers for Solo 2 devices."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Dict, List, Sequence

import usb.core

from .device import DeviceMode, Solo2Descriptor, Solo2Device
from .hid_backend import list_ctap_hid_descriptors
from .pcsc import list_pcsc_descriptors, should_prefer_ccid

_log = logging.getLogger("solo2device")


def _list_hid_regular_descriptors() -> List[Solo2Descriptor]:
    """Discover regular-mode Solo 2 devices via HID."""
    descriptors: List[Solo2Descriptor] = []
    seen_ids = set()

    try:
        for desc in list_ctap_hid_descriptors():
            hid_path = getattr(desc, "path", None)
            if hid_path is None:
                continue
            descriptor_id = f"hid:{hid_path!r}"
            if descriptor_id in seen_ids:
                continue
            descriptors.append(
                Solo2Descriptor(
                    id=descriptor_id,
                    mode=DeviceMode.REGULAR,
                    path=descriptor_id,
                    transport="hid",
                    hid_path=hid_path,
                )
            )
            seen_ids.add(descriptor_id)
    except Exception as exc:
        _log.debug("_list_hid_regular_descriptors failed: %s", exc)
    return descriptors


def _list_ccid_regular_descriptors() -> List[Solo2Descriptor]:
    """Discover regular-mode Solo 2 devices via PC/SC."""
    descriptors: List[Solo2Descriptor] = []
    seen_ids = set()
    try:
        for pcsc_desc in list_pcsc_descriptors():
            candidate = Solo2Device(
                Solo2Descriptor(
                    id=f"ccid:{pcsc_desc.reader}",
                    mode=DeviceMode.REGULAR,
                    path=f"ccid:{pcsc_desc.reader}",
                    transport="ccid",
                    reader_name=pcsc_desc.reader,
                )
            )
            if candidate.connect():
                if candidate.path in seen_ids:
                    continue
                descriptors.append(candidate.descriptor)
                seen_ids.add(candidate.path)
                candidate.disconnect()
    except Exception as exc:
        _log.debug("_list_ccid_regular_descriptors failed: %s", exc)
    return descriptors


def list_regular_descriptors() -> List[Solo2Descriptor]:
    """Discover regular-mode Solo 2 devices and return stable descriptors."""
    hid_descriptors = _list_hid_regular_descriptors()
    if hid_descriptors:
        # On Windows, probing CCID during background discovery can cause the
        # SmartCard stack to flap and make the GUI think the token vanished.
        # Prefer HID for presence detection and keep PC/SC for the applet tabs.
        return hid_descriptors

    if should_prefer_ccid():
        return _list_ccid_regular_descriptors()

    return hid_descriptors


def list_bootloader_descriptors() -> List[Solo2Descriptor]:
    """Discover Solo 2 bootloader devices."""
    try:
        devices = list(
            usb.core.find(
                idVendor=Solo2Device.SOLOKEYS_VID,
                idProduct=Solo2Device.BOOTLOADER_PID,
                find_all=True,
            )
            or []
        )
    except Exception as exc:
        _log.debug("list_bootloader_descriptors failed: %s", exc)
        devices = []

    return [
        Solo2Descriptor(
            id=f"{dev.bus}-{dev.address}",
            mode=DeviceMode.BOOTLOADER,
            path=f"{dev.bus}-{dev.address}",
            transport="bootloader",
        )
        for dev in devices
    ]


def list_descriptors() -> List[Solo2Descriptor]:
    """List all currently discoverable Solo 2 devices."""
    return list_regular_descriptors() + list_bootloader_descriptors()


def list_devices() -> List[Solo2Descriptor]:
    """Public alias for device discovery."""
    return list_descriptors()


def open_device(descriptor_or_id: Solo2Descriptor | str) -> Solo2Device:
    """Open a regular Solo 2 device from a descriptor or stable ID."""
    if isinstance(descriptor_or_id, Solo2Descriptor):
        device = Solo2Device.from_descriptor(descriptor_or_id)
    else:
        match = next(
            (descriptor for descriptor in list_regular_descriptors() if descriptor.id == descriptor_or_id),
            None,
        )
        if match is None:
            raise RuntimeError(f"Solo 2 device not found: {descriptor_or_id}")
        device = Solo2Device.from_descriptor(match)
    if not device.connect():
        raise RuntimeError(f"Failed to connect to Solo 2 device: {device.path}")
    return device


def open_bootloader(descriptor_or_id: Solo2Descriptor | str) -> Solo2Device:
    """Open a bootloader-mode Solo 2 device from a descriptor or stable ID."""
    if isinstance(descriptor_or_id, Solo2Descriptor):
        device = Solo2Device.from_descriptor(descriptor_or_id)
    else:
        match = next(
            (descriptor for descriptor in list_bootloader_descriptors() if descriptor.id == descriptor_or_id),
            None,
        )
        if match is None:
            raise RuntimeError(f"Solo 2 bootloader not found: {descriptor_or_id}")
        device = Solo2Device.from_descriptor(match)
    if not device.connect():
        raise RuntimeError(f"Failed to connect to Solo 2 bootloader: {device.path}")
    return device


@dataclass
class DeviceSnapshot:
    """Snapshot of discovered devices keyed by their stable id."""

    descriptors: Dict[str, Solo2Descriptor]

    @classmethod
    def capture(cls) -> "DeviceSnapshot":
        items = {descriptor.id: descriptor for descriptor in list_descriptors()}
        return cls(items)


class DeviceWatcher:
    """Polling helper that reports added and removed Solo 2 descriptors."""

    def __init__(self):
        self._snapshot = DeviceSnapshot.capture()

    def poll(self) -> tuple[Sequence[Solo2Descriptor], Sequence[Solo2Descriptor]]:
        current = DeviceSnapshot.capture()
        added = [
            descriptor
            for device_id, descriptor in current.descriptors.items()
            if device_id not in self._snapshot.descriptors
        ]
        removed = [
            descriptor
            for device_id, descriptor in self._snapshot.descriptors.items()
            if device_id not in current.descriptors
        ]
        self._snapshot = current
        return added, removed

    def refresh(
        self,
        on_added: Callable[[Solo2Descriptor], None] | None = None,
        on_removed: Callable[[Solo2Descriptor], None] | None = None,
    ) -> tuple[Sequence[Solo2Descriptor], Sequence[Solo2Descriptor]]:
        added, removed = self.poll()
        if on_added is not None:
            for descriptor in added:
                on_added(descriptor)
        if on_removed is not None:
            for descriptor in removed:
                on_removed(descriptor)
        return added, removed
