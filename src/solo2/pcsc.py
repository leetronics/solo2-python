"""PC/SC transport helpers for Solo 2 applets."""

from __future__ import annotations

import ctypes
import logging
import sys
from dataclasses import dataclass
from typing import Optional

_log = logging.getLogger("solo2device")

try:
    from smartcard.System import readers
    from smartcard.Exceptions import CardConnectionException, NoCardException
    from smartcard.CardConnection import CardConnection as _CardConnection

    PCSC_AVAILABLE = True
except ImportError as exc:  # pragma: no cover - depends on platform packaging
    readers = None
    CardConnectionException = Exception
    NoCardException = Exception
    _CardConnection = None
    PCSC_AVAILABLE = False
    _log.debug("PCSC import failed: %s", exc)


SECRETS_AID = bytes.fromhex("A0000005272101")
ADMIN_AID = bytes.fromhex("A00000084700000001")
SW_SUCCESS = (0x90, 0x00)


def pcsc_available() -> bool:
    return PCSC_AVAILABLE


def is_windows_non_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return not bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def should_prefer_ccid() -> bool:
    """Mirror Nitrokey App2 policy: Windows non-admin prefers CCID if available."""
    return is_windows_non_admin() and pcsc_available()


def _build_apdu(cla: int, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"", le: int | None = None) -> bytes:
    apdu = bytearray([cla, ins, p1, p2])
    if data:
        if len(data) <= 255:
            apdu.extend((len(data),))
        else:
            apdu.extend((0x00, (len(data) >> 8) & 0xFF, len(data) & 0xFF))
        apdu.extend(data)
    if le is not None:
        if data:
            if le <= 255:
                apdu.append(le)
            else:
                apdu.extend(((le >> 8) & 0xFF, le & 0xFF))
        elif le <= 255:
            apdu.append(le)
        else:
            apdu.extend((0x00, (le >> 8) & 0xFF, le & 0xFF))
    return bytes(apdu)


@dataclass
class PcscDescriptor:
    reader: str


class Solo2PcscConnection:
    """Minimal PC/SC connection wrapper with SELECT and GET RESPONSE handling."""

    def __init__(self, connection, reader_name: str):
        self._connection = connection
        self.reader_name = reader_name
        self._selected_aid: bytes | None = None

    def close(self) -> None:
        try:
            self._connection.disconnect()
        except Exception:
            pass
        self._selected_aid = None

    def _transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        data, sw1, sw2 = self._connection.transmit(list(apdu))
        return bytes(data), sw1, sw2

    def _transmit_all(self, apdu: bytes) -> tuple[bytes, int, int]:
        payload, sw1, sw2 = self._transmit(apdu)
        out = bytearray(payload)
        while sw1 == 0x61:
            more, sw1, sw2 = self._transmit(_build_apdu(0x00, 0xC0, 0, 0, b"", sw2 or 0))
            out.extend(more)
        return bytes(out), sw1, sw2

    def select(self, aid: bytes) -> bytes:
        payload, sw1, sw2 = self._transmit_all(_build_apdu(0x00, 0xA4, 0x04, 0x00, aid))
        if (sw1, sw2) != SW_SUCCESS:
            raise RuntimeError(f"SELECT failed on {self.reader_name}: SW={sw1:02X}{sw2:02X}")
        self._selected_aid = aid
        return payload

    def _transmit_selected(self, aid: bytes, apdu: bytes) -> tuple[bytes, int, int]:
        """Transmit an APDU against a selected applet, retrying once on transient 6F00."""
        if self._selected_aid != aid:
            self.select(aid)

        payload, sw1, sw2 = self._transmit_all(apdu)
        if (sw1, sw2) == (0x6F, 0x00):
            _log.debug(
                "PCSC transient 6F00 on reader=%s aid=%s, retrying after reselect",
                self.reader_name,
                aid.hex(),
            )
            self._selected_aid = None
            self.select(aid)
            payload, sw1, sw2 = self._transmit_all(apdu)
        return payload, sw1, sw2

    def call_secrets(self, apdu: bytes) -> bytes:
        payload, sw1, sw2 = self._transmit_selected(SECRETS_AID, apdu)
        return bytes([sw1, sw2]) + payload

    def call_admin(self, command: int, data: bytes = b"", response_len: Optional[int] = None) -> bytes:
        p1 = data[0] if data else 0x00
        body, sw1, sw2 = self._transmit_selected(
            ADMIN_AID,
            _build_apdu(0x00, command, 0x00, p1, data, response_len),
        )
        if (sw1, sw2) != SW_SUCCESS:
            raise RuntimeError(f"Admin command 0x{command:02X} failed: SW={sw1:02X}{sw2:02X}")
        return body


def _connect_reader(reader) -> Solo2PcscConnection | None:
    protocols = []
    if _CardConnection is not None:
        protocols.append(_CardConnection.T1_protocol)
    protocols.append(None)

    for protocol in protocols:
        try:
            connection = reader.createConnection()
            if protocol is None:
                connection.connect()
            else:
                connection.connect(protocol)
            return Solo2PcscConnection(connection, str(reader))
        except (NoCardException, CardConnectionException, OSError) as exc:
            _log.debug("PCSC connect failed reader=%s protocol=%s err=%s", reader, protocol, exc)
        except Exception as exc:
            _log.debug("PCSC unexpected connect failure reader=%s protocol=%s err=%s", reader, protocol, exc)
    return None


def _iter_connections():
    if not PCSC_AVAILABLE:
        return
    try:
        reader_list = readers()
    except Exception as exc:
        _log.debug("PCSC readers() failed: %s", exc)
        return
    for reader in reader_list:
        connection = _connect_reader(reader)
        if connection is not None:
            yield connection


def list_pcsc_descriptors() -> list[PcscDescriptor]:
    descriptors: list[PcscDescriptor] = []
    for connection in _iter_connections():
        try:
            connection.select(ADMIN_AID)
            descriptors.append(PcscDescriptor(reader=connection.reader_name))
            _log.debug("PCSC admin app detected on reader=%s", connection.reader_name)
        except Exception as exc:
            _log.debug("PCSC reader skipped reader=%s err=%s", connection.reader_name, exc)
        finally:
            connection.close()
    return descriptors


def open_pcsc_connection(*, secrets: bool = False, admin: bool = False) -> Solo2PcscConnection:
    last_error: Exception | None = None
    probe_aid = SECRETS_AID if secrets else ADMIN_AID
    for connection in _iter_connections():
        try:
            connection.select(probe_aid)
            return connection
        except Exception as exc:
            last_error = exc
            connection.close()
    if last_error is not None:
        raise RuntimeError(str(last_error))
    raise RuntimeError("No SoloKeys PC/SC reader found")
