"""High-level Provisioner operations for Solo 2 Hacker devices."""

from __future__ import annotations

from dataclasses import dataclass

from .device import Solo2Device
from .errors import Solo2CommandError, Solo2TransportError

try:
    from smartcard.System import readers
    from smartcard.Exceptions import CardConnectionException, NoCardException

    PCSC_AVAILABLE = True
except ImportError:
    readers = None
    CardConnectionException = Exception
    NoCardException = Exception
    PCSC_AVAILABLE = False


PROVISION_AID = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x01, 0x00, 0x00, 0x01]
INS_SELECT = 0xA4
INS_GEN_ED25519 = 0xBB
INS_GEN_P256 = 0xBC
INS_GEN_X25519 = 0xB7
INS_STORE_ED25519_CERT = 0xB9
INS_STORE_P256_CERT = 0xBA
INS_STORE_X25519_CERT = 0xB6
INS_STORE_T1_PUBKEY = 0xB5
INS_REFORMAT_FS = 0xBD
INS_WRITE_FILE = 0xBF

KEY_TYPES = {
    "ed25519": (INS_GEN_ED25519, INS_STORE_ED25519_CERT, 32),
    "p256": (INS_GEN_P256, INS_STORE_P256_CERT, 64),
    "x25519": (INS_GEN_X25519, INS_STORE_X25519_CERT, 32),
}


@dataclass
class GeneratedKey:
    """Provisioner-generated public key material."""

    key_type: str
    public_key: bytes


class ProvisionerSession:
    """Synchronous provisioner session via PC/SC."""

    def __init__(self, device: Solo2Device):
        self._device = device
        self._connection = None

    def _connect_pcsc(self) -> None:
        if not PCSC_AVAILABLE:
            raise Solo2TransportError("PCSC not available")
        if readers is None:
            raise Solo2TransportError("PCSC readers unavailable")

        try:
            reader_list = readers()
        except Exception as exc:
            raise Solo2TransportError(f"Failed to list PCSC readers: {exc}") from exc

        if not reader_list:
            raise Solo2TransportError("No PCSC readers found")

        select_variants = [
            [0x00, INS_SELECT, 0x04, 0x00, len(PROVISION_AID)] + PROVISION_AID,
            [0x00, INS_SELECT, 0x04, 0x00, len(PROVISION_AID)] + PROVISION_AID + [0x00],
        ]
        last_error = "Provision applet not found"

        for reader in reader_list:
            try:
                connection = reader.createConnection()
                connection.connect()
                for select_cmd in select_variants:
                    response, sw1, sw2 = connection.transmit(select_cmd)
                    if sw1 == 0x90 and sw2 == 0x00:
                        self._connection = connection
                        return
                    last_error = (
                        f"Provision SELECT failed on '{reader}': SW={sw1:02X}{sw2:02X}"
                    )
                try:
                    connection.disconnect()
                except Exception:
                    pass
            except NoCardException:
                last_error = f"No card in '{reader}'"
            except CardConnectionException as exc:
                last_error = f"Connection failed on '{reader}': {exc}"
            except Exception as exc:
                last_error = f"Error on '{reader}': {exc}"

        raise Solo2TransportError(last_error)

    def close(self) -> None:
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
            self._connection = None

    def _send_apdu(
        self, ins: int, p1: int = 0, p2: int = 0, data: bytes = b""
    ) -> bytes:
        if self._connection is None:
            self._connect_pcsc()
        if self._connection is None:
            raise Solo2TransportError("Provisioner not connected")

        apdu = [0x00, ins, p1, p2]
        if data:
            apdu.append(len(data))
            apdu.extend(data)
        apdu.append(0x00)

        response, sw1, sw2 = self._connection.transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            return bytes(response)
        raise Solo2CommandError(f"APDU failed: {sw1:02X}{sw2:02X}")

    def generate_key(self, key_type: str) -> GeneratedKey:
        info = KEY_TYPES.get(key_type)
        if not info:
            raise Solo2CommandError(f"Unknown key type: {key_type}")
        gen_ins, _, expected_len = info
        try:
            result = self._send_apdu(gen_ins)
            return GeneratedKey(key_type=key_type, public_key=result[:expected_len])
        finally:
            self.close()

    def store_certificate(self, key_type: str, der_data: bytes) -> None:
        info = KEY_TYPES.get(key_type)
        if not info:
            raise Solo2CommandError(f"Unknown key type: {key_type}")
        _, store_ins, _ = info
        try:
            self._send_apdu(store_ins, data=der_data)
        finally:
            self.close()

    def store_t1_pubkey(self, pubkey_bytes: bytes) -> None:
        if len(pubkey_bytes) != 32:
            raise Solo2CommandError("T1 public key must be exactly 32 bytes")
        try:
            self._send_apdu(INS_STORE_T1_PUBKEY, data=pubkey_bytes)
        finally:
            self.close()

    def reformat_filesystem(self) -> None:
        try:
            self._send_apdu(INS_REFORMAT_FS)
        finally:
            self.close()

    def write_file(self, path: str, data: bytes) -> None:
        path_bytes = path.encode("utf-8")
        if len(path_bytes) > 255:
            raise Solo2CommandError("File path too long")
        payload = bytes([len(path_bytes)]) + path_bytes + data
        try:
            self._send_apdu(INS_WRITE_FILE, data=payload)
        finally:
            self.close()
