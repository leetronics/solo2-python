"""Secrets/OATH support for Solo 2 devices."""

from __future__ import annotations

import base64
import os
import re
import struct
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Optional, Union

from .device import Solo2Device
from .errors import (
    Solo2CommandError,
    Solo2PinRequiredError,
    Solo2TouchRequiredError,
    Solo2TransportError,
    Solo2WrongPinError,
)

PASSWORD_ONLY_PREFIX = "__solo_pw__:"
HMAC_SLOT_NAMES = {
    1: "HmacSlot1",
    2: "HmacSlot2",
}
HMAC_SLOT_NUMBERS = tuple(sorted(HMAC_SLOT_NAMES))
HMAC_SECRET_LENGTH = 20

# Backward-compatible aliases for the common KeePassXC default.
KEEPASSXC_HMAC_SLOT = 2
KEEPASSXC_HMAC_NAME = HMAC_SLOT_NAMES[KEEPASSXC_HMAC_SLOT]
KEEPASSXC_HMAC_SECRET_LENGTH = HMAC_SECRET_LENGTH


def encode_password_only_label(name: str) -> bytes:
    return f"{PASSWORD_ONLY_PREFIX}{name}".encode("utf-8")


def strip_password_only_label(name: str) -> str:
    if name.startswith(PASSWORD_ONLY_PREFIX):
        return name[len(PASSWORD_ONLY_PREFIX):]
    return name


def is_password_only_label(label: bytes | str) -> bool:
    if isinstance(label, bytes):
        return label.startswith(PASSWORD_ONLY_PREFIX.encode("utf-8"))
    return label.startswith(PASSWORD_ONLY_PREFIX)


class OtpKind(Enum):
    """OTP credential types."""

    TOTP = auto()
    HOTP = auto()

    def __str__(self) -> str:
        return self.name


class OtherKind(Enum):
    """Other credential types supported by the secrets app."""

    HMAC = auto()
    REVERSE_HOTP = auto()

    def __str__(self) -> str:
        return self.name


CredentialKind = Union[OtpKind, OtherKind]


class Algorithm(Enum):
    """Hash algorithms for OTP generation."""

    SHA1 = 1
    SHA256 = 2
    SHA512 = 3


@dataclass
class Credential:
    """Credential information for the secrets app."""

    id: bytes
    otp: Optional[OtpKind] = None
    other: Optional[OtherKind] = None
    algorithm: Algorithm = Algorithm.SHA1
    digits: int = 6
    period: int = 30
    login: Optional[bytes] = None
    password: Optional[bytes] = None
    metadata: Optional[bytes] = None
    touch_required: bool = False
    protected: bool = False
    encrypted: bool = False
    has_password_safe: bool = False

    @property
    def name(self) -> str:
        return strip_password_only_label(self.id.decode("utf-8", errors="replace"))

    @property
    def password_only(self) -> bool:
        return self.has_password_safe and is_password_only_label(self.id)

    @property
    def is_otp(self) -> bool:
        return self.otp is not None and not self.password_only

    @property
    def kind_name(self) -> str:
        if self.password_only:
            return "Password"
        if self.otp is not None:
            return str(self.otp)
        if self.other is not None:
            return str(self.other)
        return "UNKNOWN"

    @property
    def algorithm_name(self) -> str:
        return self.algorithm.name


@dataclass
class OtpResult:
    """Generated OTP result."""

    credential: Credential
    code: str
    counter: Optional[int] = None
    remaining_seconds: int = 0


@dataclass
class SecretsAppStatus:
    """Status information from the secrets app."""

    supported: bool
    version: str
    pin_set: bool | None
    pin_attempts_remaining: Optional[int]
    credentials_count: int
    max_credentials: int


@dataclass
class HmacSlotInfo:
    """Status for the KeePassXC-compatible HMAC challenge-response slot."""

    slot: int
    name: str
    configured: bool
    touch_required: bool = False
    pin_protected: bool = False


class SecretsAppProtocol:
    """OATH protocol constants and helpers."""

    VENDOR_CMD = 0x70

    INS_PUT = 0x01
    INS_DELETE = 0x02
    INS_SET_CODE = 0x03
    INS_RESET = 0x04
    INS_LIST = 0xA1
    INS_CALCULATE = 0xA2
    INS_VALIDATE = 0xA3
    INS_CALCULATE_ALL = 0xA4
    INS_SEND_REMAINING = 0xA5
    INS_VERIFY_CODE = 0xB1
    INS_VERIFY_PIN = 0xB2
    INS_CHANGE_PIN = 0xB3
    INS_SET_PIN = 0xB4
    INS_GET_CREDENTIAL = 0xB5
    INS_UPDATE_CREDENTIAL = 0xB7
    INS_YK_API_REQUEST = 0x01

    TAG_NAME = 0x71
    TAG_NAME_LIST = 0x72
    TAG_KEY = 0x73
    TAG_CHALLENGE = 0x74
    TAG_RESPONSE = 0x76
    TAG_PROPERTY = 0x78
    TAG_PASSWORD = 0x80
    TAG_NEW_PASSWORD = 0x81
    TAG_PWS_LOGIN = 0x83
    TAG_PWS_PASSWORD = 0x84
    TAG_PWS_METADATA = 0x85

    PROP_TOUCH_REQUIRED = 0x02
    PROP_PIN_ENCRYPTED = 0x04

    KIND_TOTP = 0x20
    KIND_HOTP = 0x10
    KIND_REVERSE_HOTP = 0x30
    KIND_HMAC = 0x40

    SW_SUCCESS = 0x9000
    SW_TOUCH_REQUIRED = 0x6985
    SW_PIN_REQUIRED = 0x6982
    SW_PIN_BLOCKED = 0x6983
    SW_NOT_FOUND = 0x6A82
    SW_MORE_DATA_MASK = 0x6100
    SW_WRONG_PIN_MASK = 0x63C0

    @classmethod
    def parse_status(cls, response: bytes) -> tuple[int, int, bytes]:
        if len(response) < 2:
            return (0x6F, 0x00, b"")
        potential_sw1 = response[0]
        if potential_sw1 in (0x90, 0x61, 0x6A, 0x69, 0x63):
            sw1, sw2 = response[0], response[1]
            data = response[2:] if len(response) > 2 else b""
        else:
            sw1, sw2 = response[-2], response[-1]
            data = response[:-2] if len(response) > 2 else b""
        return (sw1, sw2, data)


def _algorithm_from_nibble(nibble: int) -> Algorithm:
    return {
        0x01: Algorithm.SHA1,
        0x02: Algorithm.SHA256,
        0x03: Algorithm.SHA512,
    }.get(nibble, Algorithm.SHA1)


def _algorithm_to_nibble(algorithm: Algorithm) -> int:
    return {
        Algorithm.SHA1: 0x01,
        Algorithm.SHA256: 0x02,
        Algorithm.SHA512: 0x03,
    }.get(algorithm, 0x01)


def normalize_hmac_secret(secret: bytes | bytearray | str) -> bytes:
    """Normalize a KeePassXC-compatible HMAC secret to 20 raw bytes."""

    if isinstance(secret, (bytes, bytearray)):
        secret_bytes = bytes(secret)
    else:
        compact = re.sub(r"[\s-]+", "", secret).strip()
        if not compact:
            raise Solo2CommandError("HMAC secret is required")
        try:
            if re.fullmatch(r"[0-9a-fA-F]+", compact):
                if len(compact) % 2:
                    raise Solo2CommandError("Hex HMAC secret must have an even number of characters")
                secret_bytes = bytes.fromhex(compact)
            else:
                padding = "=" * ((8 - len(compact) % 8) % 8)
                secret_bytes = base64.b32decode(compact.upper() + padding, casefold=True)
        except Solo2CommandError:
            raise
        except Exception as exc:
            raise Solo2CommandError(f"Invalid HMAC secret: {exc}") from exc

    if len(secret_bytes) != HMAC_SECRET_LENGTH:
        raise Solo2CommandError(
            f"HMAC secret must be exactly {HMAC_SECRET_LENGTH} bytes"
        )
    return secret_bytes


def _hmac_slot_name(slot: int) -> str:
    try:
        return HMAC_SLOT_NAMES[slot]
    except KeyError as exc:
        joined = ", ".join(str(number) for number in HMAC_SLOT_NUMBERS)
        raise Solo2CommandError(f"Only HMAC slots {joined} are supported") from exc


class SecretsSession:
    """Synchronous secrets session backed by a device or a raw APDU transport."""

    def __init__(
        self,
        device: Solo2Device | None = None,
        *,
        transport: Callable[[bytes], bytes] | None = None,
    ):
        if device is None and transport is None:
            raise ValueError("device or transport is required")
        self._device = device
        self._transport = transport

    @staticmethod
    def _build_tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value

    @staticmethod
    def _parse_tlv(data: bytes) -> list[tuple[int, bytes]]:
        items: list[tuple[int, bytes]] = []
        offset = 0
        while offset + 2 <= len(data):
            tag = data[offset]
            length = data[offset + 1]
            value = data[offset + 2 : offset + 2 + length]
            items.append((tag, value))
            offset += 2 + length
        return items

    @staticmethod
    def _name_candidates(name: str) -> list[str]:
        candidates = [name]
        if not is_password_only_label(name):
            candidates.append(f"{PASSWORD_ONLY_PREFIX}{name}")
        return candidates

    def _raw_send(self, apdu: bytes) -> bytes:
        if self._transport is not None:
            try:
                return bytes(self._transport(apdu))
            except Exception as exc:
                raise Solo2TransportError(str(exc)) from exc
        if self._device is None:
            raise Solo2TransportError("No device transport configured")
        try:
            return self._device.secrets().send_apdu(apdu)
        except Exception as exc:
            raise Solo2TransportError(str(exc)) from exc

    @staticmethod
    def _build_apdu(ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> bytes:
        apdu = bytes([0x00, ins, p1, p2])
        if data:
            if len(data) <= 255:
                apdu += bytes([len(data)]) + data
            else:
                apdu += bytes([0x00, (len(data) >> 8) & 0xFF, len(data) & 0xFF]) + data
        return apdu

    def _raise_for_sw(self, sw: int) -> None:
        if sw == SecretsAppProtocol.SW_TOUCH_REQUIRED:
            raise Solo2TouchRequiredError("Touch required")
        if sw == SecretsAppProtocol.SW_PIN_REQUIRED:
            raise Solo2PinRequiredError("PIN required")
        if sw == SecretsAppProtocol.SW_PIN_BLOCKED:
            raise Solo2CommandError("PIN blocked")
        if sw == SecretsAppProtocol.SW_NOT_FOUND:
            raise Solo2CommandError("Credential not found")
        if (sw & 0xFFF0) == SecretsAppProtocol.SW_WRONG_PIN_MASK:
            attempts = sw & 0x0F
            raise Solo2WrongPinError(
                f"Wrong PIN ({attempts} retries left)",
                attempts_remaining=attempts,
            )
        raise Solo2CommandError(f"APDU error: 0x{sw:04X}")

    def _send_apdu(self, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> bytes:
        raw = self._raw_send(self._build_apdu(ins, p1, p2, data))
        if len(raw) < 2:
            raise Solo2TransportError(f"Response too short: {raw.hex()}")
        sw = (raw[0] << 8) | raw[1]
        if sw == SecretsAppProtocol.SW_SUCCESS:
            return raw[2:]
        if (sw & 0xFF00) == SecretsAppProtocol.SW_MORE_DATA_MASK:
            return raw[2:]
        self._raise_for_sw(sw)

    def _send_apdu_all(
        self, ins: int, p1: int = 0, p2: int = 0, data: bytes = b""
    ) -> bytes:
        all_data = b""
        current_apdu = self._build_apdu(ins, p1, p2, data)
        while True:
            raw = self._raw_send(current_apdu)
            if len(raw) < 2:
                raise Solo2TransportError(f"Response too short: {raw.hex()}")
            sw = (raw[0] << 8) | raw[1]
            all_data += raw[2:]
            if sw == SecretsAppProtocol.SW_SUCCESS:
                break
            if (sw & 0xFF00) == SecretsAppProtocol.SW_MORE_DATA_MASK:
                current_apdu = self._build_apdu(SecretsAppProtocol.INS_SEND_REMAINING)
                continue
            self._raise_for_sw(sw)
        return all_data

    def get_status(self) -> SecretsAppStatus:
        oath_aid = bytes.fromhex("A0000005272101")
        select_apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(oath_aid)]) + oath_aid
        pin_set = False
        pin_attempts: int | None = None

        try:
            raw = self._raw_send(select_apdu)
            sw1, sw2, payload = SecretsAppProtocol.parse_status(raw)
            sw = (sw1 << 8) | sw2
            if sw == SecretsAppProtocol.SW_NOT_FOUND:
                return SecretsAppStatus(False, "0.0.0", False, None, 0, 50)
            if sw == SecretsAppProtocol.SW_SUCCESS:
                offset = 0
                while offset + 2 <= len(payload):
                    tag = payload[offset]
                    length = payload[offset + 1]
                    value = payload[offset + 2 : offset + 2 + length]
                    offset += 2 + length
                    if tag == 0x79 and length >= 3:
                        version = ".".join(str(part) for part in value[:3])
                    elif tag == 0x82 and length >= 1:
                        pin_set = True
                        pin_attempts = value[0]
                try:
                    credentials = self.list_credentials()
                    cred_count = len(credentials)
                except Solo2PinRequiredError:
                    cred_count = 0
                    pin_set = True
                except Exception:
                    cred_count = 0
                return SecretsAppStatus(True, locals().get("version", "1.0.0"), pin_set, pin_attempts, cred_count, 50)
        except Solo2TransportError:
            pass

        try:
            credentials = self.list_credentials()
            return SecretsAppStatus(True, "1.0.0", pin_set or None, pin_attempts, len(credentials), 50)
        except Solo2PinRequiredError:
            return SecretsAppStatus(True, "1.0.0", True, pin_attempts, 0, 50)
        except Exception:
            return SecretsAppStatus(False, "0.0.0", False, None, 0, 50)

    def list_credentials(self) -> list[Credential]:
        payload = self._send_apdu_all(SecretsAppProtocol.INS_LIST, data=bytes([0x01]))
        credentials: list[Credential] = []
        offset = 0
        while offset < len(payload):
            if payload[offset] != SecretsAppProtocol.TAG_NAME_LIST:
                break
            offset += 1
            if offset >= len(payload):
                break
            entry_len = payload[offset]
            offset += 1
            if offset + entry_len > len(payload) or entry_len < 1:
                break

            kind_algo = payload[offset]
            offset += 1
            kind = kind_algo & 0xF0
            otp_kind = None
            other_kind = None
            if kind == SecretsAppProtocol.KIND_TOTP:
                otp_kind = OtpKind.TOTP
            elif kind == SecretsAppProtocol.KIND_HOTP:
                otp_kind = OtpKind.HOTP
            elif kind == SecretsAppProtocol.KIND_REVERSE_HOTP:
                other_kind = OtherKind.REVERSE_HOTP
            elif kind == SecretsAppProtocol.KIND_HMAC:
                other_kind = OtherKind.HMAC

            algorithm = _algorithm_from_nibble(kind_algo & 0x0F)
            remaining_len = entry_len - 1
            entry_data = payload[offset : offset + remaining_len]
            offset += remaining_len

            touch_required = False
            protected = False
            has_password_safe = False
            label_bytes = entry_data
            if remaining_len >= 1:
                properties = entry_data[-1]
                label_bytes = entry_data[:-1]
                touch_required = bool(properties & 0x01)
                protected = bool(properties & 0x02)
                has_password_safe = bool(properties & 0x04)

            credentials.append(
                Credential(
                    id=label_bytes,
                    otp=otp_kind,
                    other=other_kind,
                    algorithm=algorithm,
                    touch_required=touch_required,
                    protected=protected,
                    encrypted=protected,
                    has_password_safe=has_password_safe,
                )
            )
        return credentials

    def serialize_credential(self, credential: Credential) -> dict:
        return {
            "name": credential.name,
            "rawName": credential.id.decode("utf-8", errors="replace"),
            "type": credential.kind_name.upper(),
            "kind": credential.kind_name,
            "algorithm": credential.algorithm_name,
            "digits": credential.digits,
            "touchRequired": credential.touch_required,
            "pinEncrypted": credential.encrypted,
            "hasPasswordSafe": credential.has_password_safe,
            "passwordOnly": credential.password_only,
        }

    def list_credentials_dicts(self) -> list[dict]:
        return [self.serialize_credential(credential) for credential in self.list_credentials()]

    def list_hmac_slots(self) -> list[HmacSlotInfo]:
        return [self.get_hmac_slot(slot) for slot in HMAC_SLOT_NUMBERS]

    def get_hmac_slot(self, slot: int = KEEPASSXC_HMAC_SLOT) -> HmacSlotInfo:
        name = _hmac_slot_name(slot)
        target = next(
            (
                credential
                for credential in self.list_credentials()
                if credential.other == OtherKind.HMAC and credential.name == name
            ),
            None,
        )
        if target is None:
            return HmacSlotInfo(slot=slot, name=name, configured=False)
        return HmacSlotInfo(
            slot=slot,
            name=name,
            configured=True,
            touch_required=target.touch_required,
            pin_protected=target.protected,
        )

    def generate_hmac_secret(self) -> bytes:
        return os.urandom(HMAC_SECRET_LENGTH)

    def configure_hmac_slot(
        self,
        slot: int,
        secret: bytes | bytearray | str,
        *,
        overwrite: bool = False,
    ) -> HmacSlotInfo:
        name = _hmac_slot_name(slot)
        secret_bytes = normalize_hmac_secret(secret)
        current = self.get_hmac_slot(slot)
        if current.configured and not overwrite:
            raise Solo2CommandError(
                f"{name} is already configured; pass overwrite=True to replace it"
            )
        if current.configured:
            self.delete_hmac_slot(slot)

        credential = Credential(
            id=name.encode("utf-8"),
            other=OtherKind.HMAC,
            algorithm=Algorithm.SHA1,
            digits=HMAC_SECRET_LENGTH,
            touch_required=False,
            protected=False,
            encrypted=False,
            has_password_safe=False,
        )
        self.add_credential(credential, secret_bytes)
        return self.get_hmac_slot(slot)

    def delete_hmac_slot(self, slot: int) -> None:
        name = _hmac_slot_name(slot)
        current = self.get_hmac_slot(slot)
        if not current.configured:
            raise Solo2CommandError(f"{name} is not configured")
        self.delete_credential(name)

    def add_credential(self, credential: Credential, secret: bytes) -> None:
        payload = bytearray()
        payload.extend(self._build_tlv(SecretsAppProtocol.TAG_NAME, credential.id))

        kind_algo = _algorithm_to_nibble(credential.algorithm)
        if credential.otp == OtpKind.TOTP:
            kind_algo |= SecretsAppProtocol.KIND_TOTP
        elif credential.otp == OtpKind.HOTP:
            kind_algo |= SecretsAppProtocol.KIND_HOTP
        elif credential.other == OtherKind.REVERSE_HOTP:
            kind_algo |= SecretsAppProtocol.KIND_REVERSE_HOTP
        elif credential.other == OtherKind.HMAC:
            kind_algo |= SecretsAppProtocol.KIND_HMAC
        else:
            kind_algo |= SecretsAppProtocol.KIND_TOTP

        key_data = bytes([kind_algo, credential.digits]) + secret
        payload.extend(self._build_tlv(SecretsAppProtocol.TAG_KEY, key_data))

        if credential.touch_required or credential.protected:
            properties = 0
            if credential.touch_required:
                properties |= SecretsAppProtocol.PROP_TOUCH_REQUIRED
            if credential.protected:
                properties |= SecretsAppProtocol.PROP_PIN_ENCRYPTED
            payload.extend(bytes([SecretsAppProtocol.TAG_PROPERTY, properties]))

        if credential.otp == OtpKind.HOTP:
            payload.extend(bytes([0x7A, 0x04, 0x00, 0x00, 0x00, 0x00]))

        if credential.login is not None:
            payload.extend(self._build_tlv(SecretsAppProtocol.TAG_PWS_LOGIN, credential.login))
        if credential.password is not None:
            payload.extend(self._build_tlv(SecretsAppProtocol.TAG_PWS_PASSWORD, credential.password))
        if credential.metadata is not None:
            payload.extend(self._build_tlv(SecretsAppProtocol.TAG_PWS_METADATA, credential.metadata))

        self._send_apdu(SecretsAppProtocol.INS_PUT, data=bytes(payload))

    def delete_credential(self, credential: Credential | str) -> None:
        if isinstance(credential, Credential):
            names = [credential.id.decode("utf-8", errors="replace")]
        else:
            names = self._name_candidates(credential)

        last_error: Exception | None = None
        for candidate in names:
            try:
                payload = self._build_tlv(
                    SecretsAppProtocol.TAG_NAME,
                    candidate.encode("utf-8"),
                )
                self._send_apdu(SecretsAppProtocol.INS_DELETE, data=payload)
                return
            except Exception as exc:
                last_error = exc
        if last_error is not None:
            raise last_error

    def generate_otp(self, credential: Credential) -> OtpResult:
        payload = bytearray()
        payload.extend(self._build_tlv(SecretsAppProtocol.TAG_NAME, credential.id))
        if credential.otp == OtpKind.TOTP:
            challenge = struct.pack(">Q", int(time.time()) // credential.period)
        else:
            challenge = struct.pack(">Q", 0)
        payload.extend(self._build_tlv(SecretsAppProtocol.TAG_CHALLENGE, challenge))
        response = self._send_apdu(
            SecretsAppProtocol.INS_CALCULATE,
            p1=0x00,
            p2=0x01,
            data=bytes(payload),
        )

        digits: int
        code_bytes: bytes
        if len(response) >= 7 and response[0] == SecretsAppProtocol.TAG_RESPONSE:
            digits = response[2]
            code_bytes = response[3:7]
        elif len(response) >= 5:
            digits = response[0]
            code_bytes = response[1:5]
        else:
            raise Solo2CommandError(f"Invalid OTP response format: {response.hex()}")

        code_value = int.from_bytes(code_bytes, "big") % (10**digits)
        remaining_seconds = (
            credential.period - int(time.time()) % credential.period
            if credential.otp == OtpKind.TOTP
            else 0
        )
        return OtpResult(
            credential=credential,
            code=str(code_value).zfill(digits),
            remaining_seconds=remaining_seconds,
        )

    def get_credential(self, credential: Credential | str) -> Credential:
        if isinstance(credential, Credential):
            names = [credential.id.decode("utf-8", errors="replace")]
            base = credential
        else:
            names = self._name_candidates(credential)
            base = Credential(id=credential.encode("utf-8"))

        last_error: Exception | None = None
        for candidate in names:
            try:
                payload = self._build_tlv(
                    SecretsAppProtocol.TAG_NAME, candidate.encode("utf-8")
                )
                response = self._send_apdu_all(SecretsAppProtocol.INS_GET_CREDENTIAL, data=payload)
                data = Credential(
                    id=base.id,
                    otp=base.otp,
                    other=base.other,
                    algorithm=base.algorithm,
                    digits=base.digits,
                    period=base.period,
                    touch_required=base.touch_required,
                    protected=base.protected,
                    encrypted=base.encrypted,
                    has_password_safe=base.has_password_safe,
                )
                for tag, value in self._parse_tlv(response):
                    if tag == SecretsAppProtocol.TAG_NAME:
                        data.id = value
                    elif tag == SecretsAppProtocol.TAG_PWS_LOGIN:
                        data.login = value
                    elif tag == SecretsAppProtocol.TAG_PWS_PASSWORD:
                        data.password = value
                    elif tag == SecretsAppProtocol.TAG_PWS_METADATA:
                        data.metadata = value
                return data
            except Exception as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise Solo2CommandError("Credential not found")

    def update_credential(
        self,
        credential: Credential,
        *,
        new_name: str | None = None,
        login: str | None = None,
        password: str | None = None,
        metadata: str | None = None,
    ) -> None:
        payload = bytearray()
        payload.extend(self._build_tlv(SecretsAppProtocol.TAG_NAME, credential.id))
        if new_name:
            target_name = (
                encode_password_only_label(new_name)
                if credential.password_only
                else new_name.encode("utf-8")
            )
            payload.extend(self._build_tlv(SecretsAppProtocol.TAG_NAME, target_name))
        if login is not None:
            payload.extend(self._build_tlv(SecretsAppProtocol.TAG_PWS_LOGIN, login.encode("utf-8")))
        if password is not None:
            payload.extend(self._build_tlv(SecretsAppProtocol.TAG_PWS_PASSWORD, password.encode("utf-8")))
        if metadata is not None:
            payload.extend(self._build_tlv(SecretsAppProtocol.TAG_PWS_METADATA, metadata.encode("utf-8")))
        self._send_apdu(SecretsAppProtocol.INS_UPDATE_CREDENTIAL, data=bytes(payload))

    def verify_reverse_hotp(self, credential: Credential, code: str) -> None:
        code_value = int(code)
        payload = bytearray()
        payload.extend(self._build_tlv(SecretsAppProtocol.TAG_NAME, credential.id))
        payload.extend(bytes([0x75, 0x04]))
        payload.extend(code_value.to_bytes(4, "big"))
        self._send_apdu(SecretsAppProtocol.INS_VERIFY_CODE, data=bytes(payload))

    def calculate_hmac(self, slot: int, challenge: bytes) -> str:
        slot_info = self.get_hmac_slot(slot)
        if not slot_info.configured:
            raise Solo2CommandError(f"{slot_info.name} is not configured")
        if len(challenge) > 63:
            raise Solo2CommandError("Challenge must be 63 bytes or shorter")
        padded = challenge + bytes([64 - len(challenge)]) * (64 - len(challenge))
        slot_cmd = 0x30 if slot == 1 else 0x38
        apdu = bytearray(
            [0x00, SecretsAppProtocol.INS_YK_API_REQUEST, slot_cmd, 0x00, len(padded)]
        )
        apdu.extend(padded)
        response = self._raw_send(bytes(apdu))
        sw1, sw2, data = SecretsAppProtocol.parse_status(response)
        if (sw1 << 8) | sw2 != SecretsAppProtocol.SW_SUCCESS:
            self._raise_for_sw((sw1 << 8) | sw2)
        return data.hex()

    def verify_pin(self, pin: str) -> dict:
        payload = self._build_tlv(SecretsAppProtocol.TAG_PASSWORD, pin.encode("utf-8"))
        try:
            self._send_apdu(SecretsAppProtocol.INS_VERIFY_PIN, data=payload)
            return {"success": True}
        except Solo2WrongPinError as exc:
            return {
                "success": False,
                "error": str(exc),
                "attempts": exc.attempts_remaining,
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def set_pin(self, pin: str) -> dict:
        payload = self._build_tlv(SecretsAppProtocol.TAG_PASSWORD, pin.encode("utf-8"))
        try:
            self._send_apdu(SecretsAppProtocol.INS_SET_PIN, data=payload)
            return {"success": True}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def change_pin(self, old_pin: str, new_pin: str) -> dict:
        payload = self._build_tlv(SecretsAppProtocol.TAG_PASSWORD, old_pin.encode("utf-8"))
        payload += self._build_tlv(
            SecretsAppProtocol.TAG_NEW_PASSWORD, new_pin.encode("utf-8")
        )
        try:
            self._send_apdu(SecretsAppProtocol.INS_CHANGE_PIN, data=payload)
            return {"success": True}
        except Solo2WrongPinError as exc:
            return {
                "success": False,
                "error": str(exc),
                "attempts": exc.attempts_remaining,
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}


class OATHError(Solo2CommandError):
    """Compatibility alias for browser/native-host code."""


class OATHTouchRequired(OATHError):
    """Compatibility alias for touch-required flows."""


class OATHPINRequired(OATHError):
    """Compatibility alias for pin-required flows."""


class OATHBridge:
    """Compatibility bridge for browser/native-host call sites."""

    def __init__(self, transport: Callable[[bytes], bytes] | None = None, device: Solo2Device | None = None):
        self._session = SecretsSession(device=device, transport=transport)

    def list_credentials(self) -> list[dict]:
        return self._session.list_credentials_dicts()

    def list_secrets(self) -> list[dict]:
        return self.list_credentials()

    def calculate_otp(self, name: str, period: int = 30) -> str:
        for credential in self._session.list_credentials():
            if credential.name == name or credential.id.decode("utf-8", errors="replace") == name:
                credential.period = period
                try:
                    return self._session.generate_otp(credential).code
                except Solo2TouchRequiredError as exc:
                    raise OATHTouchRequired(str(exc)) from exc
                except Solo2PinRequiredError as exc:
                    raise OATHPINRequired(str(exc)) from exc
                except Solo2CommandError as exc:
                    raise OATHError(str(exc)) from exc
        raise OATHError("Credential not found")

    def verify_pin(self, pin: str) -> dict:
        return self._session.verify_pin(pin)

    def set_pin(self, pin: str) -> dict:
        return self._session.set_pin(pin)

    def change_pin(self, old_pin: str, new_pin: str) -> dict:
        return self._session.change_pin(old_pin, new_pin)

    def add_credential(
        self,
        name: str,
        secret_b32: str,
        type_: str,
        algorithm: str,
        digits: int,
        touch_required: bool,
        pin_protected: bool,
        login: str | None = None,
        password: str | None = None,
        metadata: str | None = None,
        password_only: bool = False,
    ) -> dict:
        import base64

        secret_b32 = secret_b32.upper().replace(" ", "").replace("-", "")
        padding = (8 - len(secret_b32) % 8) % 8
        secret_b32 += "=" * padding
        try:
            secret_bytes = base64.b32decode(secret_b32)
        except Exception as exc:
            return {"success": False, "error": f"Invalid base32 secret: {exc}"}

        stored_name = encode_password_only_label(name) if password_only else name.encode("utf-8")
        credential = Credential(
            id=stored_name,
            otp=OtpKind.TOTP if type_.upper() == "TOTP" else OtpKind.HOTP,
            algorithm=getattr(Algorithm, algorithm.upper(), Algorithm.SHA1),
            digits=digits,
            touch_required=touch_required,
            protected=pin_protected,
            has_password_safe=any(value is not None for value in (login, password, metadata)),
            login=login.encode("utf-8") if login is not None else None,
            password=password.encode("utf-8") if password is not None else None,
            metadata=metadata.encode("utf-8") if metadata is not None else None,
        )
        try:
            self._session.add_credential(credential, secret_bytes)
            return {"success": True}
        except Solo2TouchRequiredError:
            return {"success": False, "error": "TOUCH_REQUIRED"}
        except Solo2PinRequiredError:
            return {"success": False, "error": "PIN_REQUIRED"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def delete_credential(self, name: str) -> dict:
        try:
            self._session.delete_credential(name)
            return {"success": True}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def get_password_entry(self, name: str) -> dict:
        try:
            entry = self._session.get_credential(name)
            return {
                "success": True,
                "credential": {
                    "name": entry.name,
                    "login": entry.login.decode("utf-8", errors="replace") if entry.login else "",
                    "password": entry.password.decode("utf-8", errors="replace") if entry.password else "",
                    "metadata": entry.metadata.decode("utf-8", errors="replace") if entry.metadata else "",
                },
            }
        except Solo2TouchRequiredError:
            return {"success": False, "error": "TOUCH_REQUIRED"}
        except Solo2PinRequiredError:
            return {"success": False, "error": "PIN_REQUIRED"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def update_password_entry(
        self,
        name: str,
        *,
        new_name: str | None = None,
        login: str | None = None,
        password: str | None = None,
        metadata: str | None = None,
    ) -> dict:
        try:
            credential = self._session.get_credential(name)
            self._session.update_credential(
                credential,
                new_name=new_name,
                login=login,
                password=password,
                metadata=metadata,
            )
            return {"success": True}
        except Solo2TouchRequiredError:
            return {"success": False, "error": "TOUCH_REQUIRED"}
        except Solo2PinRequiredError:
            return {"success": False, "error": "PIN_REQUIRED"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
