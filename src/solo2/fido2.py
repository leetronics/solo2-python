"""High-level FIDO2 credential-management operations for Solo 2 devices."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin

from .device import Solo2Device
from .errors import Solo2CommandError, Solo2PinRequiredError, Solo2TransportError


@dataclass
class Fido2Credential:
    """FIDO2 credential information."""

    id: str
    rp_id: str
    rp_name: str
    user_id: str
    user_name: str
    user_display_name: str
    created: int
    is_resident: bool
    algorithm: str
    cred_id: Optional[bytes] = None


@dataclass
class Fido2PinStatus:
    """FIDO2 PIN and credential-management capability status."""

    ctap2_available: bool
    pin_set: bool
    pin_retries: Optional[int]
    uv_set: bool
    cred_mgmt_supported: bool


class Fido2Session:
    """Synchronous FIDO2 management session."""

    def __init__(self, device: Solo2Device, pin: str | None = None):
        self._device = device
        self._pin = pin
        self._ctap2 = None
        self._client_pin: ClientPin | None = None
        self._pin_token: bytes | None = None
        self._pin_protocol = None
        self._credman: CredentialManagement | None = None

    def set_pin_value(self, pin: str | None) -> None:
        self._pin = pin
        self._pin_token = None
        self._credman = None

    def _get_ctap2(self):
        if self._ctap2 is None:
            self._ctap2 = self._device.open_ctap2()
        if self._ctap2 is None:
            raise Solo2TransportError("Device not connected")
        return self._ctap2

    def get_pin_status(self) -> Fido2PinStatus:
        if self._device.prefers_ccid():
            return Fido2PinStatus(
                ctap2_available=False,
                pin_set=False,
                pin_retries=None,
                uv_set=False,
                cred_mgmt_supported=False,
            )

        info = self._get_ctap2().get_info()
        options = dict(info.options) if info.options else {}
        pin_retries = None
        if options.get("clientPin"):
            pin_retries = self.get_pin_retries()
        return Fido2PinStatus(
            ctap2_available=True,
            pin_set=bool(options.get("clientPin")),
            pin_retries=pin_retries,
            uv_set=bool(options.get("uv")),
            cred_mgmt_supported=bool(
                options.get("credMgmt") or options.get("credentialMgmtPreview")
            ),
        )

    def get_pin_retries(self) -> int:
        client_pin = self._client_pin or ClientPin(self._get_ctap2())
        self._client_pin = client_pin
        return client_pin.get_pin_retries()[0]

    def _ensure_authenticated(self, pin: str | None = None) -> None:
        pin = pin or self._pin
        if not pin:
            raise Solo2PinRequiredError("PIN required")

        permissions = [ClientPin.PERMISSION.CREDENTIAL_MGMT]
        persistent = getattr(ClientPin.PERMISSION, "PERSISTENT_CREDENTIAL_MGMT", None)
        if persistent is not None:
            permissions.append(persistent)

        last_error: Exception | None = None
        for permission in permissions:
            try:
                self._client_pin = ClientPin(self._get_ctap2())
                self._pin_protocol = self._client_pin.protocol
                self._pin_token = self._client_pin.get_pin_token(pin, permission)
                self._credman = CredentialManagement(
                    self._ctap2, self._pin_protocol, self._pin_token
                )
                self._pin = pin
                return
            except Exception as exc:
                last_error = exc

        if last_error is None:
            raise Solo2CommandError("Authentication failed")
        raise Solo2CommandError(str(last_error)) from last_error

    def list_credentials(self, pin: str | None = None) -> list[Fido2Credential]:
        self._ensure_authenticated(pin)
        assert self._credman is not None

        credentials: list[Fido2Credential] = []
        metadata = self._credman.get_metadata()
        existing_count = metadata.get(CredentialManagement.RESULT.EXISTING_CRED_COUNT, 0)
        if existing_count <= 0:
            return credentials

        for rp_data in self._credman.enumerate_rps():
            rp = rp_data.get(CredentialManagement.RESULT.RP)
            rp_id_hash = rp_data.get(CredentialManagement.RESULT.RP_ID_HASH)
            if not rp:
                continue
            for cred_data in self._credman.enumerate_creds(rp_id_hash):
                cred_id = cred_data.get(CredentialManagement.RESULT.CREDENTIAL_ID)
                user = cred_data.get(CredentialManagement.RESULT.USER)
                if not cred_id or not user:
                    continue
                credentials.append(
                    Fido2Credential(
                        id=cred_id.hex() if isinstance(cred_id, bytes) else str(cred_id),
                        rp_id=rp.get("id", ""),
                        rp_name=rp.get("name", ""),
                        user_id=(
                            user.get("id", b"").hex()
                            if isinstance(user.get("id"), bytes)
                            else str(user.get("id", ""))
                        ),
                        user_name=user.get("name", ""),
                        user_display_name=user.get("displayName", ""),
                        created=0,
                        is_resident=True,
                        algorithm="ES256",
                        cred_id=cred_id,
                    )
                )
        return credentials

    def delete_credential(self, credential: Fido2Credential | bytes, pin: str | None = None) -> None:
        self._ensure_authenticated(pin)
        assert self._credman is not None
        cred_id = credential if isinstance(credential, bytes) else credential.cred_id
        if cred_id is None:
            raise Solo2CommandError("Missing credential id")
        self._credman.delete_cred(cred_id)

    def rename_credential(
        self,
        credential: Fido2Credential,
        new_name: str,
        pin: str | None = None,
    ) -> None:
        self._ensure_authenticated(pin)
        assert self._credman is not None
        if credential.cred_id is None:
            raise Solo2CommandError("Missing credential id")
        user_id = credential.user_id
        if isinstance(user_id, str):
            try:
                user_id_bytes = bytes.fromhex(user_id)
            except ValueError:
                user_id_bytes = user_id.encode()
        else:
            user_id_bytes = user_id

        cred_id_descriptor = {"id": credential.cred_id, "type": "public-key"}
        user_info = {
            "id": user_id_bytes,
            "name": new_name,
            "displayName": new_name,
        }
        self._credman.update_user_info(cred_id_descriptor, user_info)

    def set_pin(self, new_pin: str) -> None:
        if len(new_pin) < 4:
            raise Solo2CommandError("PIN must be at least 4 characters")
        client_pin = self._client_pin or ClientPin(self._get_ctap2())
        self._client_pin = client_pin
        client_pin.set_pin(new_pin)
        self.set_pin_value(new_pin)

    def change_pin(self, current_pin: str, new_pin: str) -> None:
        if len(new_pin) < 4:
            raise Solo2CommandError("PIN must be at least 4 characters")
        client_pin = self._client_pin or ClientPin(self._get_ctap2())
        self._client_pin = client_pin
        client_pin.change_pin(current_pin, new_pin)
        self.set_pin_value(new_pin)
