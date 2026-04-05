"""Command-line interface for the standalone solo2 package."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import sys
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any

from .admin import AdminSession, RebootMode
from .device import DeviceMode, Solo2Descriptor, Solo2Device, format_firmware_full, format_firmware_version
from .discovery import list_bootloader_descriptors, list_regular_descriptors, open_device
from .errors import (
    Solo2ConfirmationRequiredError,
    Solo2Error,
    Solo2NotFoundError,
    Solo2PinRequiredError,
)
from .fido2 import Fido2Session
from .hid_backend import list_ctap_hid_descriptors
from .pcsc import list_pcsc_descriptors
from .provisioner import ProvisionerSession
from .secrets import (
    Algorithm,
    Credential,
    KEEPASSXC_HMAC_SLOT,
    HMAC_SLOT_NAMES,
    OtpKind,
    SecretsSession,
    normalize_hmac_secret,
)


@dataclass(frozen=True)
class CliResult:
    human: Any
    data: Any


@dataclass(frozen=True)
class DeviceSummary:
    kind: str
    display: str
    id: str
    mode: str
    uuid: str | None = None
    transports: list[str] | None = None
    transport_summary: str | None = None
    firmware_version: str | None = None
    locked: bool | None = None
    variant: str | None = None
    path: str | None = None
    capabilities: list[str] | None = None


def _serialize(value: Any) -> Any:
    if isinstance(value, CliResult):
        return _serialize(value.data)
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except Exception:
            return value.hex()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize(item) for item in value]
    if is_dataclass(value):
        return _serialize(asdict(value))
    if hasattr(value, "name") and hasattr(value, "value"):
        return value.name
    return value


def _print_result(result: Any, as_json: bool) -> None:
    if not as_json and isinstance(result, CliResult):
        if result.human is None:
            return
        _print_human(result.human)
        return
    serialized = _serialize(result)
    if as_json:
        print(json.dumps(serialized, indent=2, sort_keys=True))
        return
    if serialized is None:
        return
    _print_human(serialized)


def _print_human(value: Any, indent: int = 0) -> None:
    prefix = " " * indent
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print(f"{prefix}{key}:")
                _print_human(item, indent + 2)
            else:
                print(f"{prefix}{key}: {item}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            if index and isinstance(item, (dict, list)):
                print()
            _print_human(item, indent)
        return
    print(f"{prefix}{value}")


def _compact_dict(**items: Any) -> dict[str, Any]:
    return {key: value for key, value in items.items() if value is not None}


def _uuid_simple(uuid: str | None) -> str | None:
    if not uuid:
        return None
    return uuid.replace("-", "").upper()


def _transport_label(transport: str) -> str:
    if transport == "hid":
        return "CTAP"
    if transport == "ccid":
        return "PCSC"
    return transport.upper()


def _transport_summary(transports: set[str]) -> str:
    if transports == {"CTAP", "PCSC"}:
        return "CTAP+PCSC"
    if transports == {"CTAP"}:
        return "CTAP only"
    if transports == {"PCSC"}:
        return "PCSC only"
    return "+".join(sorted(transports))


def _locked_from_variant(variant: str | None) -> bool | None:
    if variant == "Secure":
        return True
    if variant == "Hacker":
        return False
    return None


def _regular_display(
    *,
    uuid: str | None,
    transports: set[str],
    firmware_version: str | None,
    locked: bool | None,
    fallback_id: str,
) -> str:
    transport_text = _transport_summary(transports)
    lock_status = ""
    if locked is True:
        lock_status = ", locked"
    elif locked is False:
        lock_status = ", unlocked"
    return (
        f"Solo 2 {_uuid_simple(uuid) or fallback_id} "
        f"({transport_text}, firmware {format_firmware_version(firmware_version)}{lock_status})"
    )


def _build_hid_descriptor(raw_descriptor) -> Solo2Descriptor:
    descriptor_id = f"hid:{raw_descriptor.path!r}"
    return Solo2Descriptor(
        id=descriptor_id,
        mode=DeviceMode.REGULAR,
        path=descriptor_id,
        transport="hid",
        hid_path=raw_descriptor.path,
    )


def _build_pcsc_descriptor(reader_name: str) -> Solo2Descriptor:
    descriptor_id = f"ccid:{reader_name}"
    return Solo2Descriptor(
        id=descriptor_id,
        mode=DeviceMode.REGULAR,
        path=descriptor_id,
        transport="ccid",
        reader_name=reader_name,
    )


def _list_device_summaries() -> list[DeviceSummary]:
    regular_inventory: dict[str, dict[str, Any]] = {}

    regular_descriptors = [_build_hid_descriptor(descriptor) for descriptor in list_ctap_hid_descriptors()]
    regular_descriptors.extend(
        _build_pcsc_descriptor(descriptor.reader) for descriptor in list_pcsc_descriptors()
    )

    for descriptor in regular_descriptors:
        device = Solo2Device.from_descriptor(descriptor)
        if not device.connect():
            continue
        try:
            key = device.device_uuid or descriptor.id
            entry = regular_inventory.setdefault(
                key,
                {
                    "id": device.path,
                    "uuid": device.device_uuid,
                    "mode": DeviceMode.REGULAR.value,
                    "path": device.path,
                    "firmware_version": device.firmware_version,
                    "variant": device.variant or None,
                    "locked": _locked_from_variant(device.variant),
                    "transports": set(),
                    "capabilities": set(device.get_info().capabilities or []),
                },
            )
            entry["transports"].add(_transport_label(descriptor.transport))
            if device.device_uuid and not entry["uuid"]:
                entry["uuid"] = device.device_uuid
                entry["id"] = device.path
                entry["path"] = device.path
            if device.firmware_version and not entry["firmware_version"]:
                entry["firmware_version"] = device.firmware_version
            if device.variant and not entry["variant"]:
                entry["variant"] = device.variant
            locked = _locked_from_variant(device.variant)
            if locked is not None and entry["locked"] is None:
                entry["locked"] = locked
            entry["capabilities"].update(device.get_info().capabilities or [])
        finally:
            device.disconnect()

    summaries = [
        DeviceSummary(
            kind="solo2",
            display=_regular_display(
                uuid=entry["uuid"],
                transports=entry["transports"],
                firmware_version=entry["firmware_version"],
                locked=entry["locked"],
                fallback_id=entry["id"],
            ),
            id=entry["id"],
            mode=entry["mode"],
            uuid=entry["uuid"],
            transports=sorted(entry["transports"]),
            transport_summary=_transport_summary(entry["transports"]),
            firmware_version=entry["firmware_version"],
            locked=entry["locked"],
            variant=entry["variant"],
            path=entry["path"],
            capabilities=sorted(entry["capabilities"]) or None,
        )
        for entry in regular_inventory.values()
    ]

    for descriptor in list_bootloader_descriptors():
        summaries.append(
            DeviceSummary(
                kind="bootloader",
                display=f"LPC 55 {descriptor.id}",
                id=descriptor.id,
                mode=descriptor.mode.value,
                path=descriptor.path,
            )
        )

    return sorted(
        summaries,
        key=lambda item: (
            0 if item.kind == "bootloader" else 1,
            item.uuid or item.id,
        ),
    )


def _select_device(device_id: str | None):
    descriptors = list_regular_descriptors()
    if device_id:
        return open_device(device_id)
    if len(descriptors) == 1:
        return open_device(descriptors[0])
    if not descriptors:
        raise Solo2NotFoundError("No Solo 2 device found")
    joined = ", ".join(descriptor.id for descriptor in descriptors)
    raise Solo2Error(f"Multiple devices found, use --device: {joined}")


def _require_yes(args: argparse.Namespace, message: str) -> None:
    if not getattr(args, "yes", False):
        raise Solo2ConfirmationRequiredError(message)


def _resolve_fido2_pin(
    args: argparse.Namespace,
    session: Fido2Session,
    *,
    required: bool,
) -> str | None:
    if getattr(args, "pin", None):
        return args.pin
    if not required:
        return None

    status = session.get_pin_status()
    if not status.pin_set:
        return None
    if not sys.stdin.isatty():
        raise Solo2PinRequiredError("PIN required; pass --pin in non-interactive mode")

    pin = getpass.getpass("Enter FIDO2 PIN: ")
    if not pin:
        raise Solo2PinRequiredError("PIN required")
    args.pin = pin
    session.set_pin_value(pin)
    return pin


def cmd_list(_args: argparse.Namespace):
    summaries = _list_device_summaries()
    return CliResult(
        human=[summary.display for summary in summaries],
        data=summaries,
    )


def cmd_info(args: argparse.Namespace):
    device = _select_device(args.device)
    info = device.get_info()
    inventory_summary = next(
        (
            summary
            for summary in _list_device_summaries()
            if summary.kind == "solo2"
            and (
                summary.id == device.descriptor.id
                or (summary.uuid and summary.uuid == device.device_uuid)
                or summary.path == info.path
            )
        ),
        None,
    )
    transports = set(inventory_summary.transports or []) if inventory_summary else {_transport_label(device.descriptor.transport)}
    locked = inventory_summary.locked if inventory_summary else _locked_from_variant(device.variant)
    summary = _regular_display(
        uuid=device.device_uuid,
        transports=transports,
        firmware_version=device.firmware_version,
        locked=locked,
        fallback_id=device.descriptor.id,
    )
    data = _compact_dict(
        display=summary,
        id=device.descriptor.id,
        path=info.path,
        mode=info.mode.value,
        uuid=device.device_uuid,
        variant=device.variant or None,
        transport_summary=_transport_summary(transports),
        transports=sorted(transports),
        firmware_version=device.firmware_version,
        firmware=format_firmware_full(device.firmware_version),
        locked=locked,
        serial_number=info.serial_number,
        capabilities=info.capabilities,
    )
    human = [summary]
    if data.get("variant"):
        human.append(f"variant: {data['variant']}")
    human.append(f"id: {data['id']}")
    human.append(f"path: {data['path']}")
    if data.get("capabilities"):
        human.append(f"capabilities: {', '.join(data['capabilities'])}")
    return CliResult(human=human, data=data)


def cmd_admin(args: argparse.Namespace):
    session = AdminSession(_select_device(args.device))
    if args.admin_cmd == "uuid":
        return {"uuid": session.get_uuid()}
    if args.admin_cmd == "diagnostics":
        return session.get_diagnostics()
    if args.admin_cmd == "wink":
        session.wink()
        return {"success": True}
    if args.admin_cmd == "reboot":
        mode = RebootMode.BOOTLOADER if args.mode == "bootloader" else RebootMode.REGULAR
        session.reboot(mode)
        return {"success": True, "mode": mode.name.lower()}
    if args.admin_cmd == "factory-reset":
        _require_yes(args, "Pass --yes to perform a factory reset.")
        session.factory_reset()
        return {"success": True}
    raise Solo2Error(f"Unknown admin command: {args.admin_cmd}")


def cmd_fido2(args: argparse.Namespace):
    session = Fido2Session(_select_device(args.device), pin=args.pin)
    if args.fido_cmd == "pin-status":
        return session.get_pin_status()
    if args.fido_cmd in {"list", "delete", "rename"}:
        pin = _resolve_fido2_pin(args, session, required=True)
    else:
        pin = args.pin
    if args.fido_cmd == "list":
        return session.list_credentials(pin=pin)
    if args.fido_cmd == "set-pin":
        _require_yes(args, "Pass --yes to set a new FIDO2 PIN.")
        session.set_pin(args.new_pin)
        return {"success": True}
    if args.fido_cmd == "change-pin":
        _require_yes(args, "Pass --yes to change the FIDO2 PIN.")
        session.change_pin(args.current_pin, args.new_pin)
        return {"success": True}
    credentials = session.list_credentials(pin=pin)
    target = next(
        (
            credential
            for credential in credentials
            if credential.id == args.credential_id
            or credential.rp_id == args.credential_id
        ),
        None,
    )
    if target is None:
        raise Solo2Error(f"Credential not found: {args.credential_id}")
    if args.fido_cmd == "delete":
        _require_yes(args, "Pass --yes to delete the FIDO2 credential.")
        session.delete_credential(target, pin=pin)
        return {"success": True}
    if args.fido_cmd == "rename":
        session.rename_credential(target, args.new_name, pin=pin)
        return {"success": True}
    raise Solo2Error(f"Unknown FIDO2 command: {args.fido_cmd}")


def _secrets_session(args: argparse.Namespace) -> SecretsSession:
    return SecretsSession(_select_device(args.device))


def _find_secret(args: argparse.Namespace, session: SecretsSession) -> Credential:
    credentials = session.list_credentials()
    for credential in credentials:
        raw_name = credential.id.decode("utf-8", errors="replace")
        if credential.name == args.name or raw_name == args.name:
            return credential
    raise Solo2Error(f"Credential not found: {args.name}")


def cmd_secrets(args: argparse.Namespace):
    session = _secrets_session(args)
    if args.secrets_cmd == "status":
        return session.get_status()
    if args.secrets_cmd == "list":
        return session.list_credentials_dicts()
    if args.secrets_cmd == "hmac-status":
        return session.list_hmac_slots()
    if args.secrets_cmd == "hmac-generate":
        secret = session.generate_hmac_secret()
        slot_info = session.configure_hmac_slot(
            args.slot,
            secret,
            overwrite=args.force,
        )
        return {
            "success": True,
            "slot": slot_info.slot,
            "name": slot_info.name,
            "configured": slot_info.configured,
            "secret_hex": secret.hex(),
        }
    if args.secrets_cmd == "hmac-import":
        slot_info = session.configure_hmac_slot(
            args.slot,
            normalize_hmac_secret(args.secret),
            overwrite=args.force,
        )
        return {
            "success": True,
            "slot": slot_info.slot,
            "name": slot_info.name,
            "configured": slot_info.configured,
        }
    if args.secrets_cmd == "hmac-remove":
        _require_yes(args, f"Pass --yes to remove {HMAC_SLOT_NAMES[args.slot]}.")
        session.delete_hmac_slot(args.slot)
        return {"success": True}
    if args.secrets_cmd == "verify-pin":
        return session.verify_pin(args.pin_value)
    if args.secrets_cmd == "set-pin":
        _require_yes(args, "Pass --yes to set the Secrets PIN.")
        return session.set_pin(args.pin_value)
    if args.secrets_cmd == "change-pin":
        _require_yes(args, "Pass --yes to change the Secrets PIN.")
        return session.change_pin(args.old_pin, args.new_pin)
    if args.secrets_cmd == "add":
        secret_b32 = args.secret.upper().replace(" ", "").replace("-", "")
        padding = (8 - len(secret_b32) % 8) % 8
        secret_b32 += "=" * padding
        secret_bytes = base64.b32decode(secret_b32)
        credential = Credential(
            id=args.name.encode("utf-8"),
            otp=OtpKind.TOTP if args.kind == "totp" else OtpKind.HOTP,
            algorithm=Algorithm[args.algorithm],
            digits=args.digits,
            touch_required=args.touch,
            protected=args.pin_protected,
            has_password_safe=any(value is not None for value in (args.login, args.password, args.metadata)),
            login=args.login.encode("utf-8") if args.login else None,
            password=args.password.encode("utf-8") if args.password else None,
            metadata=args.metadata.encode("utf-8") if args.metadata else None,
        )
        session.add_credential(credential, secret_bytes)
        return {"success": True}

    credential = _find_secret(args, session)
    if args.secrets_cmd == "delete":
        _require_yes(args, "Pass --yes to delete the secrets credential.")
        session.delete_credential(credential)
        return {"success": True}
    if args.secrets_cmd == "otp":
        return session.generate_otp(credential)
    if args.secrets_cmd == "get":
        return session.get_credential(credential)
    if args.secrets_cmd == "update":
        session.update_credential(
            credential,
            new_name=args.new_name,
            login=args.login,
            password=args.password,
            metadata=args.metadata,
        )
        return {"success": True}
    if args.secrets_cmd == "verify-reverse-hotp":
        session.verify_reverse_hotp(credential, args.code)
        return {"success": True}
    if args.secrets_cmd == "hmac":
        return {
            "slot": args.slot,
            "hmac": session.calculate_hmac(args.slot, args.challenge.encode("utf-8")),
        }
    raise Solo2Error(f"Unknown secrets command: {args.secrets_cmd}")


def cmd_provisioner(args: argparse.Namespace):
    session = ProvisionerSession(_select_device(args.device))
    if args.provisioner_cmd == "generate-key":
        return session.generate_key(args.key_type)
    if args.provisioner_cmd == "store-cert":
        session.store_certificate(args.key_type, Path(args.cert_file).read_bytes())
        return {"success": True}
    if args.provisioner_cmd == "store-t1-pubkey":
        session.store_t1_pubkey(Path(args.pubkey_file).read_bytes())
        return {"success": True}
    if args.provisioner_cmd == "reformat-fs":
        _require_yes(args, "Pass --yes to reformat the provisioner filesystem.")
        session.reformat_filesystem()
        return {"success": True}
    if args.provisioner_cmd == "write-file":
        session.write_file(args.path, Path(args.source_file).read_bytes())
        return {"success": True}
    raise Solo2Error(f"Unknown provisioner command: {args.provisioner_cmd}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pysolo2")
    parser.add_argument("--device", help="descriptor id of the target device")
    parser.add_argument("--json", action="store_true", help="print JSON output")

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list discoverable Solo 2 devices")
    list_parser.set_defaults(func=cmd_list)

    info_parser = subparsers.add_parser("info", help="show device information")
    info_parser.set_defaults(func=cmd_info)

    admin_parser = subparsers.add_parser("admin", help="admin app operations")
    admin_sub = admin_parser.add_subparsers(dest="admin_cmd", required=True)
    admin_sub.add_parser("uuid").set_defaults(func=cmd_admin)
    admin_sub.add_parser("diagnostics").set_defaults(func=cmd_admin)
    admin_sub.add_parser("wink").set_defaults(func=cmd_admin)
    reboot_parser = admin_sub.add_parser("reboot")
    reboot_parser.add_argument("--mode", choices=["regular", "bootloader"], default="regular")
    reboot_parser.set_defaults(func=cmd_admin)
    reset_parser = admin_sub.add_parser("factory-reset")
    reset_parser.add_argument("--yes", action="store_true")
    reset_parser.set_defaults(func=cmd_admin)

    fido_parser = subparsers.add_parser("fido2", help="FIDO2 credential management")
    fido_parser.add_argument("--pin")
    fido_sub = fido_parser.add_subparsers(dest="fido_cmd", required=True)
    fido_sub.add_parser("pin-status").set_defaults(func=cmd_fido2)
    fido_sub.add_parser("list").set_defaults(func=cmd_fido2)
    set_pin = fido_sub.add_parser("set-pin")
    set_pin.add_argument("new_pin")
    set_pin.add_argument("--yes", action="store_true")
    set_pin.set_defaults(func=cmd_fido2)
    change_pin = fido_sub.add_parser("change-pin")
    change_pin.add_argument("current_pin")
    change_pin.add_argument("new_pin")
    change_pin.add_argument("--yes", action="store_true")
    change_pin.set_defaults(func=cmd_fido2)
    delete = fido_sub.add_parser("delete")
    delete.add_argument("credential_id")
    delete.add_argument("--yes", action="store_true")
    delete.set_defaults(func=cmd_fido2)
    rename = fido_sub.add_parser("rename")
    rename.add_argument("credential_id")
    rename.add_argument("new_name")
    rename.set_defaults(func=cmd_fido2)

    secrets_parser = subparsers.add_parser("secrets", help="secrets/OATH operations")
    secrets_sub = secrets_parser.add_subparsers(dest="secrets_cmd", required=True)
    secrets_sub.add_parser("status").set_defaults(func=cmd_secrets)
    secrets_sub.add_parser("list").set_defaults(func=cmd_secrets)
    verify_pin = secrets_sub.add_parser("verify-pin")
    verify_pin.add_argument("pin_value")
    verify_pin.set_defaults(func=cmd_secrets)
    set_pin = secrets_sub.add_parser("set-pin")
    set_pin.add_argument("pin_value")
    set_pin.add_argument("--yes", action="store_true")
    set_pin.set_defaults(func=cmd_secrets)
    change_pin = secrets_sub.add_parser("change-pin")
    change_pin.add_argument("old_pin")
    change_pin.add_argument("new_pin")
    change_pin.add_argument("--yes", action="store_true")
    change_pin.set_defaults(func=cmd_secrets)
    add = secrets_sub.add_parser("add")
    add.add_argument("name")
    add.add_argument("secret")
    add.add_argument("--kind", choices=["totp", "hotp"], default="totp")
    add.add_argument("--algorithm", choices=["SHA1", "SHA256", "SHA512"], default="SHA1")
    add.add_argument("--digits", type=int, default=6)
    add.add_argument("--touch", action="store_true")
    add.add_argument("--pin-protected", action="store_true")
    add.add_argument("--login")
    add.add_argument("--password")
    add.add_argument("--metadata")
    add.set_defaults(func=cmd_secrets)
    delete = secrets_sub.add_parser("delete")
    delete.add_argument("name")
    delete.add_argument("--yes", action="store_true")
    delete.set_defaults(func=cmd_secrets)
    otp = secrets_sub.add_parser("otp")
    otp.add_argument("name")
    otp.set_defaults(func=cmd_secrets)
    get_cmd = secrets_sub.add_parser("get")
    get_cmd.add_argument("name")
    get_cmd.set_defaults(func=cmd_secrets)
    update = secrets_sub.add_parser("update")
    update.add_argument("name")
    update.add_argument("--new-name")
    update.add_argument("--login")
    update.add_argument("--password")
    update.add_argument("--metadata")
    update.set_defaults(func=cmd_secrets)
    reverse = secrets_sub.add_parser("verify-reverse-hotp")
    reverse.add_argument("name")
    reverse.add_argument("code")
    reverse.set_defaults(func=cmd_secrets)
    secrets_sub.add_parser(
        "hmac-status",
        help="show HMAC slot status",
    ).set_defaults(func=cmd_secrets)
    hmac_generate = secrets_sub.add_parser(
        "hmac-generate",
        help="generate and program a new HMAC secret into a slot",
    )
    hmac_generate.add_argument("--slot", type=int, choices=[1, 2], default=KEEPASSXC_HMAC_SLOT)
    hmac_generate.add_argument("--force", action="store_true")
    hmac_generate.set_defaults(func=cmd_secrets)
    hmac_import = secrets_sub.add_parser(
        "hmac-import",
        help="import a hex/base32 HMAC secret into a slot",
    )
    hmac_import.add_argument("--slot", type=int, choices=[1, 2], default=KEEPASSXC_HMAC_SLOT)
    hmac_import.add_argument("--secret", required=True)
    hmac_import.add_argument("--force", action="store_true")
    hmac_import.set_defaults(func=cmd_secrets)
    hmac_remove = secrets_sub.add_parser(
        "hmac-remove",
        help="remove the configured HMAC secret from a slot",
    )
    hmac_remove.add_argument("--slot", type=int, choices=[1, 2], default=KEEPASSXC_HMAC_SLOT)
    hmac_remove.add_argument("--yes", action="store_true")
    hmac_remove.set_defaults(func=cmd_secrets)
    hmac = secrets_sub.add_parser(
        "hmac",
        help="calculate an HMAC challenge-response using the configured slot",
    )
    hmac.add_argument("challenge")
    hmac.add_argument("--slot", type=int, choices=[1, 2], default=KEEPASSXC_HMAC_SLOT)
    hmac.set_defaults(func=cmd_secrets)

    provision_parser = subparsers.add_parser("provisioner", help="provisioner app operations")
    provision_sub = provision_parser.add_subparsers(dest="provisioner_cmd", required=True)
    gen = provision_sub.add_parser("generate-key")
    gen.add_argument("key_type", choices=["ed25519", "p256", "x25519"])
    gen.set_defaults(func=cmd_provisioner)
    cert = provision_sub.add_parser("store-cert")
    cert.add_argument("key_type", choices=["ed25519", "p256", "x25519"])
    cert.add_argument("cert_file")
    cert.set_defaults(func=cmd_provisioner)
    t1 = provision_sub.add_parser("store-t1-pubkey")
    t1.add_argument("pubkey_file")
    t1.set_defaults(func=cmd_provisioner)
    reformat = provision_sub.add_parser("reformat-fs")
    reformat.add_argument("--yes", action="store_true")
    reformat.set_defaults(func=cmd_provisioner)
    write_file = provision_sub.add_parser("write-file")
    write_file.add_argument("path")
    write_file.add_argument("source_file")
    write_file.set_defaults(func=cmd_provisioner)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
        _print_result(result, args.json)
        return 0
    except Solo2ConfirmationRequiredError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except Solo2Error as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
