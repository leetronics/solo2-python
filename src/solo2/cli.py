"""Command-line interface for the standalone solo2 package."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .admin import AdminSession, RebootMode
from .discovery import list_descriptors, list_regular_descriptors, open_device
from .errors import (
    Solo2ConfirmationRequiredError,
    Solo2Error,
    Solo2NotFoundError,
)
from .fido2 import Fido2Session
from .provisioner import ProvisionerSession
from .secrets import Algorithm, Credential, OtpKind, SecretsSession


def _serialize(value: Any) -> Any:
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
    serialized = _serialize(result)
    if as_json:
        print(json.dumps(serialized, indent=2, sort_keys=True))
        return
    if serialized is None:
        return
    if isinstance(serialized, list):
        for item in serialized:
            if isinstance(item, dict):
                print(json.dumps(item, indent=2, sort_keys=True))
            else:
                print(item)
        return
    if isinstance(serialized, dict):
        print(json.dumps(serialized, indent=2, sort_keys=True))
        return
    print(serialized)


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


def cmd_list(_args: argparse.Namespace):
    return [
        {
            "id": descriptor.id,
            "mode": descriptor.mode.value,
            "transport": descriptor.transport,
            "path": descriptor.path,
            "firmware_version": descriptor.firmware_version,
            "uuid": descriptor.uuid,
        }
        for descriptor in list_descriptors()
    ]


def cmd_info(args: argparse.Namespace):
    device = _select_device(args.device)
    info = device.get_info()
    return {
        "path": info.path,
        "mode": info.mode.value,
        "firmware_version": info.firmware_version,
        "serial_number": info.serial_number,
        "capabilities": info.capabilities,
        "descriptor": {
            "id": device.descriptor.id,
            "transport": device.descriptor.transport,
            "uuid": device.descriptor.uuid,
        },
    }


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
    if args.fido_cmd == "list":
        return session.list_credentials(pin=args.pin)
    if args.fido_cmd == "set-pin":
        _require_yes(args, "Pass --yes to set a new FIDO2 PIN.")
        session.set_pin(args.new_pin)
        return {"success": True}
    if args.fido_cmd == "change-pin":
        _require_yes(args, "Pass --yes to change the FIDO2 PIN.")
        session.change_pin(args.current_pin, args.new_pin)
        return {"success": True}
    credentials = session.list_credentials(pin=args.pin)
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
        session.delete_credential(target, pin=args.pin)
        return {"success": True}
    if args.fido_cmd == "rename":
        session.rename_credential(target, args.new_name, pin=args.pin)
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
        return {"hmac": session.calculate_hmac(args.slot, args.challenge.encode("utf-8"))}
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
    parser = argparse.ArgumentParser(prog="solo2")
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
    hmac = secrets_sub.add_parser("hmac")
    hmac.add_argument("challenge")
    hmac.add_argument("--slot", type=int, choices=[1, 2], default=1)
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
