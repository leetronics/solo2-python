# solo2

Standalone Python library and CLI for Solo 2 devices.

## Installation

Install the package and CLI from the repo root:

```bash
python3 -m pip install .
```

That installs the `solo2` command defined in `pyproject.toml`.

For editable local development:

```bash
python3 -m pip install -e .
```

You can then verify the CLI is available with:

```bash
solo2 --help
```

For an isolated user install, `pipx` also works:

```bash
pipx install .
```

On Linux, USB and smartcard access may additionally require system packages such as `libusb` and `pcsc-lite`/`pcsclite`.

## CLI Overview

Top-level commands:

- `solo2 list`
  List discoverable Solo 2 devices.
- `solo2 info`
  Show information about the selected device.
- `solo2 admin`
  Admin app operations such as UUID, diagnostics, reboot, and factory reset.
- `solo2 fido2`
  FIDO2 PIN and credential management.
- `solo2 secrets`
  Secrets/Vault operations including OTP credentials, PIN handling, and HMAC slots.
- `solo2 provisioner`
  Provisioner app operations for keys, certificates, and filesystem tasks.

Global options:

- `--device <id>`
  Select a specific descriptor id.
- `--json`
  Print machine-readable JSON output.

## Common Examples

```bash
solo2 list
solo2 info
solo2 admin diagnostics
solo2 fido2 pin-status
solo2 fido2 list --pin 123456
solo2 secrets status
solo2 secrets list
solo2 secrets hmac-status
solo2 provisioner generate-key ed25519
```

Use `--help` on any command group for the full subcommand list:

```bash
solo2 admin --help
solo2 fido2 --help
solo2 secrets --help
solo2 provisioner --help
```
