# solo2

Standalone Python library and CLI for Solo 2 devices.

## Installation

Install the package and CLI from the repo root:

```bash
python3 -m pip install .
```

That installs the `pysolo2` command defined in `pyproject.toml`.

For editable local development:

```bash
python3 -m pip install -e .
```

You can then verify the CLI is available with:

```bash
pysolo2 --help
```

For an isolated user install, `pipx` also works:

```bash
pipx install .
```

On Linux, USB and smartcard access may additionally require system packages such as `libusb` and `pcsc-lite`/`pcsclite`.

## CLI Overview

Top-level commands:

- `pysolo2 list`
  List discoverable Solo 2 devices.
- `pysolo2 info`
  Show information about the selected device.
- `pysolo2 admin`
  Admin app operations such as UUID, diagnostics, reboot, and factory reset.
- `pysolo2 fido2`
  FIDO2 PIN and credential management.
- `pysolo2 secrets`
  Secrets/Vault operations including OTP credentials, PIN handling, and HMAC slots.
- `pysolo2 provisioner`
  Provisioner app operations for keys, certificates, and filesystem tasks.

Global options:

- `--device <id>`
  Select a specific descriptor id.
- `--json`
  Print machine-readable JSON output.

## Common Examples

```bash
pysolo2 list
pysolo2 info
pysolo2 admin diagnostics
pysolo2 fido2 pin-status
pysolo2 fido2 list --pin 123456
pysolo2 secrets status
pysolo2 secrets list
pysolo2 secrets hmac-status
pysolo2 provisioner generate-key ed25519
```

Use `--help` on any command group for the full subcommand list:

```bash
pysolo2 admin --help
pysolo2 fido2 --help
pysolo2 secrets --help
pysolo2 provisioner --help
```
