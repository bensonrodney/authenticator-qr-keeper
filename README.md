# authenticator-qr-keeper

A command-line tool for securely storing and reproducing TOTP authenticator QR codes.

When you set up two-factor authentication, most services show you a QR code once and never again. If you lose your phone or switch authenticator apps, you're stuck going through account recovery for every service. This tool lets you save those QR codes in an AES-256 encrypted file so you can reproduce them any time — and it also shows you the current live OTP code so you don't even need to scan the QR.

## Demo

<video src="https://ejectedalien-publicly-accessible.s3.ap-southeast-2.amazonaws.com/videos/authenticator_qr_keeper_demo.mp4" controls width="700"></video>

## Features

- Stores `otpauth://` URLs in an AES-256-CBC encrypted file (compatible with `openssl`)
- Reproduces QR codes in the terminal
- Shows the live TOTP code with a countdown to the next rotation
- Add new codes by scanning a QR code image file
- Encrypted file can also be edited with the bundled shell scripts

## Requirements

- Python 3.12+
- `uv` (for installation and development)
- `openssl` (for the companion shell scripts)
- `libgl1` may be required on some systems for OpenCV: `sudo apt-get install libgl1`

## Installation

Install the `qrcodes` command using `uv`:

```bash
git clone <repo-url>
cd authenticator-qr-keeper
make install
```

This installs `qrcodes` as an isolated tool into `~/.local/bin` via `uv tool install`. Make sure `~/.local/bin` is on your `PATH`.

## Usage

### View a QR code

```
qrcodes
```

On first run, if no codes file exists, you will be prompted to create one and set a password. On subsequent runs you will be shown a numbered list of your stored accounts to choose from.

After selecting an account, the QR code is printed to the terminal and the live TOTP code is shown with a countdown bar:

```
  OTP: 483 921  [████████████████░░░░░░░░░░░░░░] 16s  (Press Enter to continue)
```

Press **Enter** or **Ctrl+C** to return to the menu.

### Add a new code from a QR image

```
qrcodes --add /path/to/qrcode-image.png
```

This reads the `otpauth://` URL from the image, prompts for your file password, and appends the new code. A timestamped backup of the codes file is created before any write.

## Codes file format

The codes file lives at `~/.qr/.qrcodes` and is AES-256-CBC encrypted. In its unencrypted form it is a plain text file with one `otpauth://` URL per line. Lines starting with `#` are treated as comments.

```
# My accounts
otpauth://totp/My%20Service%3Amyuser?secret=YOURSECRETHERE&issuer=My%20Service
otpauth://totp/Another%20Service%3Amyuser?secret=ANOTHERSECRET&issuer=Another%20Service
```

You can edit the file directly using the bundled `edit-encrypted-file.sh` script (see [Shell scripts](#shell-scripts) below), which decrypts to a temp file, opens it in `$EDITOR`, and re-encrypts on save.

### Obtaining otpauth:// URLs

When a service shows you a QR code during 2FA setup:

1. Save a screenshot of the QR code image.
2. Run `qrcodes --add /path/to/screenshot.png` to import it.

Alternatively, some authenticator apps (e.g. Aegis) let you export your accounts as `otpauth://` URLs directly.

## Shell scripts

Three shell scripts are installed alongside the `qrcodes` command. They use `openssl` directly and are compatible with the encrypted file format used by this tool.

| Script | Purpose |
|---|---|
| `encrypt-file.sh <infile> <outfile>` | Encrypt a plaintext file |
| `decrypt-file.sh <infile>` | Decrypt a file to stdout |
| `edit-encrypted-file.sh <file>` | Decrypt, open in `$EDITOR`, re-encrypt on save |

## Development

Set up the development environment:

```bash
make dev        # creates .venv and installs all dependencies including dev tools
```

Available `make` targets:

| Target | Description |
|---|---|
| `make dev` | Set up the dev environment (`uv sync --extra dev`) |
| `make install` | Install the `qrcodes` command for your user |
| `make check` | Run linting, format check, and tests (use before committing) |
| `make lint` | Run `ruff check` only |
| `make fmt` | Apply `ruff format` to the codebase |
| `make test` | Run the test suite |

### Running tests

```bash
make test
```

Tests cover the encryption/decryption layer (including openssl interoperability), the `otpauth://` URL parser, file parsing, and the TOTP code generation.

## Security notes

- The codes file uses AES-256-CBC (the same cipher and key derivation as `openssl aes-256-cbc -pbkdf2 -iter 10000`), which means you can decrypt it with `openssl` directly if needed.
- AES-CBC provides confidentiality but not authentication. A corrupted or tampered file will decrypt to garbage rather than raising an error.
- A timestamped backup (e.g. `.qrcodes.backup.20240101-120000`) is created before every write.
- The decrypted contents exist in memory only and are never written to disk by `qrcodes`.
