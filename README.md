# authenticator-qr-keeper

A command-line tool for securely storing and reproducing QR codes — primarily TOTP authenticator codes, but also WiFi credentials and anything else stored as a QR code.

When you set up two-factor authentication, most services show you a QR code once and never again. If you lose your phone or switch authenticator apps, you're stuck going through account recovery for every service. This tool lets you save those QR codes in an AES-256 encrypted file so you can reproduce them any time — and it also shows you the current live OTP code so you don't even need to scan the QR.

## Demo

[Watch the demo](https://ejectedalien-publicly-accessible.s3.ap-southeast-2.amazonaws.com/videos/authenticator_qr_keeper_demo.mp4)

## Features

- Stores QR codes in an AES-256-CBC encrypted file (compatible with `openssl`)
- Reproduces QR codes in the terminal
- Shows live TOTP codes with a countdown in both the selection list and the QR view
- Supports WiFi QR codes — displays the network name and auth type in the selection list
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

On first run, if no codes file exists, you will be prompted to create one and set a password. On subsequent runs an interactive search screen opens:

```
  Search: git
> GitHub:demo@example.com    483 921
  Google:demo@example.com    157 302
  2/5  ↑↓ navigate  Enter select  Esc quit
```

The current TOTP code for each account is shown alongside its name and updates every second — so you can often just read the code straight from the list without needing to open the QR view at all. Type to filter your accounts as you type. Search terms are space-separated and use OR logic — `git aws` matches any account containing "git" or "aws". Use `↑↓` to move between matches and **Enter** to select. **Esc** exits.

After selecting an account, the QR code is printed to the terminal and the live TOTP code is shown with a countdown bar:

```
  OTP: 483 921  [████████████████░░░░░░░░░░░░░░] 16s  (Press Enter to continue)
```

Press **Enter** or **Ctrl+C** to return to the search screen.

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

# WiFi credentials
WIFI:T:WPA2;S:MyHomeNetwork;P:mysecretpassword;;
```

WiFi entries are displayed as `WiFi: NetworkName (WPA2)` in the selection list.

You can edit the file directly using the bundled `edit-encrypted-file.sh` script (see [Shell scripts](#shell-scripts) below), which decrypts to a temp file, opens it in `$EDITOR`, and re-encrypts on save.

### Obtaining otpauth:// URLs

When a service shows you a QR code during 2FA setup:

1. Save a screenshot of the QR code image.
2. Run `qrcodes --add /path/to/screenshot.png` to import it.

Alternatively, some authenticator apps (e.g. Aegis) let you export your accounts as `otpauth://` URLs directly.

## Shell scripts

Three shell scripts live in the `scripts/` directory and are installed alongside the `qrcodes` command. They use `openssl` directly and are fully compatible with the encrypted file format.

### edit-encrypted-file.sh

The most useful of the three. It lets you edit your codes file directly without leaving the terminal:

```bash
edit-encrypted-file.sh ~/.qr/.qrcodes
```

It will:
1. Prompt for your password
2. Decrypt the file to a secure temporary directory
3. Open it in `$EDITOR` (set this to your preferred editor, e.g. `export EDITOR=nano`)
4. On exit, check whether the file changed (via SHA-256)
5. If changed: back up the original with a timestamp, then re-encrypt and save
6. If unchanged: do nothing — the encrypted file is left untouched
7. Securely delete the temporary decrypted file on exit (even on Ctrl+C)

If the file doesn't exist yet, it will offer to create a new one.

### encrypt-file.sh

Encrypts a plaintext file to an output file:

```bash
encrypt-file.sh plaintext.qrcodes ~/.qr/.qrcodes
```

Useful for creating the codes file from scratch by writing a plaintext file first (see `example.qrcodes.file` in this repo for the format), then encrypting it.

### decrypt-file.sh

Decrypts a file and prints the contents to stdout:

```bash
decrypt-file.sh ~/.qr/.qrcodes
decrypt-file.sh ~/.qr/.qrcodes > plaintext.qrcodes
```

Useful for inspecting the contents or making a plaintext backup. Redirect to a file if needed, but make sure to delete it afterwards.

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
