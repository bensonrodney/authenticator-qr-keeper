#!/usr/bin/env python3

"""
Reproduce Google Authenticator QR codes from a password-protected file at ~/.qr/.qrcodes.

Displays a list of accounts and lets you select which QR code to view.
"""

import copy
import curses
import getpass
import io
import re
import select
import sys
import time
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from shutil import copyfile
from urllib.parse import parse_qs, unquote, urlparse

import pyotp
from cv2 import QRCodeDetector, imread
from qrcode import QRCode

from authentication_qr_keeper.passcrypt import (
    encrypt_file_bytes,
    load_data_from_encrypted_file,
)

TYPE_TOTP = "totp"
TYPE_HOTP = "hotp"

user = getpass.getuser()
src_file_dir = Path(f"/home/{user}/.qr")
src_file = src_file_dir / ".qrcodes"
leading_slashes = re.compile("^[/]{1,}")


def read_and_decrypt_file(file, password):
    try:
        plaintext = load_data_from_encrypted_file(file, password)
        return io.StringIO(plaintext.decode())
    except UnicodeDecodeError:
        return None


def read_qr_code(image_file):
    try:
        img = imread(image_file)
        detector = QRCodeDetector()
        value, points, straight_qrcode = detector.detectAndDecode(img)
        return value
    except Exception as exc:
        print(str(exc))
        return None


class Code:
    def __init__(self, url):
        self._raw = url.strip()
        self._url = urlparse(self._raw)
        self._name = None

    def _get_name(self):
        if not self._name:
            self._name = leading_slashes.sub("", unquote(self._url.path))
        return copy.copy(self._name)

    name = property(_get_name)

    def __str__(self):
        return copy.copy(self._raw)

    @property
    def current_otp(self) -> str | None:
        if self._url.netloc != TYPE_TOTP:
            return None
        params = parse_qs(self._url.query)
        secrets = params.get("secret", [])
        if not secrets:
            return None
        try:
            return pyotp.TOTP(secrets[0]).now()
        except Exception:
            return None

    def show_qr(self):
        code = QRCode()
        code.add_data(str(self))
        code.print_ascii(invert=True)
        if self.current_otp is None:
            return
        try:
            while True:
                otp = self.current_otp
                remaining = 30 - int(time.time()) % 30
                bar = "█" * remaining + "░" * (30 - remaining)
                otp_fmt = f"{otp[:3]} {otp[3:]}"
                print(f"\r  OTP: {otp_fmt}  [{bar}] {remaining:2d}s  (Press Enter to continue)  ", end="", flush=True)
                if select.select([sys.stdin], [], [], 1)[0]:
                    sys.stdin.readline()
                    break
        except KeyboardInterrupt:
            pass
        print()


def parse_file(src, password):
    codes = []
    try:
        data_stream = read_and_decrypt_file(src, password)
        if not data_stream:
            return []
        lines = [line.strip() for line in data_stream.readlines()]
        codes = [Code(line) for line in lines if (len(line) > 0) and (line[0] != "#")]
        return codes
    except FileNotFoundError:
        return None


def filter_codes(codes: list, query: str) -> list:
    if not query:
        return list(codes)
    terms = query.lower().split()
    return [c for c in codes if any(t in c.name.lower() for t in terms)]


def _interactive_select(codes: list) -> "Code | None":
    def run(stdscr):
        try:
            curses.use_default_colors()
        except Exception:
            pass
        curses.curs_set(1)

        query = ""
        cursor_pos = 0
        scroll_offset = 0

        while True:
            height, width = stdscr.getmaxyx()
            list_height = max(1, height - 3)

            matches = filter_codes(codes, query)

            if matches:
                cursor_pos = max(0, min(cursor_pos, len(matches) - 1))
            else:
                cursor_pos = 0

            if cursor_pos < scroll_offset:
                scroll_offset = cursor_pos
            elif cursor_pos >= scroll_offset + list_height:
                scroll_offset = cursor_pos - list_height + 1

            stdscr.erase()

            prompt = f"  Search: {query}"
            try:
                stdscr.addstr(0, 0, prompt[:width])
            except curses.error:
                pass

            for i in range(list_height):
                idx = scroll_offset + i
                if idx >= len(matches):
                    break
                name = matches[idx].name
                try:
                    if idx == cursor_pos:
                        stdscr.addstr(i + 1, 0, f"> {name}"[:width], curses.A_REVERSE)
                    else:
                        stdscr.addstr(i + 1, 0, f"  {name}"[:width])
                except curses.error:
                    pass

            status = f"  {len(matches)}/{len(codes)}  ↑↓ navigate  Enter select  Esc quit"
            try:
                stdscr.addstr(height - 1, 0, status[:width])
            except curses.error:
                pass

            try:
                stdscr.move(0, min(len(prompt), width - 1))
            except curses.error:
                pass

            stdscr.refresh()

            key = stdscr.getch()

            if key == curses.KEY_UP:
                cursor_pos = max(0, cursor_pos - 1)
            elif key == curses.KEY_DOWN:
                if matches:
                    cursor_pos = min(len(matches) - 1, cursor_pos + 1)
            elif key in (10, 13):
                return matches[cursor_pos] if matches else None
            elif key == 27:
                return None
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                if query:
                    query = query[:-1]
                    cursor_pos = 0
                    scroll_offset = 0
            elif 32 <= key <= 126:
                query += chr(key)
                cursor_pos = 0
                scroll_offset = 0

    try:
        return curses.wrapper(run)
    except KeyboardInterrupt:
        return None


def select_and_print_code(codes):
    codes.sort(key=Code._get_name)
    selected = _interactive_select(codes)
    if selected is None:
        return 1
    print(selected.name)
    selected.show_qr()
    return 0


def create_file():
    password1 = getpass.getpass("Enter a password for the encrypted file: ")
    password2 = getpass.getpass("Enter the password again: ")
    if password1 != password2:
        print("Error: passwords don't match.")
        return False

    if not src_file_dir.is_dir():
        src_file_dir.mkdir()
    with open(str(src_file), "wb") as _file:
        encrypted_data = encrypt_file_bytes(b"", password1)
        _file.write(encrypted_data)
    return True


def do_show_codes() -> int:
    if not src_file.is_file():
        print(f"File doesn't exist: {src_file}")
        print("Creating file now...")
        file_created = create_file()
        if file_created:
            print("File now exists but will be empty. You need to add codes before it will be useful.")
        else:
            print(f"Error creating file: {src_file}")
        return 0 if file_created else 1

    try:
        password = getpass.getpass()
    except KeyboardInterrupt:
        print()
        return 0

    codes = parse_file(str(src_file), password)
    if codes is None:
        print("ERROR! Couldn't parse source file.")
        return 1

    if len(codes) < 1:
        print("ERROR: No codes found in source file or the password is incorrect.")
        return 1

    choice_regex = re.compile(r"^([yY]|[yY][eE][sS]|)$")
    while True:
        try:
            if select_and_print_code(codes) != 0:
                print()
                break
            choice = input("Display another code? [Yn]: ")
            if not choice_regex.search(choice):
                break
        except KeyboardInterrupt:
            print()
            break

    return 0


def add_code_to_file(src, password, code):
    data_stream = read_and_decrypt_file(src, password)
    if not data_stream:
        raise RuntimeError("Failed to read source file")

    lines = [line.strip() for line in data_stream.readlines()]
    lines.append(code.strip())
    lines.append("")

    data = "\n".join(lines)
    encrypted_data = encrypt_file_bytes(data.encode("utf-8"), password)

    now = datetime.now().strftime("%Y%m%d-%H%M%S")
    copyfile(src, f"{src}.backup.{now}")

    with open(src, "wb") as outfile:
        outfile.write(encrypted_data)


def do_add_code(image_file_path: str | Path) -> int:
    if not src_file.is_file():
        print(f"File doesn't exist: {src_file}")
        file_created = create_file()
        if file_created:
            print("File is now created, try again.")
        else:
            print(f"Error creating file: {src_file}")
        return 0 if file_created else 1

    if not isinstance(image_file_path, Path):
        image_file_path = Path(image_file_path)

    if not image_file_path.is_file():
        print(f"ERROR: file not found - '{image_file_path}'")
        return 1

    data = read_qr_code(str(image_file_path))
    if not data:
        print("ERROR: error reading QR code or no data within the QR code.")
        return 1

    print(f"#### {data}")

    if not src_file.is_file():
        print("ERROR: source file not found. Exiting.")
        return 1

    try:
        password = getpass.getpass()
    except KeyboardInterrupt:
        print()
        return 0

    try:
        add_code_to_file(str(src_file), password, data)
    except Exception:
        print("ERROR: failed to add code to file")
        return 1

    return 0


def main():
    parser = ArgumentParser()
    parser.add_argument("-a", "--add", metavar="IMAGE_FILE_PATH", default=None, help="Add new qrcode from a qrcode image.")
    args = parser.parse_args()

    if args.add:
        return do_add_code(args.add)

    return do_show_codes()


if __name__ == "__main__":
    sys.exit(main())
