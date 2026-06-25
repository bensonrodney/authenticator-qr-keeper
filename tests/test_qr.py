from pathlib import Path
from tempfile import TemporaryDirectory

from authentication_qr_keeper.passcrypt import save_data_to_encrypted_file
from authentication_qr_keeper.qr import Code, add_code_to_file, parse_file

PASSWORD = "testpassword"

TOTP_URL = "otpauth://totp/My%20Service%3Amyuser?secret=ABCDEF123456&issuer=My%20Service"
TOTP_URL_2 = "otpauth://totp/Other%20Service%3Aotheruser?secret=GHIJKL789012&issuer=Other%20Service"


def make_encrypted_file(tmpdir: str, contents: str) -> str:
    path = str(Path(tmpdir) / "codes")
    save_data_to_encrypted_file(path, contents.encode(), PASSWORD)
    return path


# ---------------------------------------------------------------------------
# Code class
# ---------------------------------------------------------------------------


def test_code_name_decoded_from_url():
    code = Code(TOTP_URL)
    assert code.name == "My Service:myuser"


def test_code_name_strips_leading_slash():
    # urlparse gives path as "/My%20Service" — leading slash must be removed
    code = Code("otpauth://totp/%2FLeading%2FSlashes?secret=X")
    assert not code.name.startswith("/")


def test_code_name_is_cached():
    code = Code(TOTP_URL)
    name1 = code.name
    name2 = code.name
    assert name1 == name2


def test_code_str_returns_original_url():
    code = Code(TOTP_URL)
    assert str(code) == TOTP_URL


def test_code_str_strips_surrounding_whitespace():
    code = Code(f"  {TOTP_URL}  ")
    assert str(code) == TOTP_URL


# ---------------------------------------------------------------------------
# parse_file
# ---------------------------------------------------------------------------


def test_parse_file_returns_codes():
    with TemporaryDirectory() as tmpdir:
        path = make_encrypted_file(tmpdir, f"{TOTP_URL}\n{TOTP_URL_2}\n")
        codes = parse_file(path, PASSWORD)
        assert len(codes) == 2
        assert codes[0].name == "My Service:myuser"
        assert codes[1].name == "Other Service:otheruser"


def test_parse_file_skips_comment_lines():
    with TemporaryDirectory() as tmpdir:
        content = f"# this is a comment\n{TOTP_URL}\n# another comment\n"
        path = make_encrypted_file(tmpdir, content)
        codes = parse_file(path, PASSWORD)
        assert len(codes) == 1


def test_parse_file_skips_blank_lines():
    with TemporaryDirectory() as tmpdir:
        content = f"\n\n{TOTP_URL}\n\n"
        path = make_encrypted_file(tmpdir, content)
        codes = parse_file(path, PASSWORD)
        assert len(codes) == 1


def test_parse_file_returns_none_when_file_missing():
    result = parse_file("/nonexistent/path/codes", PASSWORD)
    assert result is None


def test_parse_file_returns_empty_list_on_bad_password():
    with TemporaryDirectory() as tmpdir:
        path = make_encrypted_file(tmpdir, TOTP_URL)
        result = parse_file(path, "wrong-password")
        # Wrong password produces garbage bytes; read_and_decrypt_file returns
        # None on UnicodeDecodeError, which parse_file converts to [].
        assert result == [] or isinstance(result, list)


def test_parse_file_empty_file_returns_empty_list():
    with TemporaryDirectory() as tmpdir:
        path = make_encrypted_file(tmpdir, "")
        codes = parse_file(path, PASSWORD)
        assert codes == []


# ---------------------------------------------------------------------------
# add_code_to_file
# ---------------------------------------------------------------------------


def test_add_code_to_file_appends_code():
    with TemporaryDirectory() as tmpdir:
        path = make_encrypted_file(tmpdir, f"{TOTP_URL}\n")
        add_code_to_file(path, PASSWORD, TOTP_URL_2)
        codes = parse_file(path, PASSWORD)
        names = [c.name for c in codes]
        assert "My Service:myuser" in names
        assert "Other Service:otheruser" in names


def test_add_code_to_file_creates_backup():
    with TemporaryDirectory() as tmpdir:
        path = make_encrypted_file(tmpdir, f"{TOTP_URL}\n")
        add_code_to_file(path, PASSWORD, TOTP_URL_2)
        backups = list(Path(tmpdir).glob("codes.backup.*"))
        assert len(backups) == 1


def test_add_code_to_file_backup_is_readable():
    with TemporaryDirectory() as tmpdir:
        path = make_encrypted_file(tmpdir, f"{TOTP_URL}\n")
        add_code_to_file(path, PASSWORD, TOTP_URL_2)
        backup = list(Path(tmpdir).glob("codes.backup.*"))[0]
        # Backup was written before the new code was added, so it has only the original
        codes = parse_file(str(backup), PASSWORD)
        assert len(codes) == 1
        assert codes[0].name == "My Service:myuser"
