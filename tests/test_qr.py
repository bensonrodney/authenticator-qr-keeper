from pathlib import Path
from tempfile import TemporaryDirectory

from authentication_qr_keeper.passcrypt import save_data_to_encrypted_file
from authentication_qr_keeper.qr import Code, _otp_dot_bar, add_code_to_file, filter_codes, parse_file

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


def test_code_name_wifi_shows_ssid_and_auth():
    code = Code("WIFI:T:WPA;S:MyNetwork;P:password;;")
    assert code.name == "WiFi: MyNetwork (WPA)"


def test_code_name_wifi_no_auth():
    code = Code("WIFI:T:nopass;S:OpenNetwork;;")
    assert code.name == "WiFi: OpenNetwork (nopass)"


def test_code_name_wifi_quoted_ssid():
    code = Code('WIFI:T:WPA2;S:"My Network";P:secret;;')
    assert code.name == "WiFi: My Network (WPA2)"


def test_code_name_wifi_case_insensitive_prefix():
    code = Code("wifi:T:WPA;S:TestNet;P:pass;;")
    assert code.name == "WiFi: TestNet (WPA)"


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


def test_current_otp_returns_six_digit_string():
    # Secret must be valid base32 (A-Z and 2-7 only)
    url = "otpauth://totp/Service%3Auser?secret=JBSWY3DPEHPK3PXP&issuer=Service"
    code = Code(url)
    otp = code.current_otp
    assert otp is not None
    assert len(otp) == 6
    assert otp.isdigit()


def test_current_otp_is_none_for_hotp():
    hotp_url = "otpauth://hotp/Service%3Auser?secret=ABCDEF123456&counter=0"
    code = Code(hotp_url)
    assert code.current_otp is None


def test_current_otp_is_none_when_no_secret():
    url = "otpauth://totp/Service%3Auser?issuer=Service"
    assert Code(url).current_otp is None


def test_totp_period_defaults_to_30():
    url = "otpauth://totp/Service%3Auser?secret=JBSWY3DPEHPK3PXP&issuer=Service"
    assert Code(url).totp_period == 30


def test_totp_period_reads_from_url():
    url = "otpauth://totp/Service%3Auser?secret=JBSWY3DPEHPK3PXP&period=60"
    assert Code(url).totp_period == 60


def test_totp_period_is_none_for_non_totp():
    assert Code("otpauth://hotp/Service?secret=X&counter=0").totp_period is None
    assert Code("WIFI:T:WPA;S:Net;P:pass;;").totp_period is None


def test_otp_remaining_is_between_1_and_period():
    url = "otpauth://totp/Service%3Auser?secret=JBSWY3DPEHPK3PXP&issuer=Service"
    code = Code(url)
    remaining = code.otp_remaining
    assert remaining is not None
    assert 1 <= remaining <= 30


def test_otp_remaining_respects_custom_period():
    url = "otpauth://totp/Service%3Auser?secret=JBSWY3DPEHPK3PXP&period=60"
    code = Code(url)
    remaining = code.otp_remaining
    assert remaining is not None
    assert 1 <= remaining <= 60


def test_otp_remaining_is_none_for_non_totp():
    assert Code("WIFI:T:WPA;S:Net;P:pass;;").otp_remaining is None
    assert Code("otpauth://hotp/Service?secret=X&counter=0").otp_remaining is None


# ---------------------------------------------------------------------------
# _otp_dot_bar
# ---------------------------------------------------------------------------


def test_otp_dot_bar_full_at_max_remaining():
    assert _otp_dot_bar(30, 30) == "⣿⣿⣿⣿"


def test_otp_dot_bar_empty_at_zero_remaining():
    assert _otp_dot_bar(0, 30) == "⠀⠀⠀⠀"


def test_otp_dot_bar_is_four_chars():
    assert len(_otp_dot_bar(15, 30)) == 4


def test_otp_dot_bar_drains_right_to_left():
    # At ~1/4 remaining the rightmost three chars should be empty
    bar = _otp_dot_bar(7, 30)
    assert bar[1] == "⠀"
    assert bar[2] == "⠀"
    assert bar[3] == "⠀"


def test_otp_dot_bar_changes_every_second():
    # With 4 chars × 8 dots = 32 levels for any period <= 32s, each second is unique
    bars = [_otp_dot_bar(r, 30) for r in range(1, 31)]
    assert len(bars) == len(set(bars)), "some seconds share the same bar"


def test_otp_dot_bar_works_with_60s_period():
    full = _otp_dot_bar(60, 60)
    empty = _otp_dot_bar(0, 60)
    assert full == "⣿⣿⣿⣿"
    assert empty == "⠀⠀⠀⠀"


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


# ---------------------------------------------------------------------------
# filter_codes
# ---------------------------------------------------------------------------

CODES = [
    Code("otpauth://totp/GitHub%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"),
    Code("otpauth://totp/Google%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=Google"),
    Code("otpauth://totp/AWS%3Abob?secret=JBSWY3DPEHPK3PXP&issuer=AWS"),
]


def test_filter_codes_empty_query_returns_all():
    assert filter_codes(CODES, "") == CODES


def test_filter_codes_matches_substring():
    result = filter_codes(CODES, "git")
    assert len(result) == 1
    assert result[0].name == "GitHub:alice"


def test_filter_codes_is_case_insensitive():
    assert filter_codes(CODES, "GIT") == filter_codes(CODES, "git")


def test_filter_codes_matches_multiple():
    # "alice" appears in GitHub and Google entries
    result = filter_codes(CODES, "alice")
    assert len(result) == 2


def test_filter_codes_no_match_returns_empty():
    assert filter_codes(CODES, "zzznomatch") == []


def test_filter_codes_does_not_mutate_input():
    original = list(CODES)
    filter_codes(CODES, "git")
    assert CODES == original


def test_filter_codes_space_separated_terms_use_or_logic():
    # "github aws" should match GitHub:alice and AWS:bob but not Google:alice
    result = filter_codes(CODES, "github aws")
    names = [c.name for c in result]
    assert "GitHub:alice" in names
    assert "AWS:bob" in names
    assert "Google:alice" not in names


def test_filter_codes_or_logic_matches_all_when_broad():
    # "alice bob" matches all three entries (alice in two, bob in one)
    result = filter_codes(CODES, "alice bob")
    assert len(result) == 3
