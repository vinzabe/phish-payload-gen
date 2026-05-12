"""Defang/refang tests."""
from __future__ import annotations

import pytest

from phish_paygen import defang, defang_url, refang


@pytest.mark.parametrize("inp,exp", [
    ("https://example.com",        "hxxps[://]example[.]com"),
    ("http://foo.bar/path",        "hxxp[://]foo[.]bar/path"),
    ("ftp://files.example.com",
     "fxxp[://]files[.]example[.]com"),
    ("https://example.com/login?x=1",
     "hxxps[://]example[.]com/login?x=1"),
])
def test_defang_url_simple(inp, exp):
    assert defang_url(inp) == exp


def test_defang_inside_text():
    out = defang("Visit https://evil.example/login now")
    assert "hxxps[://]evil[.]example/login" in out


def test_defang_ipv4():
    assert "1[.]2[.]3[.]4" in defang("ping 1.2.3.4 for me")


def test_defang_email_address():
    assert "alice[@]example[.]com" in defang(
        "mail alice@example.com please")


def test_refang_round_trip():
    txt = ("see https://example.com/login or "
           "http://1.2.3.4/x or alice@example.com")
    assert refang(defang(txt)) == txt


def test_refang_ftp():
    assert "ftp://example.com" in refang(
        "fxxp[://]example[.]com")


def test_defang_no_change_for_plain_text():
    assert defang("hello world") == "hello world"


def test_defang_handles_empty():
    assert defang("") == ""
    assert refang("") == ""


def test_defang_does_not_double_process():
    once = defang("https://example.com")
    twice = defang(once)
    # Already-defanged stays defanged once; '[' is preserved.
    assert twice.count("[://]") == 1


def test_defang_url_passthrough_for_bare_host():
    assert defang_url("example.com") == "example[.]com"


def test_defang_handles_uppercase_scheme():
    assert defang_url("HTTPS://Example.com") \
        .startswith("hxxps[://]")


def test_refang_handles_uppercase_xx():
    assert refang("HXXPS[://]example[.]com") == \
        "https://example.com"


def test_defang_ip_at_word_boundary_only():
    # IPv4 in a sentence still gets bracketed; we just check the
    # rest of the sentence is untouched.
    out = defang("ping 10.0.0.1 done")
    assert out.startswith("ping ")
    assert out.endswith(" done")
    assert "10[.]0[.]0[.]1" in out
