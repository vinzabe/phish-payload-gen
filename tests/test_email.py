"""Email model tests."""
from __future__ import annotations

from phish_paygen import Email


def test_default_email_empty():
    e = Email()
    assert e.subject == ""
    assert e.to_addrs == ()
    assert e.attachments == ()


def test_header_case_insensitive():
    e = Email(headers={"X-Custom": "1"})
    assert e.header("x-custom") == "1"
    assert e.header("X-CUSTOM") == "1"
    assert e.header("missing", "d") == "d"


def test_to_dict_round_trip():
    e = Email(subject="hi", from_addr="a@b.test",
              to_addrs=("c@d.test",), headers={"X": "y"},
              attachments=({"filename": "x.txt"},))
    d = e.to_dict()
    e2 = Email.from_dict(d)
    assert e2.subject == "hi"
    assert e2.to_addrs == ("c@d.test",)
    assert e2.headers == {"X": "y"}
    assert e2.attachments == ({"filename": "x.txt"},)


def test_from_dict_handles_partial():
    e = Email.from_dict({"subject": "x"})
    assert e.subject == "x"
    assert e.from_addr == ""


def test_email_is_frozen():
    e = Email()
    try:
        e.subject = "no"  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("Email should be frozen")


def test_email_keeps_html_body():
    e = Email(body_html="<a href='x'>y</a>")
    assert "href" in e.body_html
