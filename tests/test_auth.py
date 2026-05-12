"""AuthorizationGate tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from phish_paygen import AuthorizationGate
from phish_paygen.auth import (
    AUTHORISATION_STATEMENT,
    AuthorizationStatus,
)


def test_default_is_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("AGSBX_RED_TEAM_AUTH", raising=False)
    monkeypatch.setenv(
        "AGSBX_RED_TEAM_AUTH_FILE",
        str(tmp_path / "no_such_file"))
    g = AuthorizationGate()
    st = g.check()
    assert st.allowed is False
    assert "AGSBX_RED_TEAM_AUTH" in st.reason


def test_env_alone_not_enough(monkeypatch, tmp_path):
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH", "1")
    monkeypatch.setenv(
        "AGSBX_RED_TEAM_AUTH_FILE",
        str(tmp_path / "missing"))
    st = AuthorizationGate().check()
    assert st.allowed is False
    assert "not found" in st.reason


def test_file_alone_not_enough(monkeypatch, tmp_path):
    p = tmp_path / "auth.txt"
    p.write_text(AUTHORISATION_STATEMENT)
    monkeypatch.delenv("AGSBX_RED_TEAM_AUTH", raising=False)
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH_FILE", str(p))
    st = AuthorizationGate().check()
    assert st.allowed is False
    assert st.file_present is True
    assert st.statement_present is True


def test_file_present_but_no_statement(monkeypatch, tmp_path):
    p = tmp_path / "auth.txt"
    p.write_text("I have permission. trust me.")
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH", "1")
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH_FILE", str(p))
    st = AuthorizationGate().check()
    assert st.allowed is False
    assert "does not contain" in st.reason
    assert st.statement_present is False


def test_full_open(open_gate):
    st = open_gate.check()
    assert st.allowed is True
    assert st.reason == "ok"
    assert st.env_present and st.file_present
    assert st.statement_present


def test_is_allowed_true_when_open(open_gate):
    assert open_gate.is_allowed() is True


def test_is_allowed_false_when_closed(gate):
    assert gate.is_allowed() is False


def test_status_to_dict():
    s = AuthorizationStatus(True, "ok", True, True, True)
    d = s.to_dict()
    assert d["allowed"] is True
    assert d["reason"] == "ok"


def test_default_auth_file_is_home(monkeypatch):
    monkeypatch.delenv("AGSBX_RED_TEAM_AUTH_FILE",
                       raising=False)
    g = AuthorizationGate()
    p = g.auth_file_path()
    assert str(p).endswith(".agsbx_red_team_auth")


def test_unreadable_file_is_treated_as_no_statement(
        monkeypatch, tmp_path):
    p = tmp_path / "d"
    p.mkdir()  # path exists but is a directory.
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH", "1")
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH_FILE", str(p))
    st = AuthorizationGate().check()
    assert st.allowed is False
    assert st.file_present is False  # is_file() returns False


def test_custom_statement(monkeypatch, tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("MY-CUSTOM-OK")
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH", "1")
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH_FILE", str(p))
    g = AuthorizationGate(statement="MY-CUSTOM-OK")
    assert g.is_allowed() is True
