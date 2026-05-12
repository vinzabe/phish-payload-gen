"""Shared fixtures for phish_paygen tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phish_paygen import (  # noqa: E402
    AuthorizationGate,
    Email,
    LureGenerator,
    PhishingDetector,
    TemplateLibrary,
)


@pytest.fixture
def library() -> TemplateLibrary:
    return TemplateLibrary()


@pytest.fixture
def detector() -> PhishingDetector:
    return PhishingDetector(internal_domains=("acme.test",))


@pytest.fixture
def gate(monkeypatch, tmp_path) -> AuthorizationGate:
    """Default: gate is *closed* — no env var, no file."""
    monkeypatch.delenv("AGSBX_RED_TEAM_AUTH", raising=False)
    monkeypatch.setenv(
        "AGSBX_RED_TEAM_AUTH_FILE",
        str(tmp_path / "no_such_file"))
    return AuthorizationGate()


@pytest.fixture
def open_gate(monkeypatch, tmp_path) -> AuthorizationGate:
    """A fully-authorised gate, written into tmp_path."""
    auth_file = tmp_path / "auth.txt"
    auth_file.write_text(
        "I confirm I have written authorisation from the "
        "target organisation to run a phishing-awareness "
        "exercise.\n")
    monkeypatch.setenv("AGSBX_RED_TEAM_AUTH", "1")
    monkeypatch.setenv(
        "AGSBX_RED_TEAM_AUTH_FILE", str(auth_file))
    return AuthorizationGate()


@pytest.fixture
def stub_generator(library, gate) -> LureGenerator:
    return LureGenerator(library=library, gate=gate)


@pytest.fixture
def benign_email() -> Email:
    return Email(
        subject="Lunch tomorrow?",
        from_addr="bob@acme.test",
        from_name="Bob Builder",
        to_addrs=("alice@acme.test",),
        body_text=("Hi Alice,\n\nWant to grab lunch tomorrow "
                   "at 12:30?\n\nRegards,\nBob"))


@pytest.fixture
def obvious_phish() -> Email:
    return Email(
        subject=(
            "URGENT: Your PayPal account will be suspended "
            "immediately"),
        from_addr="security@paypaI-secure.zip",
        from_name="PayPal Security",
        reply_to="paypal-help@gmail.com",
        body_text=(
            "Click here immediately to verify your account: "
            "http://192.168.1.1/login\n"
            "Action required within 24 hours."),
        body_html=(
            "<a href=\"http://attacker.zip/x\">"
            "https://paypal.com</a>"))


@pytest.fixture
def lookalike_email() -> Email:
    return Email(
        subject="Account update",
        from_addr="no-reply@micros0ft.com",
        from_name="Microsoft",
        body_text="Please review.\n\nRegards,\nMicrosoft Team")
