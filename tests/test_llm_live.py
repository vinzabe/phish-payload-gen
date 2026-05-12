"""LLM_LIVE: 5 tests for PhishingExplainer using the real API.

These exercise *only* the explainer (a defender-side analyst tool).
The lure generator is intentionally NOT tested live — realistic
generation requires the auth gate to be open, and we want the
default test environment to never produce realistic phishing copy.
"""
from __future__ import annotations

import os
import re

import pytest

LIVE = os.environ.get("LLM_LIVE", "0") == "1"
pytestmark = pytest.mark.skipif(not LIVE, reason="LLM_LIVE not set")


class _LiveCache:
    _exp = None

    @classmethod
    def explain(cls):
        if cls._exp is None:
            from phish_paygen import (
                Email, PhishingDetector, PhishingExplainer)
            from phish_paygen.llm_client import LLMClient

            email = Email(
                subject=("URGENT: Your PayPal account will be "
                         "suspended in 24 hours"),
                from_addr="security@paypaI-secure.zip",
                from_name="PayPal Security",
                reply_to="paypal-help@gmail.com",
                body_text=(
                    "Click here immediately to verify your "
                    "account: http://192.168.1.1/login"),
                body_html=(
                    "<a href=\"http://attacker.zip/x\">"
                    "https://paypal.com</a>"))
            report = PhishingDetector().analyze(email)
            llm = LLMClient(timeout=180.0)
            cls._exp = PhishingExplainer(llm=llm).explain(report)
        return cls._exp


def test_live_returns_text():
    e = _LiveCache.explain()
    assert e.text and e.text.strip()


def test_live_used_rules_nonempty():
    e = _LiveCache.explain()
    assert len(e.used_rules) >= 3


def test_live_text_mentions_known_rule_or_keyword():
    e = _LiveCache.explain()
    low = e.text.lower()
    used_low = {r.lower() for r in e.used_rules}
    has_rule = any(r in low for r in used_low)
    has_keyword = any(k in low for k in (
        "paypal", "phishing", "urgent", "lookalike",
        "spoof", "suspicious"))
    assert has_rule or has_keyword


def test_live_no_unknown_rule_in_text():
    e = _LiveCache.explain()
    rules = {m.group(0).upper() for m in re.finditer(
        r"PHX-[A-Z]+-\d+", e.text, flags=re.IGNORECASE)}
    known = {r.upper() for r in e.used_rules}
    assert rules.issubset(known)


def test_live_response_short_enough():
    e = _LiveCache.explain()
    assert len(e.text) < 4000
