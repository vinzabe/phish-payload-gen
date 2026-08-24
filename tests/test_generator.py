"""The structural guarantees: no credential capture, always watermarked, scoped."""
import datetime as dt

import pytest

from phishgen.authorization import Authorization, AuthorizationError
from phishgen.generator import EMBEDDED_MARKER, VISIBLE_WATERMARK, _landing_page, generate

TODAY = dt.date(2026, 8, 24)


def _auth(secret="s", scope=("corp.example.com",)):
    return Authorization("E1", "Jane", scope, dt.date(2027, 1, 1)).sign(secret)


def test_landing_page_has_no_credential_form():
    """The crux: there is no code path that renders an input for a password."""
    html = _landing_page("E1", ("urgency",)).lower()
    for forbidden in ("<form", "<input", "type=\"password\"", "name=\"pass",
                      "<textarea", "credential"):
        assert forbidden not in html, f"landing page contains {forbidden!r}"


def test_landing_page_is_educational_and_watermarked():
    html = _landing_page("E1", ("urgency", "generic greeting"))
    assert VISIBLE_WATERMARK in html
    assert EMBEDDED_MARKER in html
    assert "urgency" in html and "generic greeting" in html


def test_generate_requires_valid_auth():
    with pytest.raises(AuthorizationError):
        generate(_auth(secret="real"), "password-expiry", "a@corp.example.com",
                 secret="wrong", base_url="https://x", today=TODAY)


def test_generate_refuses_out_of_scope_target():
    with pytest.raises(AuthorizationError, match="not in the authorized scope"):
        generate(_auth(), "password-expiry", "victim@gmail.com",
                 secret="s", base_url="https://x", today=TODAY)


def test_generated_artifact_is_watermarked():
    art = generate(_auth(), "password-expiry", "alice@corp.example.com",
                   secret="s", base_url="https://x", today=TODAY)
    assert art.is_watermarked
    assert VISIBLE_WATERMARK in art.body
    assert any(k == EMBEDDED_MARKER for k, _ in art.headers)


def test_artifact_records_approver():
    art = generate(_auth(), "shared-document", "bob@corp.example.com",
                   secret="s", base_url="https://x", today=TODAY)
    assert dict(art.headers)["X-Authorized-By"] == "Jane"


def test_unknown_template_rejected():
    with pytest.raises(ValueError, match="unknown template"):
        generate(_auth(), "no-such", "a@corp.example.com",
                 secret="s", base_url="https://x", today=TODAY)


def test_tracking_id_is_deterministic():
    a1 = generate(_auth(), "password-expiry", "a@corp.example.com",
                  secret="s", base_url="https://x", today=TODAY)
    a2 = generate(_auth(), "password-expiry", "a@corp.example.com",
                  secret="s", base_url="https://x", today=TODAY)
    assert a1.tracking_id == a2.tracking_id


def test_body_contains_no_input_field():
    art = generate(_auth(), "password-expiry", "a@corp.example.com",
                   secret="s", base_url="https://x", today=TODAY)
    assert "<input" not in art.landing_page_html
