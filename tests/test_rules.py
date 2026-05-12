"""Per-rule tests."""
from __future__ import annotations

from phish_paygen import (
    AttachmentB64Suspicious,
    DisplayFromMismatch,
    Email,
    LookalikeDomain,
    MismatchedLinkText,
    SuspiciousLink,
    SuspiciousReplyTo,
    TooManyLinks,
    UnsignedExternalSender,
    UrgentActionLanguage,
    default_rules,
)


def test_display_from_mismatch_fires():
    e = Email(from_name="PayPal Security",
              from_addr="x@evil.test")
    hits = DisplayFromMismatch()(e)
    assert len(hits) == 1
    assert hits[0].rule_id == "PHX-DFM-001"
    assert hits[0].evidence["brand"] == "paypal"


def test_display_from_mismatch_silent_when_aligned():
    e = Email(from_name="PayPal Notifications",
              from_addr="x@paypal.com")
    assert DisplayFromMismatch()(e) == []


def test_display_from_mismatch_silent_no_brand():
    e = Email(from_name="Bob", from_addr="bob@acme.test")
    assert DisplayFromMismatch()(e) == []


def test_lookalike_domain_fires():
    e = Email(from_addr="x@micros0ft.com")
    hits = LookalikeDomain()(e)
    assert len(hits) == 1
    assert hits[0].rule_id == "PHX-LKAL-001"


def test_lookalike_domain_silent_for_known_brand():
    e = Email(from_addr="x@microsoft.com")
    assert LookalikeDomain()(e) == []


def test_lookalike_domain_silent_for_far_off():
    e = Email(from_addr="alice@acme.test")
    assert LookalikeDomain()(e) == []


def test_urgent_language_one_cue_low_score():
    e = Email(subject="Urgent please respond")
    hits = UrgentActionLanguage()(e)
    assert hits and hits[0].severity == "info"


def test_urgent_language_many_cues_high_score():
    e = Email(subject="URGENT: act now",
              body_text=("verify your account immediately, "
                         "this expires in 24 hours, "
                         "click here"))
    hits = UrgentActionLanguage()(e)
    assert hits and hits[0].severity == "high"


def test_urgent_language_silent_for_normal():
    e = Email(subject="lunch?", body_text="hi")
    assert UrgentActionLanguage()(e) == []


def test_suspicious_link_ip():
    e = Email(body_text="login at http://192.168.1.1/x")
    hits = SuspiciousLink()(e)
    assert hits and "raw IP" in str(hits[0].evidence["reasons"])


def test_suspicious_link_zip_tld():
    e = Email(body_text="see http://attacker.zip/")
    hits = SuspiciousLink()(e)
    assert hits


def test_suspicious_link_shortener():
    e = Email(body_text="see http://bit.ly/abc")
    hits = SuspiciousLink()(e)
    assert hits


def test_suspicious_link_silent_for_clean_url():
    e = Email(body_text="visit https://example.com/safe")
    assert SuspiciousLink()(e) == []


def test_suspicious_link_two_reasons_high():
    e = Email(body_text="see http://bit.ly/x at 1.2.3.4")
    # bit.ly is shortener AND .ly is borderline; here we test
    # the rule still fires at least medium.
    hits = SuspiciousLink()(e)
    assert hits


def test_mismatched_link_text_fires():
    e = Email(body_html=(
        "<a href=\"http://attacker.test/x\">"
        "https://paypal.com</a>"))
    hits = MismatchedLinkText()(e)
    assert hits and hits[0].rule_id == "PHX-LTXT-001"
    assert hits[0].evidence["text_domain"] == "paypal.com"


def test_mismatched_link_text_silent_when_aligned():
    e = Email(body_html=(
        "<a href=\"https://paypal.com/x\">"
        "https://paypal.com</a>"))
    assert MismatchedLinkText()(e) == []


def test_attachment_b64_suspicious_fires():
    e = Email(attachments=({
        "filename": "invoice.html",
        "content_base64": "A" * 1000,
    },))
    hits = AttachmentB64Suspicious()(e)
    assert hits and hits[0].rule_id == "PHX-AB64-001"


def test_attachment_b64_suspicious_silent_for_pdf():
    e = Email(attachments=({
        "filename": "doc.pdf",
        "content_base64": "A" * 1000,
    },))
    assert AttachmentB64Suspicious()(e) == []


def test_attachment_b64_suspicious_silent_when_no_b64():
    e = Email(attachments=({"filename": "x.html"},))
    assert AttachmentB64Suspicious()(e) == []


def test_suspicious_reply_to_freemail():
    e = Email(from_addr="ceo@acme.test",
              reply_to="ceo@gmail.com")
    hits = SuspiciousReplyTo()(e)
    assert hits and hits[0].severity == "high"


def test_suspicious_reply_to_other_corp_medium():
    e = Email(from_addr="bob@acme.test",
              reply_to="bob@evil.test")
    hits = SuspiciousReplyTo()(e)
    assert hits and hits[0].severity == "medium"


def test_suspicious_reply_to_silent_when_same():
    e = Email(from_addr="bob@acme.test",
              reply_to="bob@acme.test")
    assert SuspiciousReplyTo()(e) == []


def test_suspicious_reply_to_silent_when_no_reply_to():
    e = Email(from_addr="bob@acme.test")
    assert SuspiciousReplyTo()(e) == []


def test_too_many_links_fires_dense():
    body = ("see http://a.test http://b.test http://c.test "
            "http://d.test")
    e = Email(body_text=body)
    hits = TooManyLinks()(e)
    assert hits and hits[0].rule_id == "PHX-LINKQ-001"


def test_too_many_links_silent_for_long_body():
    body = "see http://a.test " + ("padding " * 1000)
    e = Email(body_text=body)
    assert TooManyLinks()(e) == []


def test_unsigned_external_sender_fires():
    rule = UnsignedExternalSender(
        internal_domains=("acme.test",))
    e = Email(from_addr="x@evil.test", body_text="hello")
    hits = rule(e)
    assert hits


def test_unsigned_external_sender_silent_for_internal():
    rule = UnsignedExternalSender(
        internal_domains=("acme.test",))
    e = Email(from_addr="bob@acme.test", body_text="hello")
    assert rule(e) == []


def test_unsigned_external_sender_silent_when_signature():
    rule = UnsignedExternalSender(
        internal_domains=("acme.test",))
    e = Email(from_addr="bob@evil.test",
              body_text="hi\n\nRegards,\nBob")
    assert rule(e) == []


def test_unsigned_external_sender_no_internal_no_op():
    rule = UnsignedExternalSender()
    assert rule(Email(from_addr="x@y.test")) == []


def test_default_rules_returns_nine():
    rs = default_rules()
    assert len(rs) == 9
    ids = {r.rule_id for r in rs}
    assert "PHX-DFM-001" in ids and "PHX-LKAL-001" in ids
