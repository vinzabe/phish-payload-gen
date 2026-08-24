"""Render simulation artifacts — only for authorized, in-scope targets, always
watermarked, never with a credential form.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib

from .authorization import Authorization, AuthorizationError
from .templates import TEMPLATES

# Visible + embedded markers so any artifact is identifiable as a simulation even
# if it leaks outside the exercise.
VISIBLE_WATERMARK = "[SECURITY AWARENESS SIMULATION — not a real message]"
EMBEDDED_MARKER = "X-Phishing-Simulation"


@dataclasses.dataclass(frozen=True, slots=True)
class Artifact:
    engagement_id: str
    template_id: str
    target: str
    tracking_id: str
    subject: str
    body: str
    headers: tuple[tuple[str, str], ...]
    landing_page_html: str

    @property
    def is_watermarked(self) -> bool:
        return (VISIBLE_WATERMARK in self.body
                and any(k == EMBEDDED_MARKER for k, _ in self.headers))


def _tracking_id(engagement_id: str, target: str, template_id: str) -> str:
    return hashlib.sha256(
        f"{engagement_id}\x1f{target}\x1f{template_id}".encode()).hexdigest()[:16]


def _landing_page(engagement_id: str, teaches: tuple[str, ...]) -> str:
    """An EDUCATIONAL page. No form, no input field — it debriefs the recipient.

    This is the crux: there is no code path here that accepts a password. The page
    explains the exercise and lists what the lure demonstrated."""
    cues = "".join(f"    <li>{c}</li>\n" for c in teaches)
    return (
        "<!doctype html>\n<html><head><title>Security Awareness</title></head>\n"
        "<body>\n"
        f"  <h1>{VISIBLE_WATERMARK}</h1>\n"
        "  <p>This was a simulated phishing exercise run by your security team. "
        "No harm was done and nothing was captured.</p>\n"
        "  <p>Here is what this message was designed to teach you to notice:</p>\n"
        f"  <ul>\n{cues}  </ul>\n"
        "  <p>When in doubt, report suspicious mail to your IT service desk.</p>\n"
        f"  <!-- {EMBEDDED_MARKER}: {engagement_id} -->\n"
        "</body></html>\n")


def generate(auth: Authorization, template_id: str, target: str, *,
             secret: str, base_url: str, today: dt.date) -> Artifact:
    """Render one simulation artifact. Raises unless the authorization is valid and
    the target is in scope."""
    auth.verify(secret, today=today)          # gate 1: authentic + current
    if template_id not in TEMPLATES:
        raise ValueError(f"unknown template: {template_id}")
    if not auth.permits_target(target):        # gate 2: in scope
        raise AuthorizationError(
            f"target {target} is not in the authorized scope "
            f"{auth.scope_domains}; refusing to generate")

    tmpl = TEMPLATES[template_id]
    tid = _tracking_id(auth.engagement_id, target, template_id)
    link = f"{base_url.rstrip('/')}/t/{tid}"
    tracker = f"\n\n{VISIBLE_WATERMARK}"
    body = tmpl.body.format(link=link, tracker=tracker)
    headers = (
        (EMBEDDED_MARKER, auth.engagement_id),
        ("X-Simulation-Tracking-Id", tid),
        ("X-Authorized-By", auth.approver),
    )
    return Artifact(
        engagement_id=auth.engagement_id, template_id=template_id, target=target,
        tracking_id=tid, subject=f"{tmpl.subject}", body=body, headers=headers,
        landing_page_html=_landing_page(auth.engagement_id, tmpl.teaches))
