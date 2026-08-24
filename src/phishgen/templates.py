"""Awareness-training templates.

These teach recognition. Each template embeds the tells the training should teach
(urgency, generic greeting, a link) so the debrief can point at them. The landing
page is educational — there is deliberately NO template that presents a credential
form, because this tool does not capture credentials.
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True, slots=True)
class Template:
    id: str
    subject: str
    body: str                    # {link} and {tracker} placeholders
    teaches: tuple[str, ...]     # the recognition cues this lure demonstrates


TEMPLATES: dict[str, Template] = {
    "password-expiry": Template(
        id="password-expiry",
        subject="Action required: your password expires today",
        body=("Dear User,\n\nOur records show your password expires today. "
              "To keep access, review your account: {link}\n\n"
              "IT Service Desk{tracker}"),
        teaches=("urgency", "generic greeting", "unexpected link")),
    "shared-document": Template(
        id="shared-document",
        subject="A document has been shared with you",
        body=("Hi,\n\nA colleague shared a document with you. "
              "Open it here: {link}\n\nThanks{tracker}"),
        teaches=("vague sender", "unexpected link", "curiosity")),
    "delivery-notice": Template(
        id="delivery-notice",
        subject="Your package could not be delivered",
        body=("Hello,\n\nWe attempted delivery but need you to confirm details: "
              "{link}\n\nDelivery Team{tracker}"),
        teaches=("brand impersonation", "urgency", "unexpected link")),
}


def template_ids() -> tuple[str, ...]:
    return tuple(TEMPLATES)
