"""Email model used by the detector and the generator."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Email:
    """Minimal email envelope.

    Headers are kept as a plain dict so the test fixtures and the
    detector can be host-agnostic. ``from_addr`` and ``from_name``
    are extracted out of the ``From:`` header for convenience.
    """

    subject: str = ""
    from_addr: str = ""
    from_name: str = ""
    to_addrs: tuple[str, ...] = ()
    reply_to: str = ""
    body_text: str = ""
    body_html: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    attachments: tuple[dict[str, Any], ...] = ()

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Email":
        """Build an Email from a JSON-shaped dict."""
        return cls(
            subject=str(d.get("subject", "")),
            from_addr=str(d.get("from_addr", "")),
            from_name=str(d.get("from_name", "")),
            to_addrs=tuple(d.get("to_addrs", ())),
            reply_to=str(d.get("reply_to", "")),
            body_text=str(d.get("body_text", "")),
            body_html=str(d.get("body_html", "")),
            headers=dict(d.get("headers", {})),
            attachments=tuple(d.get("attachments", ())),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "from_addr": self.from_addr,
            "from_name": self.from_name,
            "to_addrs": list(self.to_addrs),
            "reply_to": self.reply_to,
            "body_text": self.body_text,
            "body_html": self.body_html,
            "headers": dict(self.headers),
            "attachments": list(self.attachments),
        }
