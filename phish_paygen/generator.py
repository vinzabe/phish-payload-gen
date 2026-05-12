"""Lure generator.

The generator is the *only* code path that can return a non-stub
training email. It always emits ``[TRAINING]`` in the subject and
defangs every URL in the rendered output. When the
:class:`~phish_paygen.auth.AuthorizationGate` says "no", the
generator returns the bundled stub copy verbatim — no LLM call.

When the gate says "yes" *and* the caller passed an LLM client,
the generator asks the LLM to *paraphrase* the bundled stub
template (subject + body) with the supplied placeholder values.
The result is sanitised:

- subject is forced to start with ``[TRAINING]``;
- every URL/host in the body is defanged;
- the body always ends with the bundled training-banner footer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping, Optional

from .auth import AuthorizationGate, AuthorizationStatus
from .defang import defang
from .templates import LureTemplate, TemplateLibrary

TRAINING_TAG = "[TRAINING]"
TRAINING_FOOTER = (
    "\n\n--\nThis message is part of an authorised phishing-"
    "awareness training exercise. It is not a real request. "
    "If you received it by accident please ignore.")


@dataclass(frozen=True)
class GeneratedLure:
    """A single rendered training lure."""

    template_id: str
    topic: str
    subject: str
    body: str
    realistic: bool
    auth_status: AuthorizationStatus
    rejected_terms: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "template_id": self.template_id,
            "topic": self.topic,
            "subject": self.subject,
            "body": self.body,
            "realistic": self.realistic,
            "auth_status": self.auth_status.to_dict(),
            "rejected_terms": list(self.rejected_terms),
        }


class LureGenerator:
    """Combines the template library with the auth gate + LLM."""

    def __init__(
            self,
            library: TemplateLibrary | None = None,
            gate: AuthorizationGate | None = None,
            llm: object | None = None) -> None:
        self._library = library or TemplateLibrary()
        self._gate = gate or AuthorizationGate()
        self._llm = llm

    @property
    def library(self) -> TemplateLibrary:
        return self._library

    def generate(
            self,
            template_id: str,
            placeholders: Mapping[str, str] | None = None,
            *,
            allow_realistic: bool = True) -> GeneratedLure:
        """Render a template.

        If ``allow_realistic`` is False the generator skips the
        gate check entirely and always returns stub copy. This
        lets unit tests force stub mode regardless of env state.
        """
        template = self._library.get(template_id)
        rendered = template.render(placeholders or {})
        status = (self._gate.check() if allow_realistic
                  else AuthorizationStatus(
                      False, "caller forced stub mode",
                      False, False, False))

        if status.allowed and self._llm is not None:
            try:
                subject, body = self._llm_paraphrase(rendered)
                realistic = True
            except Exception:
                subject = rendered.subject
                body = rendered.body
                realistic = False
        else:
            subject = rendered.subject
            body = rendered.body
            realistic = False

        subject, body = self._sanitise(subject, body)
        return GeneratedLure(
            template_id=rendered.template_id,
            topic=rendered.topic,
            subject=subject,
            body=body,
            realistic=realistic,
            auth_status=status,
            rejected_terms=())

    # ---- internals -----------------------------------------

    def _llm_paraphrase(
            self, t: LureTemplate) -> tuple[str, str]:
        """Ask the LLM to rewrite the stub. Returns (subj, body)."""
        prompt = (
            "You are helping a security team prepare an "
            "AUTHORISED phishing-awareness training email.\n\n"
            "Rewrite the SUBJECT and BODY below to feel "
            "natural, but you MUST:\n"
            "- keep the subject starting with [TRAINING]\n"
            "- keep every [PLACEHOLDER] verbatim\n"
            "- keep all link tokens [FAKE-LINK] verbatim\n"
            "- keep the message under 1500 characters\n"
            "- not invent new URLs, do not include any URL\n"
            "- not include attachments\n\n"
            f"SUBJECT:\n{t.subject}\n\n"
            f"BODY:\n{t.body}\n\n"
            "Return your answer as two sections labelled "
            "exactly 'SUBJECT:' and 'BODY:'.")
        try:
            text = self._llm.chat_simple(  # type: ignore[union-attr]
                prompt=prompt,
                system=("You produce phishing-awareness "
                        "training stubs only."),
                max_tokens=600,
                temperature=0.4)
        except TypeError:
            # Allow LLMs that take positional args.
            text = self._llm.chat_simple(prompt)  # type: ignore[union-attr]
        text = str(text or "")
        m = re.search(
            r"SUBJECT:\s*(?P<s>.+?)\s*BODY:\s*(?P<b>.+)",
            text, flags=re.DOTALL | re.IGNORECASE)
        if not m:
            raise ValueError("LLM response missing sections")
        return m.group("s").strip(), m.group("b").strip()

    def _sanitise(
            self, subject: str, body: str) -> tuple[str, str]:
        # Strip any URLs the LLM might have invented.
        body = re.sub(
            r"\bhttps?://\S+", "[FAKE-LINK]", body,
            flags=re.IGNORECASE)
        body = defang(body)
        if not subject.lstrip().startswith(TRAINING_TAG):
            subject = f"{TRAINING_TAG} {subject.lstrip()}"
        if TRAINING_FOOTER.strip() not in body:
            body = body.rstrip() + TRAINING_FOOTER
        return subject, body
