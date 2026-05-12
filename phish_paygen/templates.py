"""Bundled training-stub lure templates.

Every template is *intentionally obvious*. The body contains a
``[FAKE-LINK]`` placeholder, the sender domain is
``training.example``, and the subject line is tagged with
``[TRAINING]``. The only path to realistic copy is via the
:class:`~phish_paygen.generator.LureGenerator` after the
authorisation gate has approved the run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping, Sequence

#: Topic catalogue. Adding a new topic only requires appending
#: here and providing at least one :class:`LureTemplate` for it.
TEMPLATE_TOPICS: tuple[str, ...] = (
    "invoice",
    "package_delivery",
    "password_reset",
    "payroll",
    "hr_policy",
    "oauth_consent",
)

_PLACEHOLDER_RE = re.compile(r"\[([A-Z][A-Z0-9_]*)\]")


@dataclass(frozen=True)
class LureTemplate:
    """A single training-stub template.

    ``placeholders`` is computed from ``subject`` + ``body``. The
    expected ``[PLACEHOLDER]`` slots are surfaced through this
    field so the CLI can complain if a caller forgets one.
    """

    template_id: str
    topic: str
    subject: str
    body: str
    sender_role: str = "vendor"
    placeholders: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.topic not in TEMPLATE_TOPICS:
            raise ValueError(f"unknown topic: {self.topic!r}")
        if not self.placeholders:
            found = sorted({m.group(1) for m in
                            _PLACEHOLDER_RE.finditer(
                                self.subject + "\n" + self.body)})
            object.__setattr__(self, "placeholders", tuple(found))

    def render(self, values: Mapping[str, str]) -> "LureTemplate":
        """Return a new template with placeholders substituted.

        Missing placeholders are left as-is so the caller can spot
        them in the rendered output.
        """
        def _sub(text: str) -> str:
            def _repl(m: re.Match[str]) -> str:
                return str(values.get(m.group(1), m.group(0)))
            return _PLACEHOLDER_RE.sub(_repl, text)

        return LureTemplate(
            template_id=self.template_id,
            topic=self.topic,
            subject=_sub(self.subject),
            body=_sub(self.body),
            sender_role=self.sender_role,
            placeholders=self.placeholders,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "template_id": self.template_id,
            "topic": self.topic,
            "subject": self.subject,
            "body": self.body,
            "sender_role": self.sender_role,
            "placeholders": list(self.placeholders),
        }


def _bundled_templates() -> tuple[LureTemplate, ...]:
    return (
        LureTemplate(
            template_id="INV-001",
            topic="invoice",
            sender_role="vendor",
            subject="[TRAINING] Invoice [INVOICE_ID] is overdue",
            body=(
                "Hello [FIRST_NAME],\n\n"
                "Our records show invoice [INVOICE_ID] for "
                "[AMOUNT] is now [DAYS_OVERDUE] days overdue.\n"
                "Please review the invoice here: [FAKE-LINK]\n\n"
                "Regards,\n"
                "Accounts at training.example\n"
                "(This is a phishing-awareness training stub.)"),
        ),
        LureTemplate(
            template_id="PKG-001",
            topic="package_delivery",
            sender_role="courier",
            subject=(
                "[TRAINING] Your package [TRACKING_ID] could "
                "not be delivered"),
            body=(
                "Hi [FIRST_NAME],\n\n"
                "We tried to deliver package [TRACKING_ID] on "
                "[DATE] but no one was available.\n"
                "Reschedule the delivery: [FAKE-LINK]\n\n"
                "Customer service, training.example courier."),
        ),
        LureTemplate(
            template_id="PWD-001",
            topic="password_reset",
            sender_role="it_helpdesk",
            subject=(
                "[TRAINING] Action required: reset your "
                "[COMPANY] password"),
            body=(
                "Dear [FIRST_NAME],\n\n"
                "Your [COMPANY] account password expires in "
                "[HOURS] hours. To keep access, reset it now:\n"
                "[FAKE-LINK]\n\n"
                "IT Helpdesk, training.example."),
        ),
        LureTemplate(
            template_id="PWD-002",
            topic="password_reset",
            sender_role="it_helpdesk",
            subject=(
                "[TRAINING] Suspicious sign-in to your "
                "[COMPANY] account"),
            body=(
                "Hi [FIRST_NAME],\n\n"
                "We detected a sign-in to your [COMPANY] account "
                "from [CITY] at [TIME]. If this was not you, "
                "secure your account here: [FAKE-LINK]\n\n"
                "Security team, training.example."),
        ),
        LureTemplate(
            template_id="PAY-001",
            topic="payroll",
            sender_role="hr",
            subject=(
                "[TRAINING] Updated payslip for "
                "[PAY_PERIOD]"),
            body=(
                "Hello [FIRST_NAME],\n\n"
                "Your payslip for [PAY_PERIOD] has been "
                "re-issued because of an HR correction.\n"
                "Download the updated payslip: [FAKE-LINK]\n\n"
                "Payroll at training.example."),
        ),
        LureTemplate(
            template_id="HR-001",
            topic="hr_policy",
            sender_role="hr",
            subject=(
                "[TRAINING] New [COMPANY] policy: please "
                "acknowledge by [DATE]"),
            body=(
                "Hi [FIRST_NAME],\n\n"
                "[COMPANY] has updated its [POLICY_NAME]. All "
                "staff must read and acknowledge the new policy "
                "by [DATE].\n"
                "Open the policy: [FAKE-LINK]\n\n"
                "People team, training.example."),
        ),
        LureTemplate(
            template_id="OAUTH-001",
            topic="oauth_consent",
            sender_role="saas_app",
            subject=(
                "[TRAINING] [APP_NAME] is requesting access "
                "to your [COMPANY] account"),
            body=(
                "Hello [FIRST_NAME],\n\n"
                "An application called [APP_NAME] is requesting "
                "permission to read your mailbox and files in "
                "your [COMPANY] account.\n"
                "Review and approve / deny here: [FAKE-LINK]\n\n"
                "Identity team, training.example."),
        ),
    )


class TemplateLibrary:
    """In-memory catalogue of bundled + user-supplied templates."""

    def __init__(
            self,
            templates: Sequence[LureTemplate] | None = None) \
            -> None:
        self._templates: list[LureTemplate] = list(
            templates if templates is not None
            else _bundled_templates())
        self._by_id: dict[str, LureTemplate] = {
            t.template_id: t for t in self._templates}
        if len(self._by_id) != len(self._templates):
            raise ValueError(
                "duplicate template_id in supplied templates")

    def __len__(self) -> int:
        return len(self._templates)

    def __iter__(self):
        return iter(self._templates)

    def all(self) -> tuple[LureTemplate, ...]:
        return tuple(self._templates)

    def topics(self) -> tuple[str, ...]:
        return tuple(sorted({t.topic for t in self._templates}))

    def by_topic(self, topic: str) -> tuple[LureTemplate, ...]:
        if topic not in TEMPLATE_TOPICS:
            raise ValueError(f"unknown topic: {topic!r}")
        return tuple(
            t for t in self._templates if t.topic == topic)

    def get(self, template_id: str) -> LureTemplate:
        try:
            return self._by_id[template_id]
        except KeyError as exc:
            raise KeyError(
                f"no such template_id: {template_id!r}") from exc

    def add(self, template: LureTemplate) -> None:
        if template.template_id in self._by_id:
            raise ValueError(
                f"duplicate template_id: {template.template_id}")
        self._templates.append(template)
        self._by_id[template.template_id] = template
