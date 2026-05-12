"""phish-payload-gen — phishing-awareness training toolkit.

This project is a *defender-side* toolkit for phishing security
awareness programs. The pieces:

- :class:`TemplateLibrary` — hand-curated, obviously-fictional lure
  templates with ``[PLACEHOLDER]`` slots, organised by topic
  (``invoice``, ``package_delivery``, ``password_reset``,
  ``payroll``, ``hr_policy``, ``oauth_consent``).
- :class:`PhishingDetector` — runs nine bundled rules over an
  email-shaped :class:`Email` (display-vs-from mismatch, lookalike
  domains, urgent-action language, suspicious links, mismatched
  link text vs target, base64 attachments, …).
- :class:`DifficultyGrader` — scores how subtle a lure is so a
  training program can pick easy / medium / hard examples.
- :func:`defang` / :func:`refang` — RFC-style defanging of URLs
  and IPs (``http://`` → ``hxxp[://]``).
- :class:`AuthorizationGate` — central choke point that decides
  whether a request is allowed to receive *realistic* lure copy.
  Realistic copy is produced only when:
  1. the environment variable ``AGSBX_RED_TEAM_AUTH=1`` is set, AND
  2. an authorisation file exists at the path named by
     ``AGSBX_RED_TEAM_AUTH_FILE`` (default
     ``~/.agsbx_red_team_auth``) and contains the required
     statement.
  In any other case the toolkit returns *training-stub* output
  with ``[FAKE-LINK]`` / ``[REDACTED]`` markers.
- :class:`LureGenerator` — combines the template library, the
  authorisation gate and an optional LLM client. Always defangs
  URLs in returned text. Always tags output with the marker
  ``[TRAINING]``.
- :class:`PhishingExplainer` — LLM-driven analyst summary of a
  detection result, with a citation guard that refuses to mention
  rule_ids that are not in the report.
"""
from __future__ import annotations

from .auth import AuthorizationGate, AuthorizationStatus
from .defang import defang, defang_url, refang
from .detector import (
    DetectionReport,
    PhishingDetector,
    PhishingHit,
    default_rules,
)
from .difficulty import DifficultyGrader, DifficultyLabel
from .email import Email
from .explain import ExplanationReport, PhishingExplainer
from .generator import GeneratedLure, LureGenerator
from .rules import (
    AttachmentB64Suspicious,
    DisplayFromMismatch,
    LookalikeDomain,
    MismatchedLinkText,
    PhishingRule,
    SuspiciousLink,
    SuspiciousReplyTo,
    TooManyLinks,
    UnsignedExternalSender,
    UrgentActionLanguage,
)
from .templates import (
    LureTemplate,
    TEMPLATE_TOPICS,
    TemplateLibrary,
)


__all__ = [
    "AttachmentB64Suspicious",
    "AuthorizationGate",
    "AuthorizationStatus",
    "DetectionReport",
    "DifficultyGrader",
    "DifficultyLabel",
    "DisplayFromMismatch",
    "Email",
    "ExplanationReport",
    "GeneratedLure",
    "LookalikeDomain",
    "LureGenerator",
    "LureTemplate",
    "MismatchedLinkText",
    "PhishingDetector",
    "PhishingExplainer",
    "PhishingHit",
    "PhishingRule",
    "SuspiciousLink",
    "SuspiciousReplyTo",
    "TEMPLATE_TOPICS",
    "TemplateLibrary",
    "TooManyLinks",
    "UnsignedExternalSender",
    "UrgentActionLanguage",
    "default_rules",
    "defang",
    "defang_url",
    "refang",
]
