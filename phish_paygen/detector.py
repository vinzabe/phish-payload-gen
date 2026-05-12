"""Top-level :class:`PhishingDetector` and :class:`DetectionReport`."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .email import Email
from .rules import PhishingHit, PhishingRule, default_rules


_SEVERITY_ORDER = ("info", "low", "medium", "high")
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
_SEVERITY_WEIGHT = {
    "info": 0.1, "low": 0.25, "medium": 0.55, "high": 0.9}


def _band(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    if score >= 0.2:
        return "low"
    return "info"


@dataclass(frozen=True)
class DetectionReport:
    """Aggregate result for one email."""

    subject: str
    from_addr: str
    score: float
    band: str
    hits: tuple[PhishingHit, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "from_addr": self.from_addr,
            "score": float(self.score),
            "band": self.band,
            "hits": [h.to_dict() for h in self.hits],
        }


class PhishingDetector:
    """Run a suite of :class:`PhishingRule` over an Email."""

    def __init__(
            self,
            rules: Iterable[PhishingRule] | None = None,
            internal_domains: Iterable[str] = ()) -> None:
        self._rules: list[PhishingRule] = (
            list(rules) if rules is not None
            else default_rules(internal_domains=internal_domains))

    def rule_ids(self) -> tuple[str, ...]:
        return tuple(r.rule_id for r in self._rules)

    def analyze(self, email: Email) -> DetectionReport:
        hits: list[PhishingHit] = []
        for rule in self._rules:
            try:
                fired = rule(email) or []
            except Exception:
                fired = []
            hits.extend(fired)
        # Sort hits by severity desc, then by score desc.
        hits.sort(key=lambda h: (
            -_SEVERITY_RANK.get(h.severity, 0), -h.score,
            h.rule_id))
        # Soft-OR aggregation weighted by severity.
        prod = 1.0
        for h in hits:
            w = _SEVERITY_WEIGHT.get(h.severity, 0.1)
            prod *= max(0.0, 1.0 - w * float(h.score))
        score = round(1.0 - prod, 4)
        return DetectionReport(
            subject=email.subject,
            from_addr=email.from_addr,
            score=score,
            band=_band(score),
            hits=tuple(hits))
