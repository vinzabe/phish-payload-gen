"""LLM-driven analyst explainer for a :class:`DetectionReport`.

Citation-guarded: any sentence that mentions a token shaped like a
rule_id but isn't in :class:`DetectionReport.hits` is dropped. Same
for severity words and any token shaped like ``X-Y-NNN``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable

from .detector import DetectionReport

SYSTEM_PROMPT = (
    "You are a SOC analyst summarising a phishing-detection "
    "report. Use plain English, 4-6 sentences. You may only "
    "mention rule_ids, severity bands and evidence values that "
    "are present in the supplied JSON. Never invent rules.")

_RULE_RE = re.compile(r"\bPHX-[A-Z]+-\d+\b")
_GENERIC_RULE_RE = re.compile(r"\b[A-Z]{2,5}-[A-Z0-9]{2,8}-\d{3,}\b")
_SEV_WORDS = {"info", "low", "medium", "high"}
_PASSTHROUGH = {"phishing", "lure", "email", "subject",
                "domain", "link", "url", "attachment",
                "from", "reply-to", "sender", "training"}


@dataclass(frozen=True)
class ExplanationReport:
    text: str
    used_rules: tuple[str, ...] = field(default_factory=tuple)
    rejected_sentences: tuple[str, ...] = field(
        default_factory=tuple)
    raw_response: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "text": self.text,
            "used_rules": list(self.used_rules),
            "rejected_sentences": list(self.rejected_sentences),
            "raw_response": self.raw_response,
        }


class PhishingExplainer:
    """Wraps an LLM client with a citation guard."""

    def __init__(self, llm: object | None = None) -> None:
        self._llm = llm

    def explain(self, report: DetectionReport) -> ExplanationReport:
        if not isinstance(report, DetectionReport):
            raise ValueError(
                "explain() requires a DetectionReport")
        used_rules = tuple(sorted({h.rule_id for h in report.hits}))
        if self._llm is None:
            return ExplanationReport(
                text=("Detector saw "
                      f"{len(report.hits)} hit(s); band="
                      f"{report.band}, score={report.score}."),
                used_rules=used_rules)
        try:
            raw = self._llm.chat_simple(  # type: ignore[union-attr]
                prompt=self._render_prompt(report),
                system=SYSTEM_PROMPT,
                max_tokens=400,
                temperature=0.2)
        except TypeError:
            raw = self._llm.chat_simple(  # type: ignore[union-attr]
                self._render_prompt(report))
        except Exception:
            return ExplanationReport(
                text=("explainer unavailable; raw report has "
                      f"{len(report.hits)} hit(s)."),
                used_rules=used_rules)
        text, rejected = self._guard(
            str(raw or ""), used_rules)
        return ExplanationReport(
            text=text, used_rules=used_rules,
            rejected_sentences=tuple(rejected),
            raw_response=str(raw or ""))

    def _render_prompt(self, r: DetectionReport) -> str:
        payload = json.dumps(r.to_dict(), indent=2,
                             sort_keys=True)
        return (
            "Phishing detection report (JSON):\n\n"
            f"{payload}\n\n"
            "Write the SOC summary now.")

    def _guard(
            self, raw: str,
            used_rules: Iterable[str]) -> tuple[str, list[str]]:
        if not raw:
            return "", []
        used_set = {r.upper() for r in used_rules}
        kept: list[str] = []
        rejected: list[str] = []
        for sent in re.split(r"(?<=[.!?])\s+", raw.strip()):
            ok = True
            for m in _RULE_RE.finditer(sent):
                if m.group(0).upper() not in used_set:
                    ok = False
                    break
            if ok:
                for m in _GENERIC_RULE_RE.finditer(sent):
                    if m.group(0).upper() not in used_set:
                        ok = False
                        break
            if ok:
                kept.append(sent)
            else:
                rejected.append(sent)
        return " ".join(kept).strip(), rejected
