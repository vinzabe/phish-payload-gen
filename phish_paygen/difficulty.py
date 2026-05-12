"""Lure difficulty grader.

Given an :class:`~phish_paygen.email.Email` (typically the
training-stub output of :class:`~phish_paygen.generator.LureGenerator`),
estimate how *subtle* it is — i.e. how hard a human would find it
to spot. Subtle lures get fewer detector hits and have low-weight
severities; obvious ones light up several rules.

The grader is built on top of :class:`PhishingDetector`. We invert
the detector confidence: high confidence = easy to detect = label
``easy``; low confidence = hard = label ``hard``.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .detector import PhishingDetector
from .email import Email


class DifficultyLabel(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


@dataclass(frozen=True)
class DifficultyResult:
    label: DifficultyLabel
    score: float
    rationale: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label.value,
            "score": float(self.score),
            "rationale": list(self.rationale),
        }


class DifficultyGrader:
    """Score how subtle a lure is, using the bundled detector."""

    def __init__(
            self,
            detector: PhishingDetector | None = None,
            internal_domains: Iterable[str] = ()) -> None:
        self._detector = detector or PhishingDetector(
            internal_domains=internal_domains)

    def grade(self, email: Email) -> DifficultyResult:
        report = self._detector.analyze(email)
        # Difficulty is the inverse of detector confidence.
        difficulty = round(1.0 - report.score, 4)
        if difficulty >= 0.7:
            label = DifficultyLabel.HARD
        elif difficulty >= 0.4:
            label = DifficultyLabel.MEDIUM
        else:
            label = DifficultyLabel.EASY
        rationale = tuple(
            f"{h.rule_id}:{h.severity}" for h in report.hits)
        return DifficultyResult(
            label=label, score=difficulty,
            rationale=rationale)
