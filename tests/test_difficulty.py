"""DifficultyGrader tests."""
from __future__ import annotations

from phish_paygen import DifficultyGrader, DifficultyLabel, Email


def test_obvious_phish_is_easy(obvious_phish):
    r = DifficultyGrader().grade(obvious_phish)
    assert r.label == DifficultyLabel.EASY


def test_benign_is_hard(benign_email):
    r = DifficultyGrader(
        internal_domains=("acme.test",)).grade(benign_email)
    assert r.label == DifficultyLabel.HARD


def test_lookalike_is_easy_or_medium(lookalike_email):
    r = DifficultyGrader().grade(lookalike_email)
    assert r.label in (
        DifficultyLabel.EASY, DifficultyLabel.MEDIUM)


def test_difficulty_to_dict(obvious_phish):
    r = DifficultyGrader().grade(obvious_phish)
    d = r.to_dict()
    assert d["label"] == r.label.value
    assert isinstance(d["rationale"], list)


def test_rationale_has_rule_severity_pairs(obvious_phish):
    r = DifficultyGrader().grade(obvious_phish)
    for entry in r.rationale:
        assert ":" in entry


def test_score_range(obvious_phish):
    r = DifficultyGrader().grade(obvious_phish)
    assert 0.0 <= r.score <= 1.0


def test_empty_email_is_hard():
    r = DifficultyGrader().grade(Email())
    assert r.label == DifficultyLabel.HARD


def test_grader_takes_custom_detector(obvious_phish):
    from phish_paygen import PhishingDetector
    g = DifficultyGrader(detector=PhishingDetector(rules=[]))
    # No rules => always HARD.
    assert g.grade(obvious_phish).label == DifficultyLabel.HARD
