"""PhishingDetector aggregation tests."""
from __future__ import annotations

from phish_paygen import Email, PhishingDetector
from phish_paygen.detector import DetectionReport
from phish_paygen.rules import PhishingHit


def test_benign_low_band(detector, benign_email):
    r = detector.analyze(benign_email)
    assert r.band in ("info", "low")
    assert r.score < 0.5


def test_obvious_phish_high_band(detector, obvious_phish):
    r = detector.analyze(obvious_phish)
    assert r.band == "high"
    assert r.score > 0.8


def test_lookalike_email_fires(detector, lookalike_email):
    r = detector.analyze(lookalike_email)
    ids = {h.rule_id for h in r.hits}
    assert "PHX-LKAL-001" in ids


def test_report_to_dict(detector, obvious_phish):
    r = detector.analyze(obvious_phish)
    d = r.to_dict()
    assert d["band"] == r.band
    assert isinstance(d["hits"], list)


def test_hits_sorted_by_severity(detector, obvious_phish):
    r = detector.analyze(obvious_phish)
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    ranks = [sev_rank[h.severity] for h in r.hits]
    assert ranks == sorted(ranks, reverse=True)


def test_rule_ids_lists_all(detector):
    ids = detector.rule_ids()
    assert "PHX-URG-001" in ids
    assert len(ids) == 9


def test_broken_rule_does_not_kill_run(detector,
                                      benign_email):
    class Broken:
        rule_id = "PHX-BROKEN"

        def __call__(self, email):
            raise RuntimeError("nope")

    det = PhishingDetector(
        rules=[Broken(), *detector._rules])
    r = det.analyze(benign_email)
    assert isinstance(r, DetectionReport)


def test_empty_email_runs(detector):
    r = detector.analyze(Email())
    assert isinstance(r, DetectionReport)
    assert r.band in ("info", "low")


def test_score_in_range(detector, obvious_phish):
    r = detector.analyze(obvious_phish)
    assert 0.0 <= r.score <= 1.0


def test_explicit_rules_override_default():
    det = PhishingDetector(rules=[])
    r = det.analyze(Email(subject="urgent"))
    assert r.hits == ()


def test_internal_domains_passed_through():
    det = PhishingDetector(internal_domains=("acme.test",))
    r = det.analyze(Email(from_addr="x@acme.test"))
    # No PHX-EXTSIG-001 for internal sender.
    assert all(h.rule_id != "PHX-EXTSIG-001" for h in r.hits)


def test_band_thresholds():
    # Construct a fake report by running detector with no rules.
    det = PhishingDetector(rules=[])
    r = det.analyze(Email())
    assert r.band == "info"


def test_phishing_hit_to_dict():
    h = PhishingHit("PHX-X", "desc", "high", 0.9, {"k": "v"})
    d = h.to_dict()
    assert d["rule_id"] == "PHX-X"
    assert d["score"] == 0.9
