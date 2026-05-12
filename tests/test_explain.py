"""PhishingExplainer tests (mocked LLM)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from phish_paygen import (
    Email,
    ExplanationReport,
    PhishingDetector,
    PhishingExplainer,
)
from phish_paygen.explain import SYSTEM_PROMPT


def _report(email):
    return PhishingDetector(
        internal_domains=("acme.test",)).analyze(email)


def test_explainer_rejects_non_report():
    with pytest.raises(ValueError):
        PhishingExplainer(llm=MagicMock()).explain("oops")


def test_grounded_text_passes_through(obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    used = list({h.rule_id for h in r.hits})[:1]
    llm.chat_simple.return_value = (
        f"{used[0]} fired with high severity. "
        "The phishing email mentions urgency.")
    out = PhishingExplainer(llm=llm).explain(r)
    assert used[0] in out.text
    assert out.rejected_sentences == ()


def test_unknown_rule_sentence_rejected(obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    used = list({h.rule_id for h in r.hits})[:1]
    llm.chat_simple.return_value = (
        f"PHX-FAKE-999 also fired. {used[0]} was real.")
    out = PhishingExplainer(llm=llm).explain(r)
    assert "PHX-FAKE-999" not in out.text
    assert any("PHX-FAKE-999" in s
               for s in out.rejected_sentences)


def test_generic_unknown_rule_sentence_rejected(
        obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    llm.chat_simple.return_value = (
        "FAKE-XX-999 also fired. The user should be careful.")
    out = PhishingExplainer(llm=llm).explain(r)
    assert "FAKE-XX-999" not in out.text


def test_used_rules_listed(obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    llm.chat_simple.return_value = "ok"
    out = PhishingExplainer(llm=llm).explain(r)
    assert set(out.used_rules) == {h.rule_id for h in r.hits}


def test_used_rules_sorted_unique(obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    llm.chat_simple.return_value = "ok"
    out = PhishingExplainer(llm=llm).explain(r)
    assert list(out.used_rules) == sorted(set(out.used_rules))


def test_system_prompt_passed(obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    llm.chat_simple.return_value = "ok"
    PhishingExplainer(llm=llm).explain(r)
    kwargs = llm.chat_simple.call_args.kwargs
    assert kwargs["system"] == SYSTEM_PROMPT
    assert kwargs["max_tokens"] == 400


def test_llm_failure_returns_message(obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    llm.chat_simple.side_effect = RuntimeError("oops")
    out = PhishingExplainer(llm=llm).explain(r)
    assert "explainer unavailable" in out.text


def test_default_no_llm_returns_summary(obvious_phish):
    r = _report(obvious_phish)
    out = PhishingExplainer().explain(r)
    assert "hit" in out.text


def test_explanation_report_to_dict():
    rep = ExplanationReport(
        text="hi", used_rules=("PHX-DFM-001",))
    d = rep.to_dict()
    assert d["text"] == "hi"
    assert d["used_rules"] == ["PHX-DFM-001"]


def test_empty_response(obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    llm.chat_simple.return_value = ""
    out = PhishingExplainer(llm=llm).explain(r)
    assert out.text == ""


def test_benign_email_explainer_runs(benign_email):
    r = _report(benign_email)
    llm = MagicMock()
    llm.chat_simple.return_value = "All clean."
    out = PhishingExplainer(llm=llm).explain(r)
    assert isinstance(out, ExplanationReport)


def test_raw_response_preserved(obvious_phish):
    r = _report(obvious_phish)
    llm = MagicMock()
    llm.chat_simple.return_value = "abc"
    out = PhishingExplainer(llm=llm).explain(r)
    assert out.raw_response == "abc"


def test_positional_only_llm_supported(obvious_phish):
    """Some LLMs accept positional-only prompt."""
    r = _report(obvious_phish)
    llm = MagicMock()
    llm.chat_simple.side_effect = lambda *a, **kw: (
        "ok" if a or kw else "ok")
    PhishingExplainer(llm=llm).explain(r)
    assert llm.chat_simple.called
