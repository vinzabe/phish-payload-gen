"""LureGenerator tests (mocked LLM)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from phish_paygen import (
    AuthorizationGate,
    GeneratedLure,
    LureGenerator,
    TemplateLibrary,
)
from phish_paygen.generator import TRAINING_TAG, TRAINING_FOOTER


def test_stub_when_gate_closed(stub_generator):
    out = stub_generator.generate(
        "PWD-001",
        {"FIRST_NAME": "Alice", "COMPANY": "Acme",
         "HOURS": "24"})
    assert out.realistic is False
    assert "Alice" in out.body
    assert "[FAKE-LINK]" in out.body
    assert TRAINING_TAG in out.subject


def test_stub_appends_footer(stub_generator):
    out = stub_generator.generate("PWD-001", {})
    assert TRAINING_FOOTER.strip() in out.body


def test_stub_when_gate_closed_even_with_llm(
        stub_generator):
    llm = MagicMock()
    stub_generator._llm = llm
    out = stub_generator.generate("PWD-001", {})
    assert out.realistic is False
    llm.chat_simple.assert_not_called()


def test_realistic_when_gate_open_and_llm_present(open_gate):
    llm = MagicMock()
    llm.chat_simple.return_value = (
        "SUBJECT: Important: reset your Acme password\n\n"
        "BODY: Hi Alice,\n\nPlease reset your password "
        "via [FAKE-LINK].\n\nIT")
    gen = LureGenerator(gate=open_gate, llm=llm)
    out = gen.generate("PWD-001",
                       {"FIRST_NAME": "Alice"})
    assert out.realistic is True
    assert out.subject.startswith(TRAINING_TAG)
    assert "Alice" in out.body
    assert "[FAKE-LINK]" in out.body
    assert TRAINING_FOOTER.strip() in out.body


def test_realistic_falls_back_on_bad_llm(open_gate):
    llm = MagicMock()
    llm.chat_simple.return_value = "no sections here"
    gen = LureGenerator(gate=open_gate, llm=llm)
    out = gen.generate("PWD-001", {})
    assert out.realistic is False


def test_realistic_strips_invented_urls(open_gate):
    llm = MagicMock()
    llm.chat_simple.return_value = (
        "SUBJECT: Reset password now\n"
        "BODY: Click https://attacker.example/login here.")
    gen = LureGenerator(gate=open_gate, llm=llm)
    out = gen.generate("PWD-001", {})
    assert "attacker" not in out.body
    assert "[FAKE-LINK]" in out.body


def test_realistic_defangs_remaining_hosts(open_gate):
    llm = MagicMock()
    llm.chat_simple.return_value = (
        "SUBJECT: Heads up\nBODY: visit foo.bar.example soon.")
    gen = LureGenerator(gate=open_gate, llm=llm)
    out = gen.generate("PWD-001", {})
    assert "[." in out.body  # defanged dots present.


def test_unknown_template_id_raises(stub_generator):
    with pytest.raises(KeyError):
        stub_generator.generate("NOPE-999", {})


def test_allow_realistic_false_forces_stub(open_gate):
    llm = MagicMock()
    llm.chat_simple.return_value = (
        "SUBJECT: x\nBODY: y")
    gen = LureGenerator(gate=open_gate, llm=llm)
    out = gen.generate("PWD-001", {}, allow_realistic=False)
    assert out.realistic is False
    llm.chat_simple.assert_not_called()


def test_to_dict_round_trip(stub_generator):
    out = stub_generator.generate("PWD-001", {})
    d = out.to_dict()
    assert d["realistic"] is False
    assert d["template_id"] == "PWD-001"
    assert "auth_status" in d


def test_default_lib_and_gate_used():
    gen = LureGenerator()
    assert isinstance(gen.library, TemplateLibrary)


def test_realistic_keeps_training_tag_even_if_llm_drops_it(
        open_gate):
    llm = MagicMock()
    llm.chat_simple.return_value = (
        "SUBJECT: Reset password\nBODY: go via [FAKE-LINK]")
    gen = LureGenerator(gate=open_gate, llm=llm)
    out = gen.generate("PWD-001", {})
    assert out.subject.startswith(TRAINING_TAG)


def test_llm_exception_returns_stub(open_gate):
    llm = MagicMock()
    llm.chat_simple.side_effect = RuntimeError("oops")
    gen = LureGenerator(gate=open_gate, llm=llm)
    out = gen.generate("PWD-001", {})
    assert out.realistic is False


def test_generated_lure_dataclass_immutable(stub_generator):
    out = stub_generator.generate("PWD-001", {})
    try:
        out.subject = "new"  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("GeneratedLure should be frozen")


def test_gate_check_recorded(stub_generator):
    out = stub_generator.generate("PWD-001", {})
    assert out.auth_status.allowed is False
