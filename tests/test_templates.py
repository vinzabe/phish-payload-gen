"""TemplateLibrary + LureTemplate tests."""
from __future__ import annotations

import pytest

from phish_paygen import LureTemplate, TEMPLATE_TOPICS, TemplateLibrary


def test_default_library_nonempty(library):
    assert len(library) >= 5


def test_topics_are_subset_of_known(library):
    for t in library.topics():
        assert t in TEMPLATE_TOPICS


def test_get_known_template(library):
    t = library.get("PWD-001")
    assert t.topic == "password_reset"


def test_get_unknown_template(library):
    with pytest.raises(KeyError):
        library.get("NOPE-999")


def test_by_topic_returns_only_topic(library):
    items = library.by_topic("password_reset")
    assert all(t.topic == "password_reset" for t in items)
    assert items


def test_by_topic_unknown(library):
    with pytest.raises(ValueError):
        library.by_topic("not-a-topic")


def test_placeholders_extracted_from_subject_and_body():
    t = LureTemplate(
        template_id="X-1", topic="invoice",
        subject="[TRAINING] hi [FIRST_NAME]",
        body="amount=[AMOUNT] link=[FAKE-LINK]")
    # FAKE-LINK contains a hyphen so the regex (which only
    # accepts A-Z0-9_) does not capture it.
    assert "FIRST_NAME" in t.placeholders
    assert "AMOUNT" in t.placeholders


def test_render_substitutes_and_keeps_unknown():
    t = LureTemplate(
        template_id="X-1", topic="invoice",
        subject="hi [FIRST_NAME]",
        body="hello [FIRST_NAME] amount=[AMOUNT]")
    out = t.render({"FIRST_NAME": "Alice"})
    assert "Alice" in out.body
    assert "[AMOUNT]" in out.body


def test_render_returns_new_object():
    t = LureTemplate(
        template_id="X-1", topic="invoice",
        subject="hi", body="hello")
    out = t.render({})
    assert out is not t


def test_unknown_topic_rejected():
    with pytest.raises(ValueError):
        LureTemplate(template_id="X-2", topic="bogus",
                     subject="x", body="y")


def test_add_template(library):
    n = len(library)
    library.add(LureTemplate(
        template_id="MY-1", topic="invoice",
        subject="x", body="y"))
    assert len(library) == n + 1
    assert library.get("MY-1").subject == "x"


def test_add_duplicate_raises(library):
    with pytest.raises(ValueError):
        library.add(LureTemplate(
            template_id="PWD-001", topic="password_reset",
            subject="x", body="y"))


def test_constructor_rejects_duplicates():
    with pytest.raises(ValueError):
        TemplateLibrary([
            LureTemplate(template_id="A", topic="invoice",
                         subject="s", body="b"),
            LureTemplate(template_id="A", topic="invoice",
                         subject="s", body="b"),
        ])


def test_to_dict_round_trip():
    t = LureTemplate(
        template_id="X-3", topic="invoice",
        subject="s [X]", body="b [Y]",
        placeholders=("X", "Y"))
    d = t.to_dict()
    assert d["template_id"] == "X-3"
    assert d["placeholders"] == ["X", "Y"]


def test_iter_yields_all(library):
    n = sum(1 for _ in library)
    assert n == len(library)


def test_all_returns_tuple(library):
    assert isinstance(library.all(), tuple)


def test_every_bundled_subject_has_training_tag(library):
    for t in library:
        assert t.subject.startswith("[TRAINING]"), t.template_id


def test_every_bundled_body_has_fake_link(library):
    for t in library:
        assert "[FAKE-LINK]" in t.body, t.template_id
