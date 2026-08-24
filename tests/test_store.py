from phishgen.store import Store


def test_click_rate(tmp_path):
    with Store(tmp_path / "s.db") as st:
        st.record_artifact("t1", "E1", "a@x.com", "tpl")
        st.record_artifact("t2", "E1", "b@x.com", "tpl")
        assert st.record_click("t1") is True
        clicked, sent = st.click_rate("E1")
        assert clicked == 1 and sent == 2


def test_unknown_tracking_id_rejected(tmp_path):
    with Store(tmp_path / "s.db") as st:
        assert st.record_click("nonexistent") is False
        assert st.click_rate("E1") == (0, 0)


def test_duplicate_clicks_counted_once_in_rate(tmp_path):
    with Store(tmp_path / "s.db") as st:
        st.record_artifact("t1", "E1", "a@x.com", "tpl")
        st.record_click("t1")
        st.record_click("t1")
        clicked, sent = st.click_rate("E1")
        assert clicked == 1 and sent == 1


def test_schema_mismatch_fails_loudly(tmp_path):
    import sqlite3
    db = tmp_path / "s.db"
    with Store(db):
        pass
    c = sqlite3.connect(db)
    c.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    c.commit()
    c.close()
    import pytest
    with pytest.raises(RuntimeError, match="schema"):
        Store(db)
