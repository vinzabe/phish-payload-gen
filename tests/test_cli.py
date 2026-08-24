import json

import pytest

from phishgen.cli import EXIT_OK, EXIT_REFUSED, main


def _authorize(tmp_path):
    out = tmp_path / "auth.json"
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["--secret", "s", "authorize", "--engagement", "E1",
              "--approver", "Jane", "--scope", "corp.example.com",
              "--expires", "2027-01-01"])
    out.write_text(buf.getvalue())
    return str(out)


def test_full_flow(tmp_path, capsys):
    auth = _authorize(tmp_path)
    store = str(tmp_path / "s.db")
    rc = main(["--store", store, "--secret", "s", "generate", auth,
               "--template", "password-expiry", "--target",
               "alice@corp.example.com"])
    assert rc == EXIT_OK
    assert "SIMULATION" in capsys.readouterr().out


def test_out_of_scope_refused(tmp_path, capsys):
    auth = _authorize(tmp_path)
    rc = main(["--store", str(tmp_path / "s.db"), "--secret", "s", "generate",
               auth, "--template", "password-expiry", "--target",
               "victim@gmail.com"])
    assert rc == EXIT_REFUSED
    assert "not in the authorized scope" in capsys.readouterr().err


def test_missing_secret_refused(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("PHISHGEN_SECRET", raising=False)
    auth = _authorize(tmp_path)   # uses --secret so it still writes
    rc = main(["--store", str(tmp_path / "s.db"), "generate", auth,
               "--template", "password-expiry", "--target", "a@corp.example.com"])
    # a missing secret is an authorization failure -> REFUSED, never a silent pass
    assert rc == EXIT_REFUSED


def test_click_and_report(tmp_path, capsys):
    auth = _authorize(tmp_path)
    store = str(tmp_path / "s.db")
    main(["--store", store, "--secret", "s", "generate", auth, "--template",
          "password-expiry", "--target", "alice@corp.example.com", "--json"])
    tid = json.loads(capsys.readouterr().out)["tracking_id"]
    assert main(["--store", store, "click", tid]) == EXIT_OK
    capsys.readouterr()
    main(["--store", store, "report", "--engagement", "E1", "--json"])
    d = json.loads(capsys.readouterr().out)
    assert d["sent"] == 1 and d["clicked"] == 1


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
