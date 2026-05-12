"""CLI tests."""
from __future__ import annotations

import json

import pytest

from phish_paygen.cli import build_parser, main


def test_parser_requires_subcommand():
    with pytest.raises(SystemExit):
        main([])


def test_list_templates_text(capsys):
    rc = main(["list-templates"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PWD-001" in out


def test_list_templates_filtered(capsys):
    rc = main(["list-templates", "--topic", "password_reset"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PWD-001" in out
    assert "INV-001" not in out


def test_list_templates_json(capsys):
    rc = main(["list-templates", "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(t["template_id"] == "PWD-001" for t in payload)


def test_generate_text(capsys, monkeypatch, tmp_path):
    monkeypatch.delenv("AGSBX_RED_TEAM_AUTH", raising=False)
    monkeypatch.setenv(
        "AGSBX_RED_TEAM_AUTH_FILE", str(tmp_path / "noauth"))
    rc = main(["generate", "--template-id", "PWD-001",
               "--values", "{\"FIRST_NAME\":\"Alice\"}"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[STUB]" in out
    assert "Alice" in out


def test_generate_unknown_template(capsys):
    rc = main(["generate", "--template-id", "NOPE"])
    assert rc == 2


def test_generate_bad_values(capsys):
    rc = main(["generate", "--template-id", "PWD-001",
               "--values", "not-json"])
    assert rc == 2


def test_generate_json(capsys, monkeypatch, tmp_path):
    monkeypatch.delenv("AGSBX_RED_TEAM_AUTH", raising=False)
    monkeypatch.setenv(
        "AGSBX_RED_TEAM_AUTH_FILE", str(tmp_path / "noauth"))
    rc = main(["generate", "--template-id", "PWD-001",
               "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["realistic"] is False


def test_detect_text(tmp_path, capsys):
    p = tmp_path / "e.json"
    p.write_text(json.dumps({
        "subject": "URGENT verify now",
        "from_addr": "x@paypaI.zip",
        "from_name": "PayPal",
        "body_text": "click http://192.168.1.1/x",
    }))
    rc = main(["detect", "--input", str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "high" in out


def test_detect_json(tmp_path, capsys):
    p = tmp_path / "e.json"
    p.write_text(json.dumps(
        {"subject": "lunch?", "body_text": "hi"}))
    rc = main(["detect", "--input", str(p), "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["band"] in ("info", "low")


def test_detect_missing_file(capsys):
    rc = main(["detect", "--input", "/no/such/file"])
    assert rc == 2


def test_detect_bad_json(tmp_path, capsys):
    p = tmp_path / "e.json"
    p.write_text("not json")
    rc = main(["detect", "--input", str(p)])
    assert rc == 2


def test_grade(tmp_path, capsys):
    p = tmp_path / "e.json"
    p.write_text(json.dumps(
        {"subject": "URGENT verify now",
         "from_addr": "x@paypaI.zip",
         "from_name": "PayPal"}))
    rc = main(["grade", "--input", str(p)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["label"] in ("easy", "medium", "hard")


def test_defang_cmd(capsys):
    rc = main(["defang", "visit https://example.com now"])
    assert rc == 0
    assert "hxxps[://]example[.]com" in capsys.readouterr().out


def test_refang_cmd(capsys):
    rc = main(["refang", "hxxps[://]example[.]com"])
    assert rc == 0
    assert "https://example.com" in capsys.readouterr().out


def test_auth_status(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("AGSBX_RED_TEAM_AUTH", raising=False)
    monkeypatch.setenv(
        "AGSBX_RED_TEAM_AUTH_FILE", str(tmp_path / "no"))
    rc = main(["auth-status"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allowed"] is False


def test_build_parser_smoke():
    p = build_parser()
    args = p.parse_args(["list-templates"])
    assert args.cmd == "list-templates"
