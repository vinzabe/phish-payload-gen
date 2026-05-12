"""CLI for phish-payload-gen."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .auth import AuthorizationGate
from .defang import defang as defang_text, refang as refang_text
from .detector import PhishingDetector
from .difficulty import DifficultyGrader
from .email import Email
from .generator import LureGenerator
from .templates import TEMPLATE_TOPICS, TemplateLibrary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phish-paygen",
        description=("Defender-side phishing-awareness "
                     "training toolkit."))
    sub = p.add_subparsers(dest="cmd")

    pl = sub.add_parser(
        "list-templates",
        help="list bundled templates")
    pl.add_argument("--topic", choices=TEMPLATE_TOPICS,
                    default=None)
    pl.add_argument("--format", choices=("text", "json"),
                    default="text")

    pg = sub.add_parser(
        "generate", help="render a training-stub lure")
    pg.add_argument("--template-id", required=True)
    pg.add_argument(
        "--values", default="{}",
        help="JSON dict of placeholder values")
    pg.add_argument("--format", choices=("text", "json"),
                    default="text")

    pd = sub.add_parser(
        "detect",
        help="run the detector on a JSON-encoded email")
    pd.add_argument("--input", required=True,
                    help="path to email.json")
    pd.add_argument("--format", choices=("text", "json"),
                    default="text")

    pgr = sub.add_parser(
        "grade",
        help="grade lure difficulty for a JSON-encoded email")
    pgr.add_argument("--input", required=True)

    pdf = sub.add_parser(
        "defang", help="defang URLs / IPs in a string")
    pdf.add_argument("text")

    prf = sub.add_parser(
        "refang", help="refang defanged URLs / IPs")
    prf.add_argument("text")

    psa = sub.add_parser(
        "auth-status",
        help="print authorisation gate status")

    return p


def _print_template(tpl, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(tpl.to_dict(), indent=2))
    else:
        print(f"{tpl.template_id}\t{tpl.topic}\t{tpl.subject}")


def _load_email(path: str) -> Email:
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    return Email.from_dict(data)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.error("a subcommand is required")
        return 2

    if args.cmd == "list-templates":
        lib = TemplateLibrary()
        items = (lib.by_topic(args.topic)
                 if args.topic else lib.all())
        if args.format == "json":
            print(json.dumps(
                [t.to_dict() for t in items], indent=2))
        else:
            for t in items:
                _print_template(t, "text")
        return 0

    if args.cmd == "generate":
        try:
            values = json.loads(args.values)
            if not isinstance(values, dict):
                raise ValueError("values must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        gen = LureGenerator()
        try:
            out = gen.generate(args.template_id, values)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(out.to_dict(), indent=2))
        else:
            tag = "REALISTIC" if out.realistic else "STUB"
            print(f"[{tag}] subject: {out.subject}")
            print(out.body)
            if not out.realistic:
                print(f"\nauth: {out.auth_status.reason}")
        return 0

    if args.cmd == "detect":
        try:
            email = _load_email(args.input)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error reading {args.input}: {exc}",
                  file=sys.stderr)
            return 2
        report = PhishingDetector().analyze(email)
        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(f"score={report.score}\tband={report.band}")
            for h in report.hits:
                print(f"  {h.severity:6s} {h.rule_id} "
                      f"{h.score:.2f} {h.description}")
        return 0

    if args.cmd == "grade":
        try:
            email = _load_email(args.input)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error reading {args.input}: {exc}",
                  file=sys.stderr)
            return 2
        result = DifficultyGrader().grade(email)
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    if args.cmd == "defang":
        print(defang_text(args.text))
        return 0

    if args.cmd == "refang":
        print(refang_text(args.text))
        return 0

    if args.cmd == "auth-status":
        st = AuthorizationGate().check()
        print(json.dumps(st.to_dict(), indent=2))
        return 0

    parser.error(f"unknown command {args.cmd!r}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
