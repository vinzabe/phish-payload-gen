"""CLI: sign an authorization, generate artifacts, record clicks, report rates.

`generate` exit codes: 0 generated, 3 REFUSED (no/invalid auth or out-of-scope),
1 error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

from . import __version__
from .authorization import Authorization, AuthorizationError
from .generator import generate
from .store import Store
from .templates import template_ids

EXIT_OK, EXIT_ERROR, EXIT_REFUSED = 0, 1, 3


def _secret(a: argparse.Namespace) -> str:
    s = a.secret or os.environ.get("PHISHGEN_SECRET", "")
    if not s:
        raise AuthorizationError(
            "a signing secret is required (--secret or PHISHGEN_SECRET)")
    return s


def _today() -> dt.date:
    return dt.datetime.now(dt.UTC).date()


def cmd_authorize(a: argparse.Namespace) -> int:
    auth = Authorization(
        engagement_id=a.engagement, approver=a.approver,
        scope_domains=tuple(a.scope), expires=dt.date.fromisoformat(a.expires),
    ).sign(_secret(a))
    print(json.dumps({
        "engagement_id": auth.engagement_id, "approver": auth.approver,
        "scope_domains": list(auth.scope_domains),
        "expires": auth.expires.isoformat(), "signature": auth.signature},
        indent=2))
    return EXIT_OK


def _load_auth(path: str) -> Authorization:
    d = json.loads(open(path).read())  # noqa: SIM115
    return Authorization(
        engagement_id=d["engagement_id"], approver=d["approver"],
        scope_domains=tuple(d["scope_domains"]),
        expires=dt.date.fromisoformat(d["expires"]),
        signature=d.get("signature", ""))


def cmd_generate(a: argparse.Namespace) -> int:
    auth = _load_auth(a.authorization)
    try:
        art = generate(auth, a.template, a.target, secret=_secret(a),
                       base_url=a.base_url, today=_today())
    except AuthorizationError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return EXIT_REFUSED
    with Store(a.store) as st:
        st.record_artifact(art.tracking_id, art.engagement_id, art.target,
                           art.template_id)
    if a.json:
        print(json.dumps({
            "tracking_id": art.tracking_id, "subject": art.subject,
            "body": art.body, "headers": dict(art.headers),
            "watermarked": art.is_watermarked}, indent=2))
    else:
        print(f"[{art.tracking_id}] to {art.target}\n")
        print("Subject:", art.subject)
        for k, v in art.headers:
            print(f"{k}: {v}")
        print("\n" + art.body)
    return EXIT_OK


def cmd_click(a: argparse.Namespace) -> int:
    with Store(a.store) as st:
        ok = st.record_click(a.tracking_id)
    if not ok:
        print("unknown tracking id — ignored", file=sys.stderr)
        return EXIT_ERROR
    print("click recorded (educational landing page shown; nothing captured)")
    return EXIT_OK


def cmd_report(a: argparse.Namespace) -> int:
    with Store(a.store) as st:
        clicked, sent = st.click_rate(a.engagement)
    rate = clicked / sent if sent else 0.0
    print(json.dumps({"engagement_id": a.engagement, "sent": sent,
                      "clicked": clicked, "click_rate": round(rate, 4)},
                     indent=2) if a.json else
          f"engagement {a.engagement}: {clicked}/{sent} clicked "
          f"({rate:.1%}) — feeds TRAINING assignment, not discipline")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishgen", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--store", default="phishgen.db")
    p.add_argument("--secret", help="HMAC secret (or PHISHGEN_SECRET)")
    sub = p.add_subparsers(dest="cmd", required=True)

    au = sub.add_parser("authorize", help="sign an engagement authorization")
    au.add_argument("--engagement", required=True)
    au.add_argument("--approver", required=True)
    au.add_argument("--scope", action="append", required=True,
                    help="in-scope domain (repeatable)")
    au.add_argument("--expires", required=True, help="YYYY-MM-DD")
    au.set_defaults(func=cmd_authorize)

    g = sub.add_parser("generate", help="render a simulation artifact")
    g.add_argument("authorization", help="signed authorization JSON")
    g.add_argument("--template", required=True, choices=template_ids())
    g.add_argument("--target", required=True, help="recipient email (in scope)")
    g.add_argument("--base-url", default="https://awareness.example.com")
    g.add_argument("--json", action="store_true")
    g.set_defaults(func=cmd_generate)

    c = sub.add_parser("click", help="record a click (shows educational page)")
    c.add_argument("tracking_id")
    c.set_defaults(func=cmd_click)

    r = sub.add_parser("report", help="click rate for an engagement")
    r.add_argument("--engagement", required=True)
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (OSError, ValueError, KeyError, AuthorizationError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
