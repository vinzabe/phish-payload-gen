"""URL / IOC defanging used everywhere we render lures or hits.

The library never returns a clickable URL. All output passes
through :func:`defang` first so that copy-pasting a training email
into Outlook does not accidentally turn it into a live phishing
message.
"""
from __future__ import annotations

import re

# Match http://, https://, ftp:// (case-insensitive), then a host.
_URL_RE = re.compile(
    r"\b(?P<scheme>https?|ftp)://(?P<rest>[^\s<>'\")]+)",
    flags=re.IGNORECASE,
)
# Bare dotted IPv4.
_IPV4_RE = re.compile(
    r"\b(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
    r"(?![\w.])\b")
# Bare hostname (foo.bar.tld) — defang only when there's no scheme
# in front. We keep this conservative: at least two dotted labels.
_BARE_HOST_RE = re.compile(
    r"(?<![@/\w.-])(?P<host>[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)",
    flags=re.IGNORECASE,
)

_REFANG_SCHEME = re.compile(
    r"\bh(?:xx|XX)p(?P<s>s?)(?:\[://\]|\[:\]//|://)",
    flags=re.IGNORECASE)
_REFANG_FTP = re.compile(
    r"\bf(?:xx|XX)p(?:\[://\]|\[:\]//|://)",
    flags=re.IGNORECASE)
_REFANG_DOT = re.compile(r"\[\.\]")
_REFANG_AT = re.compile(r"\[@\]")


def defang_url(url: str) -> str:
    """Defang a single URL string."""
    if not url:
        return url
    m = _URL_RE.match(url.strip())
    if not m:
        # Maybe it's a bare host.
        return _defang_host(url.strip())
    scheme = m.group("scheme")
    rest = m.group("rest")
    out_scheme = (
        "hxxp" + ("s" if scheme.lower() == "https" else "")
        if scheme.lower() in ("http", "https") else "fxxp")
    return f"{out_scheme}[://]{_defang_host(rest)}"


def _defang_host(s: str) -> str:
    return s.replace(".", "[.]").replace("@", "[@]")


def defang(text: str) -> str:
    """Defang every URL, bare host and IPv4 inside ``text``."""
    if not text:
        return text

    def _url_sub(m: re.Match[str]) -> str:
        scheme = m.group("scheme")
        rest = m.group("rest")
        out_scheme = (
            "hxxp" + ("s" if scheme.lower() == "https" else "")
            if scheme.lower() in ("http", "https") else "fxxp")
        return f"{out_scheme}[://]{_defang_host(rest)}"

    def _ip_sub(m: re.Match[str]) -> str:
        return f"{m.group(1)}[.]{m.group(2)}[.]" \
               f"{m.group(3)}[.]{m.group(4)}"

    def _host_sub(m: re.Match[str]) -> str:
        return _defang_host(m.group("host"))

    out = _URL_RE.sub(_url_sub, text)
    out = _IPV4_RE.sub(_ip_sub, out)
    # Defang the @ in email addresses *before* the bare-host
    # pass so the host part on the right of the @ is no longer
    # blocked by the bare-host lookbehind.
    out = re.sub(r"(?<=[A-Za-z0-9._%+-])@(?=[A-Za-z0-9])",
                 "[@]", out)
    out = _BARE_HOST_RE.sub(_host_sub, out)
    return out


def refang(text: str) -> str:
    """Inverse of :func:`defang` — for unit tests / analyst tools."""
    if not text:
        return text
    out = _REFANG_SCHEME.sub(
        lambda m: "http" + m.group("s").lower() + "://", text)
    out = _REFANG_FTP.sub("ftp://", out)
    out = _REFANG_DOT.sub(".", out)
    out = _REFANG_AT.sub("@", out)
    return out
