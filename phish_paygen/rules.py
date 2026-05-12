"""Bundled phishing detection rules.

Each rule is a callable that takes an :class:`Email` and returns
a list of :class:`PhishingHit` (zero or more). Rules are
deliberately conservative — they prefer false-negatives over
false-positives so the library can be wired into an inbox without
flooding the user.

The bundled rule_ids and their meaning:

- ``PHX-DFM-001``  — display-name says one company, From: address
  uses a different domain.
- ``PHX-LKAL-001`` — sender domain looks like a known brand
  (Levenshtein-1 against bundled brand list).
- ``PHX-URG-001``  — urgent / fear-of-loss language in subject or
  body (multi-cue scoring).
- ``PHX-LINK-001`` — link URL points to an IP, uses uncommon TLD,
  or hides behind an URL shortener.
- ``PHX-LTXT-001`` — link text says one host, ``href`` points
  somewhere else.
- ``PHX-AB64-001`` — attachment with a suspicious extension is
  base64-encoded as a small, dense blob (heuristic).
- ``PHX-RPLY-001`` — ``Reply-To`` differs from ``From`` and uses
  a free-mail provider.
- ``PHX-LINKQ-001`` — body contains an unusually large number of
  links relative to its length.
- ``PHX-EXTSIG-001`` — message looks external (no internal-domain
  header) and has no signature block.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Protocol

from .email import Email


@dataclass(frozen=True)
class PhishingHit:
    """A single rule firing.

    ``severity`` is one of ``info / low / medium / high``.
    ``score`` is in [0,1] and is used by
    :class:`~phish_paygen.detector.PhishingDetector` to compute
    an aggregate confidence.
    """

    rule_id: str
    description: str
    severity: str
    score: float
    evidence: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "score": float(self.score),
            "evidence": dict(self.evidence),
        }


class PhishingRule(Protocol):
    rule_id: str

    def __call__(self, email: Email) -> list[PhishingHit]:
        ...


# ---- helpers ---------------------------------------------------

_LINK_HREF_RE = re.compile(
    r"<a\b[^>]*href\s*=\s*['\"](?P<href>[^'\"]+)['\"][^>]*>"
    r"(?P<text>.*?)</a>",
    flags=re.IGNORECASE | re.DOTALL)
_BARE_URL_RE = re.compile(
    r"\b(?P<url>https?://[^\s<>'\")]+)", flags=re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"https?://(?P<host>[^/\s<>'\":]+)", flags=re.IGNORECASE)
_IP_HOST_RE = re.compile(
    r"https?://(\d{1,3}\.){3}\d{1,3}(?::\d+)?(/|$)",
    flags=re.IGNORECASE)
_FREEMAIL = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "proton.me", "protonmail.com", "icloud.com", "aol.com",
    "yandex.com", "mail.ru", "gmx.com", "tutanota.com"})
_KNOWN_BRANDS = frozenset({
    "paypal.com", "microsoft.com", "google.com", "apple.com",
    "amazon.com", "dropbox.com", "linkedin.com", "github.com",
    "office365.com", "facebook.com", "instagram.com",
    "netflix.com", "fedex.com", "ups.com", "dhl.com"})
_BRAND_NAMES = frozenset({
    b.split(".")[0] for b in _KNOWN_BRANDS})
_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
    "rb.gy", "tiny.cc"})
_SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "xyz", "top", "click", "country", "kim",
    "men", "loan", "work", "click", "gq", "cf", "tk", "ml",
    "ga"})
_URGENT_WORDS = (
    "urgent", "immediately", "asap", "as soon as possible",
    "action required", "final notice", "last warning",
    "verify your account", "your account will be suspended",
    "expires today", "expires in", "within 24 hours",
    "within 48 hours", "click here", "act now",
    "limited time", "wire transfer", "payment failed")
_SUSPICIOUS_EXTS = frozenset({
    ".html", ".htm", ".js", ".vbs", ".vbe", ".jse", ".bat",
    ".cmd", ".ps1", ".scr", ".lnk", ".iso", ".img", ".rar",
    ".zip", ".7z", ".jar", ".hta", ".docm", ".xlsm",
    ".xltm", ".pptm"})


def _domain_of(addr: str) -> str:
    addr = (addr or "").strip().strip("<>").lower()
    if "@" not in addr:
        return addr
    return addr.rsplit("@", 1)[1].strip()


def _registrable(domain: str) -> str:
    """Naive eTLD+1 (no PSL)."""
    parts = domain.lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # Treat well-known two-label country tlds as one piece.
    second_levels = {"co", "ac", "gov", "org", "net"}
    tld_country = {"uk", "au", "nz", "jp", "br", "in", "kr"}
    if parts[-1] in tld_country and parts[-2] in second_levels:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (0 if ca == cb else 1))
        prev = curr
    return prev[-1]


def _iter_links(email: Email):
    """Yield (href, text). Anchor text is empty for bare URLs."""
    for m in _LINK_HREF_RE.finditer(email.body_html):
        text = re.sub(r"<[^>]+>", "", m.group("text") or "")
        yield m.group("href"), text.strip()
    for m in _BARE_URL_RE.finditer(email.body_text):
        yield m.group("url"), ""


# ---- rules -----------------------------------------------------


@dataclass
class DisplayFromMismatch:
    rule_id: str = "PHX-DFM-001"

    def __call__(self, email: Email) -> list[PhishingHit]:
        name = (email.from_name or "").lower()
        if not name:
            return []
        addr_domain = _domain_of(email.from_addr)
        if not addr_domain:
            return []
        for brand in _BRAND_NAMES:
            if brand in name and brand not in addr_domain:
                return [PhishingHit(
                    rule_id=self.rule_id,
                    description=(
                        "display name mentions a brand that is "
                        "not in the From: domain"),
                    severity="high",
                    score=0.85,
                    evidence={
                        "from_name": email.from_name,
                        "from_addr": email.from_addr,
                        "brand": brand,
                    })]
        return []


@dataclass
class LookalikeDomain:
    rule_id: str = "PHX-LKAL-001"

    def __call__(self, email: Email) -> list[PhishingHit]:
        domain = _registrable(_domain_of(email.from_addr))
        if not domain or domain in _KNOWN_BRANDS:
            return []
        for brand in _KNOWN_BRANDS:
            d = _levenshtein(domain, brand)
            if 0 < d <= 2 and abs(len(domain) - len(brand)) <= 2:
                return [PhishingHit(
                    rule_id=self.rule_id,
                    description=(
                        "sender domain is a Levenshtein-near "
                        "match of a known brand"),
                    severity="high",
                    score=0.9,
                    evidence={
                        "from_domain": domain,
                        "brand_domain": brand,
                        "edit_distance": d,
                    })]
        return []


@dataclass
class UrgentActionLanguage:
    rule_id: str = "PHX-URG-001"

    def __call__(self, email: Email) -> list[PhishingHit]:
        haystack = (email.subject + "\n" + email.body_text
                    + "\n" + email.body_html).lower()
        cues = [w for w in _URGENT_WORDS if w in haystack]
        if not cues:
            return []
        # 1 cue = info, 2 = low, 3 = medium, 4+ = high.
        n = len(cues)
        if n == 1:
            sev, score = "info", 0.2
        elif n == 2:
            sev, score = "low", 0.4
        elif n == 3:
            sev, score = "medium", 0.6
        else:
            sev, score = "high", 0.8
        return [PhishingHit(
            rule_id=self.rule_id,
            description=(
                "urgent / fear-of-loss language in subject or "
                "body"),
            severity=sev,
            score=score,
            evidence={"cues": cues})]


@dataclass
class SuspiciousLink:
    rule_id: str = "PHX-LINK-001"

    def __call__(self, email: Email) -> list[PhishingHit]:
        hits: list[PhishingHit] = []
        seen: set[str] = set()
        for href, _text in _iter_links(email):
            if href in seen:
                continue
            seen.add(href)
            reasons: list[str] = []
            if _IP_HOST_RE.match(href):
                reasons.append("link uses a raw IP")
            host_match = _DOMAIN_RE.match(href)
            host = host_match.group("host").lower() \
                if host_match else ""
            registrable = _registrable(host) if host else ""
            tld = registrable.rsplit(".", 1)[-1] \
                if "." in registrable else ""
            if tld in _SUSPICIOUS_TLDS:
                reasons.append(f"suspicious TLD .{tld}")
            if registrable in _SHORTENERS:
                reasons.append(
                    f"URL shortener {registrable}")
            if reasons:
                hits.append(PhishingHit(
                    rule_id=self.rule_id,
                    description=(
                        "link URL has one or more suspicious "
                        "properties"),
                    severity=("high" if len(reasons) >= 2
                              else "medium"),
                    score=(0.85 if len(reasons) >= 2 else 0.6),
                    evidence={"href": href,
                              "reasons": reasons}))
        return hits


@dataclass
class MismatchedLinkText:
    rule_id: str = "PHX-LTXT-001"

    def __call__(self, email: Email) -> list[PhishingHit]:
        hits: list[PhishingHit] = []
        for m in _LINK_HREF_RE.finditer(email.body_html):
            href = m.group("href")
            raw_text = re.sub(r"<[^>]+>", "",
                              m.group("text") or "").strip()
            href_match = _DOMAIN_RE.match(href)
            href_host = href_match.group("host").lower() \
                if href_match else ""
            text_match = _DOMAIN_RE.match(raw_text)
            if not text_match:
                continue
            text_host = text_match.group("host").lower()
            if href_host and text_host \
                    and _registrable(href_host) \
                    != _registrable(text_host):
                hits.append(PhishingHit(
                    rule_id=self.rule_id,
                    description=(
                        "link text shows one domain but the "
                        "href points elsewhere"),
                    severity="high",
                    score=0.9,
                    evidence={
                        "text_domain": _registrable(text_host),
                        "href_domain": _registrable(href_host),
                    }))
        return hits


@dataclass
class AttachmentB64Suspicious:
    rule_id: str = "PHX-AB64-001"

    def __call__(self, email: Email) -> list[PhishingHit]:
        hits: list[PhishingHit] = []
        for att in email.attachments:
            name = str(att.get("filename", ""))
            ext = ("." + name.rsplit(".", 1)[-1].lower()) \
                if "." in name else ""
            if ext not in _SUSPICIOUS_EXTS:
                continue
            data = att.get("content_base64", "")
            if not data:
                continue
            data_len = len(str(data))
            # Very small base64 blob == probably a credential
            # harvester or downloader stub.
            if 16 <= data_len <= 200_000:
                hits.append(PhishingHit(
                    rule_id=self.rule_id,
                    description=(
                        "small base64 attachment with a high-"
                        "risk extension"),
                    severity="high",
                    score=0.85,
                    evidence={
                        "filename": name,
                        "extension": ext,
                        "b64_len": data_len,
                    }))
        return hits


@dataclass
class SuspiciousReplyTo:
    rule_id: str = "PHX-RPLY-001"

    def __call__(self, email: Email) -> list[PhishingHit]:
        if not email.reply_to:
            return []
        from_dom = _registrable(_domain_of(email.from_addr))
        rep_dom = _registrable(_domain_of(email.reply_to))
        if not from_dom or not rep_dom or from_dom == rep_dom:
            return []
        sev, score = "medium", 0.55
        if rep_dom in _FREEMAIL:
            sev, score = "high", 0.85
        return [PhishingHit(
            rule_id=self.rule_id,
            description=(
                "reply-to domain differs from sender domain"),
            severity=sev,
            score=score,
            evidence={
                "from_domain": from_dom,
                "reply_to_domain": rep_dom,
                "reply_to_is_freemail": rep_dom in _FREEMAIL,
            })]


@dataclass
class TooManyLinks:
    rule_id: str = "PHX-LINKQ-001"
    threshold_per_100_chars: float = 0.15

    def __call__(self, email: Email) -> list[PhishingHit]:
        body_len = max(len(email.body_text)
                       + len(email.body_html), 1)
        n_links = sum(1 for _ in _iter_links(email))
        if n_links < 3:
            return []
        density = n_links / max(body_len / 100.0, 1.0)
        if density < self.threshold_per_100_chars:
            return []
        return [PhishingHit(
            rule_id=self.rule_id,
            description=(
                "unusually many links relative to body length"),
            severity="medium",
            score=0.55,
            evidence={
                "n_links": n_links,
                "body_len": body_len,
                "density": round(density, 3),
            })]


@dataclass
class UnsignedExternalSender:
    rule_id: str = "PHX-EXTSIG-001"
    internal_domains: tuple[str, ...] = ()

    def __call__(self, email: Email) -> list[PhishingHit]:
        if not self.internal_domains:
            return []
        from_dom = _registrable(_domain_of(email.from_addr))
        if from_dom in self.internal_domains:
            return []
        body = (email.body_text or "")
        # Cheap signature heuristic: must contain at least one
        # of '--', 'Regards', 'Best,', 'Sincerely'.
        if any(tok.lower() in body.lower()
               for tok in ("--", "Regards", "Best,",
                           "Sincerely", "Cheers")):
            return []
        return [PhishingHit(
            rule_id=self.rule_id,
            description=(
                "external sender with no recognisable "
                "signature block"),
            severity="low",
            score=0.35,
            evidence={"from_domain": from_dom})]


def default_rules(
        internal_domains: Iterable[str] = ()) \
        -> list[PhishingRule]:
    """Return the bundled rule set in stable order."""
    return [
        DisplayFromMismatch(),
        LookalikeDomain(),
        UrgentActionLanguage(),
        SuspiciousLink(),
        MismatchedLinkText(),
        AttachmentB64Suspicious(),
        SuspiciousReplyTo(),
        TooManyLinks(),
        UnsignedExternalSender(
            internal_domains=tuple(internal_domains)),
    ]
