"""Authorization is the gate. Nothing renders without a valid, in-scope reference.

An authorization records who approved the engagement, its scope (the domains the
simulation may target), and an expiry. It is verified with an HMAC signature so a
forged authorization is rejected — you cannot hand-write an approval.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import hmac


class AuthorizationError(RuntimeError):
    """Raised for a missing, invalid, expired, or out-of-scope authorization."""


@dataclasses.dataclass(frozen=True, slots=True)
class Authorization:
    engagement_id: str
    approver: str                 # who signed off (a person, recorded)
    scope_domains: tuple[str, ...]  # domains the simulation may target
    expires: dt.date
    signature: str = ""

    def _payload(self) -> bytes:
        doms = ",".join(sorted(self.scope_domains))
        return (f"{self.engagement_id}\x1f{self.approver}\x1f{doms}"
                f"\x1f{self.expires.isoformat()}").encode()

    def sign(self, secret: str) -> Authorization:
        if not secret:
            raise AuthorizationError("a signing secret is required")
        sig = hmac.new(secret.encode(), self._payload(),
                       hashlib.sha256).hexdigest()
        return dataclasses.replace(self, signature=sig)

    def verify(self, secret: str, *, today: dt.date) -> None:
        """Raise unless the authorization is authentic and current."""
        if not self.signature:
            raise AuthorizationError("authorization is unsigned")
        expected = hmac.new(secret.encode(), self._payload(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(self.signature, expected):
            raise AuthorizationError(
                "authorization signature is invalid (forged or tampered)")
        if today > self.expires:
            raise AuthorizationError(
                f"authorization expired on {self.expires.isoformat()}")
        if not self.scope_domains:
            raise AuthorizationError("authorization has no in-scope domains")

    def permits_target(self, email: str) -> bool:
        """True only if the target's domain is in the authorized scope."""
        domain = email.split("@")[-1].lower().strip()
        return any(domain == d.lower() or domain.endswith("." + d.lower())
                   for d in self.scope_domains)
