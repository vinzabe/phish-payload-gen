"""Authorisation gate for realistic-lure generation.

This is the central choke point. ``LureGenerator.generate(...)``
asks the gate whether realistic copy is allowed *for this run*.
The default answer is **no** — the toolkit returns training-stub
output containing ``[FAKE-LINK]`` markers and obvious giveaways
unless both:

1. the environment variable ``AGSBX_RED_TEAM_AUTH=1`` is set, AND
2. an authorisation file at the path named by
   ``AGSBX_RED_TEAM_AUTH_FILE`` (default
   ``~/.agsbx_red_team_auth``) contains the *exact* statement
   :data:`AUTHORISATION_STATEMENT`.

Both checks are required; either one missing means stub output.
The gate also records a public :class:`AuthorizationStatus` value
so callers (CLI, scripts) can show *why* they got stubbed output.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

#: Required to be present verbatim in the auth file.
AUTHORISATION_STATEMENT = (
    "I confirm I have written authorisation from the target "
    "organisation to run a phishing-awareness exercise."
)

ENV_VAR = "AGSBX_RED_TEAM_AUTH"
ENV_VAR_FILE = "AGSBX_RED_TEAM_AUTH_FILE"
DEFAULT_AUTH_FILE = "~/.agsbx_red_team_auth"


@dataclass(frozen=True)
class AuthorizationStatus:
    """Result of an authorisation check.

    ``allowed`` is True only when both the env var and the file
    are in place. ``reason`` describes the *first* missing piece.
    """

    allowed: bool
    reason: str
    env_present: bool
    file_present: bool
    statement_present: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "env_present": self.env_present,
            "file_present": self.file_present,
            "statement_present": self.statement_present,
        }


class AuthorizationGate:
    """Stateless façade over the env+file check."""

    def __init__(self,
                 env_var: str = ENV_VAR,
                 env_var_file: str = ENV_VAR_FILE,
                 default_auth_file: str = DEFAULT_AUTH_FILE,
                 statement: str = AUTHORISATION_STATEMENT) -> None:
        self.env_var = env_var
        self.env_var_file = env_var_file
        self.default_auth_file = default_auth_file
        self.statement = statement

    def auth_file_path(self) -> Path:
        """Resolve the auth-file path."""
        raw = os.environ.get(self.env_var_file,
                             self.default_auth_file)
        return Path(raw).expanduser()

    def check(self) -> AuthorizationStatus:
        """Run the gate. Never raises."""
        env_val = os.environ.get(self.env_var, "")
        env_present = env_val == "1"
        path = self.auth_file_path()
        file_present = path.is_file()
        statement_present = False
        if file_present:
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                content = ""
            statement_present = self.statement in content

        if not env_present:
            reason = (f"environment variable {self.env_var}=1 "
                      f"is not set")
            return AuthorizationStatus(
                False, reason, env_present, file_present,
                statement_present)
        if not file_present:
            reason = f"authorisation file {path} not found"
            return AuthorizationStatus(
                False, reason, env_present, file_present,
                statement_present)
        if not statement_present:
            reason = (f"authorisation file {path} does not "
                      f"contain the required statement")
            return AuthorizationStatus(
                False, reason, env_present, file_present,
                statement_present)
        return AuthorizationStatus(
            True, "ok", env_present, file_present,
            statement_present)

    def is_allowed(self) -> bool:
        """Convenience wrapper."""
        return self.check().allowed
