"""Who is using a public deployment: a signed-in user (stable id, saved data) or a guest (this session only).

Pure logic, no Streamlit: the sign-in itself (``st.login``) lives in ``gate.py``. A guest is limited per client where
the host reveals one (the address the proxy saw, stored only as a hash), so opening a new tab does not reset their
allowance; a user is limited per account.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass

from .config import settings


@dataclass(frozen=True)
class Identity:
    kind: str  # "guest" | "user"
    id: str  # the memory workspace and history owner
    label: str  # what the sidebar shows
    limit_key: str  # whose allowance is charged

    @property
    def is_guest(self) -> bool:
        return self.kind == "guest"


def _digest(text: str, n: int = 20) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:n]


def client_hash(forwarded_for: str | None) -> str | None:
    """A hash of the client address from an X-Forwarded-For header, or None. The right-most entry is the one our own
    proxy appended; earlier ones are client-controlled and could be forged, so they are ignored."""
    parts = [p.strip() for p in (forwarded_for or "").split(",") if p.strip()]
    return _digest(parts[-1], 16) if parts else None


def guest(session_id: str | None = None, client: str | None = None) -> Identity:
    sid = session_id or uuid.uuid4().hex[:16]
    return Identity("guest", sid, "Guest", f"guest-{client}" if client else sid)


def user(subject: str, label: str) -> Identity:
    """A signed-in user. ``subject`` is the provider's stable id (the OIDC ``sub``), or the e-mail if there is none."""
    uid = "u-" + _digest(subject.strip().lower())
    return Identity("user", uid, label or "Signed in", uid)


def check_allowed(email: str, verified: bool | None = None) -> str | None:
    """None if this account may use the app, else a reason. With no allow-list configured any verified account may."""
    email = (email or "").strip().lower()
    if verified is False:
        return "Your e-mail address is not verified with the sign-in provider."
    if settings.allowed_emails or settings.allowed_email_domains:
        domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        if email not in settings.allowed_emails and domain not in settings.allowed_email_domains:
            return f"{email or 'This account'} is not on this site's access list."
    return None
