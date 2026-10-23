"""The front door of a public deployment: Sign in (Streamlit's built-in OIDC login) or Continue as guest.

Only used when ``SECAGENTS_PUBLIC=1``. Locally there is no gate. Signing in needs an ``[auth]`` block in the Streamlit
secrets (see .streamlit/secrets.toml.example); without one the site is guest-only and says so.
"""

from __future__ import annotations

from dataclasses import dataclass

import streamlit as st

from . import identity as ident, session
from .config import settings
from .about import ABOUT_MD, ABOUT_TITLE
from .knowledge import footer_text, source_table
from .version import app_title


@dataclass(frozen=True)
class LoginState:
    logged_in: bool = False
    subject: str = ""
    email: str = ""
    name: str = ""
    verified: bool | None = None


def auth_configured() -> bool:
    """True when the Streamlit secrets contain an [auth] block, so st.login can work."""
    try:
        return "auth" in st.secrets
    except Exception:  # noqa: BLE001 - no secrets file at all
        return False


def login_state() -> LoginState:
    """Who the identity provider says this visitor is (patched in tests; st.user needs a real login cookie)."""
    try:
        user = st.user
        if not getattr(user, "is_logged_in", False):
            return LoginState()
        get = lambda k: (user.get(k) if hasattr(user, "get") else getattr(user, k, None)) or ""  # noqa: E731
        verified = user.get("email_verified") if hasattr(user, "get") else None
        return LoginState(True, str(get("sub")), str(get("email")), str(get("name")), verified if isinstance(verified, bool) else None)
    except Exception:  # noqa: BLE001
        return LoginState()


def client_hash() -> str | None:
    """Hash of the client address as the host's proxy saw it, if it says (used to limit guests across tabs)."""
    try:
        return ident.client_hash(st.context.headers.get("X-Forwarded-For"))
    except Exception:  # noqa: BLE001
        return None


def _sign_in() -> None:
    st.login(settings.auth_provider or None)


def _guest() -> None:
    st.session_state["guest_ok"] = True


SIGNIN_GREEN = "#1f9d55"
SIGNIN_CSS = (
    "<style>"
    ".st-key-gate-signin button, .st-key-side-signin button{"
    f"background-color:{SIGNIN_GREEN} !important;border-color:{SIGNIN_GREEN} !important;color:#fff !important}}"
    ".st-key-gate-signin button:hover, .st-key-side-signin button:hover{"
    "background-color:#17804a !important;border-color:#17804a !important;color:#fff !important}"
    "</style>"
)


def footer() -> None:
    """The bottom of every page: the app's name and version, then the collapsed About panel below it."""
    st.divider()
    st.caption(f"🛡️ {app_title()}")
    st.caption(f"📚 {footer_text()}")
    with st.expander(ABOUT_TITLE, expanded=False):
        st.markdown(ABOUT_MD)
        rows = source_table()
        if rows:
            st.markdown("**Knowledge sources** (refreshed daily; package versions are also checked live against OSV during a scan)")
            st.dataframe(rows, hide_index=True, use_container_width=True)


def resolve() -> ident.Identity:
    """The visitor's identity, or the landing page (and a stop) until they choose."""
    ss = st.session_state
    login = login_state()
    if login.logged_in:
        reason = ident.check_allowed(login.email, login.verified)
        if reason:
            st.error(reason, icon="🚫")
            st.button("Log out", on_click=st.logout, key="gate-denied-logout")
            st.stop()
        return ident.user(login.subject or login.email, login.email or login.name)
    if ss.get("guest_ok"):
        if "guest_identity" not in ss:
            ss["guest_identity"] = ident.guest(client=client_hash())
        return ss["guest_identity"]

    st.markdown(SIGNIN_CSS, unsafe_allow_html=True)
    st.title(f"🛡️ {app_title()}")
    st.caption("Five AI agents for detection, intel, scanning, response and compliance, plus a tool-using assistant.")
    left, right = st.columns(2)
    with left, st.container(border=True):
        st.subheader("Sign in")
        st.markdown("Your chats, memory and scan history are saved to your account.")
        st.markdown("🔑 Bring Your Own Key (BYOK)")
        if auth_configured():
            st.button("Sign in", type="primary", on_click=_sign_in, key="gate-signin", use_container_width=True)
        else:
            st.info("Sign-in is not set up on this site yet. Continue as a guest.")
    with right, st.container(border=True):
        st.subheader("Continue as guest")
        st.markdown("No account needed. Nothing is saved after you leave (you can export your chat).")
        st.markdown("🔑 Bring Your Own Key (BYOK)")
        st.button("Continue as guest", on_click=_guest, key="gate-guest", use_container_width=True)
    footer()
    st.stop()


def sidebar_box(visitor) -> None:
    """Who is signed in, and the sign in / log out button."""
    who = visitor.identity
    with st.container(border=True):
        if who.is_guest:
            st.markdown("👤 **Guest** · limited, nothing is saved")
            if auth_configured():
                st.markdown(SIGNIN_CSS, unsafe_allow_html=True)
                st.button("Sign in for more", on_click=_sign_in, key="side-signin", use_container_width=True)
        else:
            st.markdown(f"👤 **{who.label}**")
            st.button("Log out", on_click=st.logout, key="side-logout", use_container_width=True)
        if session.db_error():
            st.warning("Database unavailable, using temporary storage: your data will not survive a restart. "
                       f"({session.db_error()})", icon="🗄️")
        st.caption("🔑 Bring Your Own Key (BYOK)", help="Paste your own API key in the box below: it is used instead of the shared key "
                                                       "and is never limited or counted.")
