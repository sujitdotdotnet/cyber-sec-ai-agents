"""The app's name and version, from one place.

Edit the ``VERSION`` file at the repository root (for example ``1.0.0`` -> ``1.1.0``) and every title, footer, report
and ``--version`` shows it. ``APP_VERSION`` in the environment (or the Streamlit secrets) overrides the file, which
helps for a one-off build. The file is read on every call, so a running app picks the edit up on its next rerun.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "Cyber Security AI Agent"
VERSION_PREFIX = "v."  # how the number is written in titles: "(v.1.0.0)"
VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"

def get_version() -> str:
    """The version number, such as ``1.0.0`` (a leading ``v`` in the file or variable is ignored)."""
    override = os.getenv("APP_VERSION", "").strip()
    if override:
        return override.lstrip("vV.")
    try:  # a few bytes: read on every call, so an edit shows at once and there is no stale cache to reason about
        return VERSION_FILE.read_text(encoding="utf-8").strip().lstrip("vV.") or "0.0.0"
    except OSError:
        return "0.0.0"


def version_label() -> str:
    return f"{VERSION_PREFIX}{get_version()}"


def app_title() -> str:
    """``Cyber Security AI Agent (v.1.0.0)``: the title used wherever the app names itself."""
    return f"{APP_NAME} ({version_label()})"
