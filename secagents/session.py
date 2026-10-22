"""Per-visitor state for a public deployment.

On Streamlit Community Cloud every visitor shares one Python process. Module-level state (the model router with its
typed API keys, the live-log folder, the scan history) would leak between visitors. A ``Session`` bundles the
visitor's own copies, and ``activate`` points context variables at them for the current script run (LangGraph copies
the context into its worker threads, so agents see them too). When no session is active everything behaves as before:
one shared router and the folders from the settings.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .config import settings

_router: ContextVar[Any] = ContextVar("secagents_router", default=None)
_live: ContextVar[Path | None] = ContextVar("secagents_live_dir", default=None)
_history: ContextVar[Path | None] = ContextVar("secagents_history_dir", default=None)
_workspace: ContextVar[str] = ContextVar("secagents_workspace", default="default")

STALE_AFTER = 24 * 3600  # per-session folders older than this are removed


def current_router() -> Any:
    return _router.get()


def live_override() -> Path | None:
    return _live.get()


def history_override() -> Path | None:
    return _history.get()


def live_dir() -> Path:
    return _live.get() or settings.live_dir


def history_dir() -> Path:
    return _history.get() or settings.history_dir


def workspace() -> str:
    return _workspace.get()


def workspace_id(code: str) -> str:
    """A stable workspace id from a code the visitor chose (so memory survives a page reload). Not authentication."""
    return "ws-" + hashlib.sha256(code.strip().encode()).hexdigest()[:16]


class DailyBudget:
    """Model tokens spent from the host's own API keys: a cap per visitor session and one per day for everyone."""

    _lock = threading.Lock()

    def __init__(self, file: Path, session_cap: int, daily_cap: int):
        self.file, self.session_cap, self.daily_cap, self.session_used = file, session_cap, daily_cap, 0

    def _read(self) -> dict[str, Any]:
        try:
            doc = json.loads(self.file.read_text())
            return doc if doc.get("day") == str(date.today()) else {"day": str(date.today()), "tokens": 0}
        except (OSError, ValueError):
            return {"day": str(date.today()), "tokens": 0}

    def daily_used(self) -> int:
        return int(self._read()["tokens"])

    def blocked(self) -> str | None:
        if self.session_used >= self.session_cap:
            return f"This session used its {self.session_cap:,}-token allowance on the shared key. Paste your own API key in the sidebar to continue."
        if self.daily_used() >= self.daily_cap:
            return "The shared key reached today's limit. Paste your own API key in the sidebar, or try again tomorrow."
        return None

    def spend(self, tokens: int) -> None:
        self.session_used += tokens
        with self._lock:
            doc = self._read()
            doc["tokens"] = int(doc["tokens"]) + tokens
            try:
                self.file.parent.mkdir(parents=True, exist_ok=True)
                self.file.write_text(json.dumps(doc))
            except OSError:
                pass


@dataclass
class Session:
    id: str
    router: Any
    live_dir: Path
    history_dir: Path
    workspace: str
    budget: DailyBudget | None = None
    extras: dict[str, Any] = field(default_factory=dict)


def new_session(router: Any, base: Path | None = None) -> Session:
    """A fresh visitor session with its own folders under ``base`` (default: .sessions next to the history)."""
    base = base or settings.history_dir.parent / ".sessions"
    sid = uuid.uuid4().hex[:16]
    _sweep(base)
    root = base / sid
    budget = DailyBudget(base / "usage.json", settings.session_token_cap, settings.daily_token_cap)
    router.budget = budget
    return Session(sid, router, root / "live", root / "history", sid, budget)


def activate(s: Session) -> None:
    """Make this session the current one for the running script (call at the top of every Streamlit rerun)."""
    _router.set(s.router)
    _live.set(s.live_dir)
    _history.set(s.history_dir)
    _workspace.set(s.workspace)


def deactivate() -> None:
    for var, default in ((_router, None), (_live, None), (_history, None), (_workspace, "default")):
        var.set(default)


def _sweep(base: Path) -> None:
    """Delete session folders nobody touched for a day, so a public host's disk does not fill up."""
    if not base.is_dir():
        return
    cutoff = time.time() - STALE_AFTER
    for d in base.iterdir():
        try:
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass
