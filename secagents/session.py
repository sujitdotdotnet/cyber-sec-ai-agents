"""Per-visitor state for a public deployment.

On Streamlit Community Cloud every visitor shares one Python process. Module-level state (the model router with its
typed API keys, the live-log folder, the scan history) would leak between visitors. A ``Session`` bundles the
visitor's own copies, and ``activate`` points context variables at them for the current script run (LangGraph copies
the context into its worker threads, so agents see them too). When no session is active everything behaves as before:
one shared router and the folders from the settings.
"""

from __future__ import annotations

import shutil
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import settings
from .db import Db, open_db
from .identity import Identity, guest
from .limits import Allowance, Usage, allowance_for

_router: ContextVar[Any] = ContextVar("secagents_router", default=None)
_live: ContextVar[Path | None] = ContextVar("secagents_live_dir", default=None)
_history: ContextVar[Path | None] = ContextVar("secagents_history_dir", default=None)
_workspace: ContextVar[str] = ContextVar("secagents_workspace", default="default")
_scans: ContextVar[tuple[Db, str] | None] = ContextVar("secagents_scan_store", default=None)

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


def scan_store() -> tuple[Db, str] | None:
    """(database, owner) when Scan history is kept in the database for the current visitor, else None (files)."""
    return _scans.get()


def workspace() -> str:
    return _workspace.get()


@dataclass
class Session:
    id: str
    router: Any
    live_dir: Path
    history_dir: Path
    workspace: str
    identity: Identity
    allowance: Allowance
    db: Db
    scan_db: tuple[Db, str] | None = None  # signed-in users keep Scan history in the database, under their id
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def budget(self) -> Allowance:
        return self.allowance


def new_session(router: Any, identity: Identity | None = None, base: Path | None = None, db: Db | None = None) -> Session:
    """A fresh visitor session with its own folders under ``base`` (default: .sessions next to the history)."""
    identity = identity or guest()
    base = base or settings.history_dir.parent / ".sessions"
    db = db or open_db(settings.database_url or settings.memory_db)
    sid = uuid.uuid4().hex[:16]
    _sweep(base)
    usage = Usage(db)
    usage.prune()
    allowance = allowance_for(identity, usage)
    router.budget = allowance
    root = base / sid
    return Session(sid, router, root / "live", root / "history", identity.id, identity, allowance, db,
                   scan_db=None if identity.is_guest else (db, identity.id))


def activate(s: Session) -> None:
    """Make this session the current one for the running script (call at the top of every Streamlit rerun)."""
    _router.set(s.router)
    _live.set(s.live_dir)
    _history.set(s.history_dir)
    _workspace.set(s.workspace)
    _scans.set(s.scan_db)


def deactivate() -> None:
    for var, default in ((_router, None), (_live, None), (_history, None), (_workspace, "default"), (_scans, None)):
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
