"""Spending and abuse limits for a public deployment, kept in the database so a restart does not reset them.

Everything here is about the host's own API key. A visitor who pastes their own key is never blocked or charged (the
router checks that). Three things are limited: model tokens (per guest session, per client or user per day, and for
everyone together), model calls per minute, and GitHub / Drive downloads per day.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable

from .config import settings
from .db import Db
from .identity import Identity

DDL = """
CREATE TABLE IF NOT EXISTS usage (owner TEXT NOT NULL, day TEXT NOT NULL, kind TEXT NOT NULL, amount BIGINT NOT NULL, PRIMARY KEY (owner, day, kind))
"""
GLOBAL = "*"
CHECK_EVERY = 3.0  # seconds: how long a "not blocked" answer is trusted before the database is asked again


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class Usage:
    """Counters per (owner, day, kind). kind is "tokens" or "downloads"."""

    _lock = threading.Lock()

    def __init__(self, db: Db):
        self.db = db
        db.script(DDL)

    def get(self, owner: str, kind: str, day: str | None = None) -> int:
        with self.db.transaction() as tx:
            row = tx.execute("SELECT amount FROM usage WHERE owner=? AND day=? AND kind=?", (owner, day or today(), kind)).fetchone()
        return int(row["amount"]) if row else 0

    def add(self, owner: str, kind: str, amount: int, day: str | None = None) -> None:
        with self._lock, self.db.transaction() as tx:
            tx.execute("INSERT INTO usage (owner, day, kind, amount) VALUES (?,?,?,?) "
                       "ON CONFLICT (owner, day, kind) DO UPDATE SET amount = usage.amount + EXCLUDED.amount",
                       (owner, day or today(), kind, int(amount)))

    def prune(self, keep_days: int = 7) -> None:
        cutoff = datetime.fromtimestamp(time.time() - keep_days * 86400, timezone.utc).strftime("%Y-%m-%d")
        with self.db.transaction() as tx:
            tx.execute("DELETE FROM usage WHERE day < ?", (cutoff,))


class Allowance:
    """One visitor's limits. The router asks ``blocked()`` before using the host's key and reports ``spend()`` after."""

    def __init__(self, usage: Usage, identity: Identity, *, session_cap: int | None, daily_cap: int, global_cap: int,
                 rate_per_minute: int, download_cap: int, clock: Callable[[], float] = time.monotonic):
        self.usage, self.identity = usage, identity
        self.session_cap, self.daily_cap, self.global_cap = session_cap, daily_cap, global_cap
        self.rate_per_minute, self.download_cap, self.clock = rate_per_minute, download_cap, clock
        self.session_used = 0
        self._calls: deque[float] = deque()
        self._seen_downloads: set[str] = set()
        self._ok_until = 0.0

    # ---- tokens ----------------------------------------------------------------------------------------------
    def daily_used(self) -> int:
        return self.usage.get(self.identity.limit_key, "tokens")

    def blocked(self) -> str | None:
        """A sentence explaining why the host's key is unavailable right now, or None."""
        now = self.clock()
        while self._calls and now - self._calls[0] > 60:
            self._calls.popleft()
        if len(self._calls) >= self.rate_per_minute:
            return "Too many requests in a short time. Wait a few seconds and try again."
        if self.session_cap is not None and self.session_used >= self.session_cap:
            return (f"This guest session used its {self.session_cap:,}-token allowance on the shared key. "
                    "Sign in for more, or paste your own API key in the sidebar.")
        if now < self._ok_until:
            return None
        if self.daily_used() >= self.daily_cap:
            who = "Today's guest allowance" if self.identity.is_guest else "Your daily allowance"
            return f"{who} on the shared key is used up. " + ("Sign in for more, p" if self.identity.is_guest else "P") + "aste your own API key, or try again tomorrow."
        if self.usage.get(GLOBAL, "tokens") >= self.global_cap:
            return "The shared key reached today's limit for all visitors. Paste your own API key, or try again tomorrow."
        self._ok_until = now + CHECK_EVERY
        return None

    def spend(self, tokens: int) -> None:
        tokens = max(0, int(tokens))
        self.session_used += tokens
        self._calls.append(self.clock())
        self._ok_until = 0.0  # re-check the totals on the next question
        self.usage.add(self.identity.limit_key, "tokens", tokens)
        self.usage.add(GLOBAL, "tokens", tokens)

    # ---- downloads -------------------------------------------------------------------------------------------
    def download(self, url: str) -> str | None:
        """Count a GitHub / Drive fetch. None if it may go ahead (a repeat of one already counted is free)."""
        if url in self._seen_downloads:
            return None
        if self.usage.get(self.identity.limit_key, "downloads") >= self.download_cap:
            return (f"Download limit reached ({self.download_cap} GitHub / Drive fetches a day"
                    + (", sign in for more" if self.identity.is_guest else "") + "). Upload the files instead, or try tomorrow.")
        self._seen_downloads.add(url)
        self.usage.add(self.identity.limit_key, "downloads", 1)
        return None


def allowance_for(identity: Identity, usage: Usage) -> Allowance:
    guest = identity.is_guest
    return Allowance(
        usage, identity,
        session_cap=settings.session_token_cap if guest else None,
        daily_cap=settings.guest_daily_token_cap if guest else settings.user_daily_token_cap,
        global_cap=settings.daily_token_cap, rate_per_minute=settings.rate_per_minute,
        download_cap=settings.guest_daily_downloads if guest else settings.user_daily_downloads,
    )
