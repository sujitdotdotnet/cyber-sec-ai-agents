"""Agent memory in SQLite: conversation threads (short-term) and remembered facts (long-term).

Everything is scoped by a workspace id so one visitor never reads another's history on a shared deployment.
Facts are recalled by meaning with the local hashed embeddings (no API call, no key) blended with keyword overlap.
Secrets are redacted before anything is written. The file lives on the host's disk, which is ephemeral on Streamlit
Community Cloud, so memories and threads can be exported to JSON and imported back.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from .rag.store import hash_embed

MAX_FACT_CHARS = 500
MAX_FACTS = 200
EXPORT_VERSION = 1

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),  # OpenAI / Anthropic / OpenRouter style keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*\S{6,}"),
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS threads (id TEXT PRIMARY KEY, workspace TEXT NOT NULL, title TEXT NOT NULL, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS messages (thread_id TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (thread_id, seq));
CREATE TABLE IF NOT EXISTS memories (id TEXT PRIMARY KEY, workspace TEXT NOT NULL, text TEXT NOT NULL, vec TEXT NOT NULL, created REAL);
CREATE INDEX IF NOT EXISTS memories_ws ON memories (workspace);
CREATE INDEX IF NOT EXISTS threads_ws ON threads (workspace, updated);
"""


def looks_secret(text: str) -> bool:
    return any(p.search(text) for p in SECRET_PATTERNS)


def redact(text: str) -> str:
    for p in SECRET_PATTERNS:
        text = p.sub("[redacted]", text)
    return text


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    return dot / ((math.sqrt(sum(x * x for x in a)) or 1.0) * (math.sqrt(sum(y * y for y in b)) or 1.0))


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", text.lower()))


class Memory:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._keep = sqlite3.connect(str(self.path), check_same_thread=False) if str(path) == ":memory:" else None
        with self._db() as db:
            db.executescript(SCHEMA)

    def _db(self):
        db = self._keep or sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        return _Conn(db, owned=self._keep is None)

    # ---- threads -----------------------------------------------------------------------------------------
    def create_thread(self, workspace: str, title: str = "New chat") -> str:
        tid, now = uuid.uuid4().hex[:12], time.time()
        with self._db() as db:
            db.execute("INSERT INTO threads VALUES (?,?,?,?,?)", (tid, workspace, redact(title)[:80] or "New chat", now, now))
        return tid

    def threads(self, workspace: str) -> list[dict[str, Any]]:
        with self._db() as db:
            rows = db.execute("SELECT id, title, created, updated FROM threads WHERE workspace=? ORDER BY updated DESC", (workspace,)).fetchall()
        return [dict(r) for r in rows]

    def owns_thread(self, thread_id: str, workspace: str) -> bool:
        with self._db() as db:
            return db.execute("SELECT 1 FROM threads WHERE id=? AND workspace=?", (thread_id, workspace)).fetchone() is not None

    def messages(self, thread_id: str, workspace: str) -> list[dict[str, Any]]:
        if not self.owns_thread(thread_id, workspace):
            return []
        with self._db() as db:
            rows = db.execute("SELECT body FROM messages WHERE thread_id=? ORDER BY seq", (thread_id,)).fetchall()
        return [json.loads(r["body"]) for r in rows]

    def save_messages(self, thread_id: str, workspace: str, messages: list[dict[str, Any]]) -> None:
        """Store the whole conversation (replaces what was saved), with secrets redacted."""
        if not self.owns_thread(thread_id, workspace):
            raise KeyError(thread_id)
        clean = [{**m, "content": redact(m.get("content") or "")} for m in messages]
        with self._db() as db:
            db.execute("DELETE FROM messages WHERE thread_id=?", (thread_id,))
            db.executemany("INSERT INTO messages VALUES (?,?,?)", [(thread_id, i, json.dumps(m, default=str)) for i, m in enumerate(clean)])
            first = next((m["content"] for m in clean if m.get("role") == "user" and m["content"]), "")
            db.execute("UPDATE threads SET updated=?, title=CASE WHEN title='New chat' AND ?<>'' THEN ? ELSE title END WHERE id=?",
                       (time.time(), first, first[:60], thread_id))

    def delete_thread(self, thread_id: str, workspace: str) -> bool:
        if not self.owns_thread(thread_id, workspace):
            return False
        with self._db() as db:
            db.execute("DELETE FROM messages WHERE thread_id=?", (thread_id,))
            db.execute("DELETE FROM threads WHERE id=?", (thread_id,))
        return True

    # ---- long-term facts ---------------------------------------------------------------------------------
    def remember(self, text: str, workspace: str) -> str | None:
        """Save a fact; returns its id, or None if it is empty, looks like a secret or the workspace is full."""
        text = " ".join(text.split())[:MAX_FACT_CHARS]
        if not text or looks_secret(text):
            return None
        with self._db() as db:
            if db.execute("SELECT COUNT(*) FROM memories WHERE workspace=?", (workspace,)).fetchone()[0] >= MAX_FACTS:
                return None
            same = db.execute("SELECT id FROM memories WHERE workspace=? AND lower(text)=lower(?)", (workspace, text)).fetchone()
            if same:
                return same["id"]
            mid = "m" + uuid.uuid4().hex[:8]
            db.execute("INSERT INTO memories VALUES (?,?,?,?,?)", (mid, workspace, text, json.dumps(hash_embed(text)), time.time()))
        return mid

    def facts(self, workspace: str) -> list[dict[str, Any]]:
        with self._db() as db:
            rows = db.execute("SELECT id, text, created FROM memories WHERE workspace=? ORDER BY created DESC", (workspace,)).fetchall()
        return [dict(r) for r in rows]

    def recall(self, query: str, workspace: str, k: int = 5) -> list[dict[str, Any]]:
        with self._db() as db:
            rows = db.execute("SELECT id, text, vec, created FROM memories WHERE workspace=?", (workspace,)).fetchall()
        q_vec, q_words = hash_embed(query), _words(query)
        scored = []
        for r in rows:
            overlap = len(q_words & _words(r["text"])) / (len(q_words) or 1)
            score = 0.6 * _cosine(q_vec, json.loads(r["vec"])) + 0.4 * overlap
            if score > 0.12:
                scored.append((score, {"id": r["id"], "text": r["text"], "created": r["created"], "score": round(score, 3)}))
        return [item for _, item in sorted(scored, key=lambda t: -t[0])[:k]]

    def forget(self, memory_id: str, workspace: str) -> bool:
        with self._db() as db:
            return db.execute("DELETE FROM memories WHERE id=? AND workspace=?", (memory_id, workspace)).rowcount > 0

    # ---- export / import (the disk is ephemeral on free hosting) --------------------------------------------
    def export_json(self, workspace: str) -> str:
        threads = [{**t, "messages": self.messages(t["id"], workspace)} for t in self.threads(workspace)]
        return json.dumps({"version": EXPORT_VERSION, "facts": [f["text"] for f in self.facts(workspace)], "threads": threads}, indent=1)

    def import_json(self, data: str, workspace: str) -> dict[str, int]:
        try:
            doc = json.loads(data)
            facts, threads = list(doc.get("facts", [])), list(doc.get("threads", []))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("not a SecAgents memory export") from exc
        added_facts = sum(1 for f in facts if isinstance(f, str) and self.remember(f, workspace))
        added_threads = 0
        for t in threads:
            msgs = [m for m in t.get("messages", []) if isinstance(m, dict) and m.get("role") in ("user", "assistant", "tool")]
            if msgs:
                tid = self.create_thread(workspace, str(t.get("title", "Imported chat")))
                self.save_messages(tid, workspace, msgs)
                added_threads += 1
        return {"facts": added_facts, "threads": added_threads}


class _Conn:
    """sqlite3 connection as a context manager that commits, and closes only connections it opened."""

    def __init__(self, db: sqlite3.Connection, owned: bool):
        self.db, self.owned = db, owned

    def __enter__(self) -> sqlite3.Connection:
        return self.db

    def __exit__(self, exc_type, *_):
        self.db.rollback() if exc_type else self.db.commit()
        if self.owned:
            self.db.close()
