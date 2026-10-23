"""Scan history: each finished assessment is saved as one JSON file so it can be reopened later."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .config import settings
from .session import history_override, scan_store


def history_dir() -> Path:
    return history_override() or settings.history_dir


def _dir() -> Path:
    history_dir().mkdir(parents=True, exist_ok=True)
    return history_dir()


def default_name(source: str, result: dict, when: datetime | None = None) -> str:
    when = when or datetime.now()
    risk = result.get("threat_intel", {}).get("overall_risk", "n/a")
    return f"{source} · {when:%d %b %H:%M} · {risk}"


DDL = ("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, owner TEXT NOT NULL, created_at TEXT, name TEXT, source TEXT, "
       "risk TEXT, incidents INTEGER, body TEXT)")
_ready: set[int] = set()


def _db_store():
    """(db, owner) when this visitor's scans live in the database, with the table created."""
    store = scan_store()
    if store and id(store[0]) not in _ready:
        store[0].script(DDL)
        _ready.add(id(store[0]))
    return store


def save(result: dict, name: str, source: str) -> str:
    """Store a result and return its scan id."""
    now = datetime.now(timezone.utc)
    scan_id = now.strftime("%Y%m%dT%H%M%S%fZ")
    record = {
        "id": scan_id,
        "name": name.strip() or default_name(source, result),
        "source": source,
        "created_at": now.isoformat(timespec="seconds"),
        "risk": result.get("threat_intel", {}).get("overall_risk", "n/a"),
        "incidents": len(result.get("incident_plan", {}).get("incidents", [])),
        "result": result,
    }
    if store := _db_store():
        with store[0].transaction() as tx:
            tx.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)", (scan_id, store[1], record["created_at"], record["name"], source,
                                                                   record["risk"], record["incidents"], json.dumps(record, default=str)))
        return scan_id
    (_dir() / f"{scan_id}.json").write_text(json.dumps(record, default=str))
    return scan_id


def list_scans() -> list[dict]:
    """Newest first, without the (large) result payload."""
    if store := _db_store():
        with store[0].transaction() as tx:
            rows = tx.execute("SELECT id, name, source, created_at, risk, incidents FROM scans WHERE owner=? ORDER BY id DESC", (store[1],)).fetchall()
        return rows
    scans = []
    for p in sorted(_dir().glob("*.json"), reverse=True):
        try:
            rec = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        rec.pop("result", None)
        scans.append(rec)
    return scans


def _path_check(scan_id: str) -> None:
    if not re.fullmatch(r"[0-9TZ]+", scan_id):
        raise ValueError(f"bad scan id: {scan_id}")


def _path(scan_id: str) -> Path:
    _path_check(scan_id)
    return _dir() / f"{scan_id}.json"


def load(scan_id: str) -> dict:
    if store := _db_store():
        _path_check(scan_id)
        with store[0].transaction() as tx:
            row = tx.execute("SELECT body FROM scans WHERE id=? AND owner=?", (scan_id, store[1])).fetchone()
        if row is None:
            raise FileNotFoundError(scan_id)
        return json.loads(row["body"])
    return json.loads(_path(scan_id).read_text())


def rename(scan_id: str, name: str) -> None:
    rec = load(scan_id)
    rec["name"] = name.strip() or rec["name"]
    if store := _db_store():
        with store[0].transaction() as tx:
            tx.execute("UPDATE scans SET name=?, body=? WHERE id=? AND owner=?", (rec["name"], json.dumps(rec, default=str), scan_id, store[1]))
        return
    _path(scan_id).write_text(json.dumps(rec, default=str))


def delete(scan_id: str) -> None:
    if store := _db_store():
        _path_check(scan_id)
        with store[0].transaction() as tx:
            tx.execute("DELETE FROM scans WHERE id=? AND owner=?", (scan_id, store[1]))
        return
    _path(scan_id).unlink(missing_ok=True)
