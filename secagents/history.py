"""Scan history: each finished assessment is saved as one JSON file so it can be reopened later."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .config import settings
from .session import history_override


def history_dir() -> Path:
    return history_override() or settings.history_dir


def _dir() -> Path:
    history_dir().mkdir(parents=True, exist_ok=True)
    return history_dir()


def default_name(source: str, result: dict, when: datetime | None = None) -> str:
    when = when or datetime.now()
    risk = result.get("threat_intel", {}).get("overall_risk", "n/a")
    return f"{source} · {when:%d %b %H:%M} · {risk}"


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
    (_dir() / f"{scan_id}.json").write_text(json.dumps(record, default=str))
    return scan_id


def list_scans() -> list[dict]:
    """Newest first, without the (large) result payload."""
    scans = []
    for p in sorted(_dir().glob("*.json"), reverse=True):
        try:
            rec = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        rec.pop("result", None)
        scans.append(rec)
    return scans


def _path(scan_id: str) -> Path:
    if not re.fullmatch(r"[0-9TZ]+", scan_id):
        raise ValueError(f"bad scan id: {scan_id}")
    return _dir() / f"{scan_id}.json"


def load(scan_id: str) -> dict:
    return json.loads(_path(scan_id).read_text())


def rename(scan_id: str, name: str) -> None:
    rec = load(scan_id)
    rec["name"] = name.strip() or rec["name"]
    _path(scan_id).write_text(json.dumps(rec, default=str))


def delete(scan_id: str) -> None:
    _path(scan_id).unlink(missing_ok=True)
