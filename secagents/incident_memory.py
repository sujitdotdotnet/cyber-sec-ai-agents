"""Memory of past incidents: "have we seen something like this before?"

Every saved assessment adds its incidents to a Chroma collection, tagged with the owner (the signed-in user, or the local
workspace). When the Incident Response agent declares an incident it looks up the owner's closest earlier ones and
attaches them, so the playbook and the briefing can say "this resembles INC-01 from the 12 Oct scan". Lookups are always
filtered to one owner, so on a shared deployment nobody sees anyone else's incidents.

Guests keep nothing after they leave, so nothing of theirs is remembered. Failures never reach the assessment: a missing
or broken memory just means no "similar past incidents".
"""

from __future__ import annotations

import logging
from typing import Any

from . import history, session
from .config import settings
from .rag import get_kb

log = logging.getLogger(__name__)
BACKFILL_SCANS = 30  # on first use, learn from this many of the owner's most recent saved scans
_backfilled: set[tuple[str, str]] = set()


def owner() -> str:
    return session.workspace()


def enabled() -> bool:
    """Local runs and signed-in users remember; a guest does not (their session is not kept anyway)."""
    return not settings.public or session.scan_store() is not None


def _text(incident: dict[str, Any]) -> str:
    return f"{incident.get('title', '')}. {incident.get('summary', '')}"


def remember(scan_id: str, incidents: list[dict[str, Any]]) -> int:
    if not incidents or not enabled():
        return 0
    try:
        return get_kb().add_incidents(owner(), scan_id, incidents)
    except Exception as exc:  # noqa: BLE001 - memory is a bonus, never a reason to fail a save
        log.warning("could not remember incidents of %s: %s", scan_id, exc)
        return 0


def _backfill(kb) -> None:
    """After a restart the vector store may be empty while the scan history is not: relearn from the history, once."""
    key = (kb.cfg.chroma_dir.as_posix(), owner())
    if key in _backfilled:
        return
    _backfilled.add(key)
    for scan in history.list_scans()[:BACKFILL_SCANS]:
        try:
            plan = history.load(scan["id"]).get("result", {}).get("incident_plan", {})
            kb.add_incidents(owner(), scan["id"], plan.get("incidents", []))
        except Exception:  # noqa: BLE001
            continue


def similar(incidents: list[dict[str, Any]], k: int = 2) -> dict[str, list[dict[str, Any]]]:
    """{incident id: [closest earlier incidents of this owner]} for the incidents just declared (only those with a match)."""
    if not incidents or not enabled():
        return {}
    try:
        kb = get_kb()
        _backfill(kb)
        out = {}
        for inc in incidents:
            matches = [m for m in kb.similar_incidents(owner(), _text(inc), k=k) if m["score"] >= 0.2]
            if matches:
                out[inc["id"]] = matches
        return out
    except Exception as exc:  # noqa: BLE001
        log.warning("past-incident lookup failed: %s", exc)
        return {}
