"""What the knowledge files say about themselves: when they were last updated, from which sources, and CISA KEV flags.

``knowledge/meta.json`` is written by the daily sync (``knowledge_sync.py``). The footer reads it, so the page always
shows how fresh the data behind the scan is. Missing or unreadable metadata is not an error: the built-in demo files
still work, and the footer says so.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .config import settings

_kev_cache: dict[str, Any] = {"mtime": None, "ids": frozenset()}


def meta_path():
    return settings.knowledge_dir / "meta.json"


def load_meta() -> dict[str, Any]:
    try:
        doc = json.loads(meta_path().read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def kev_ids() -> frozenset[str]:
    """CVE ids on CISA's Known Exploited Vulnerabilities list (empty until the first sync has run)."""
    path = settings.knowledge_dir / "kev.jsonl"
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return frozenset()
    if _kev_cache["mtime"] != mtime:
        ids = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                ids.add(json.loads(line)["id"])
            except (ValueError, KeyError):
                continue
        _kev_cache.update(mtime=mtime, ids=frozenset(ids))
    return _kev_cache["ids"]


def kev_record(cve_id: str) -> dict[str, Any] | None:
    """The CISA KEV entry for a CVE id, or None."""
    path = settings.knowledge_dir / "kev.jsonl"
    wanted = cve_id.strip().upper()
    if wanted not in kev_ids():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("id") == wanted:
            return rec
    return None


def _day(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except ValueError:
        return iso[:10]


def footer_text() -> str:
    """One line for the page footer, e.g. ``Knowledge updated 2026-10-23 UTC · CISA KEV 1,583 · OSV 4,210 · ATT&CK v18.1``."""
    meta = load_meta()
    sources = meta.get("sources", {})
    if not sources:
        return "Knowledge base: built-in demo data (run the knowledge sync to load current data)"
    parts = [f"Knowledge updated {_day(meta.get('updated_at', ''))} UTC"]
    if "cisa_kev" in sources:
        parts.append(f"CISA KEV {sources['cisa_kev'].get('count', 0):,} (catalog {sources['cisa_kev'].get('source_date', '?')})")
    if "osv" in sources:
        parts.append(f"OSV {sources['osv'].get('count', 0):,} advisories")
    if "mitre_attack" in sources:
        parts.append(f"MITRE ATT&CK v{sources['mitre_attack'].get('version', '?')}")
    return " · ".join(parts)


def source_table() -> list[dict[str, Any]]:
    """Rows for a details view: one per source with its URL, record count and dates."""
    names = {"cisa_kev": "CISA Known Exploited Vulnerabilities", "osv": "OSV.dev (PyPI advisories)", "mitre_attack": "MITRE ATT&CK (Enterprise)"}
    return [{"Source": names.get(k, k), "Records": v.get("count", 0), "Source date / version": v.get("source_date") or v.get("version", ""),
             "Changed": _day(v.get("updated", "")), "URL": v.get("url", "")} for k, v in load_meta().get("sources", {}).items()]
