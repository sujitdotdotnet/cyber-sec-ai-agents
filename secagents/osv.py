"""OSV.dev (https://osv.dev): open, curated vulnerability data for open-source packages.

Two uses share the conversion code here:

* the daily knowledge sync (``knowledge_sync.py``) downloads advisories for a watch-list of packages into
  ``knowledge/cves_synced.jsonl``;
* a **live lookup** during an assessment asks OSV about the exact package versions that were found, so a scan is
  current even between syncs. Answers are cached for a day in the app database; if OSV cannot be reached the scan
  carries on with the local files.

An OSV advisory becomes records in the same shape as ``knowledge/cves.jsonl``: package, affected version spec, fixed
version, CVSS score and severity, title, description.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from .config import settings

API = "https://api.osv.dev/v1"
TIMEOUT = (5, 15)
CACHE_TTL = 24 * 3600
MAX_COMPONENTS = 60  # per scan
MAX_ADVISORIES = 80  # details fetched per scan
USER_AGENT = "secagents-knowledge (+https://github.com/sujitdotdotnet/cyber-sec-ai-agents)"
LABEL_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}
PINNED = re.compile(r"^\d[\w.]*$")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---- CVSS v3 base score (OSV gives the vector, not the number) --------------------------------------------------
def _roundup(x: float) -> float:
    n = round(x * 100000)
    return n / 100000 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10


def cvss3_score(vector: str) -> float | None:
    """Base score from a CVSS:3.0 / 3.1 vector string, or None if it is not one (e.g. CVSS v4)."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    except (KeyError, ValueError):
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploit = 8.22 * av * ac * pr * ui
    return _roundup(min((1.08 if scope_changed else 1.0) * (impact + exploit), 10))


def severity_label(score: float) -> str:
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "UNKNOWN"


def score_and_severity(vuln: dict[str, Any]) -> tuple[float, str]:
    for s in vuln.get("severity", []) or []:
        score = cvss3_score(str(s.get("score", ""))) if s.get("type") in ("CVSS_V3", "CVSS_V3_0", "CVSS_V3_1") else None
        if score is not None:
            return score, severity_label(score)
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if label in LABEL_SCORE:
        return LABEL_SCORE[label], "MEDIUM" if label == "MODERATE" else label
    return 0.0, "UNKNOWN"


# ---- advisory -> records ------------------------------------------------------------------------------------------
def _spec(ranges: list[dict[str, Any]], versions: list[str]) -> tuple[str, list[str]]:
    """The affected versions as one spec the matcher understands: alternatives joined with ``||``, each a conjunction."""
    alternatives: list[str] = []
    fixed: list[str] = []
    for r in ranges:
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        start = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                start = ev["introduced"]
            elif "fixed" in ev or "last_affected" in ev:
                end_op, end = ("<", ev["fixed"]) if "fixed" in ev else ("<=", ev["last_affected"])
                parts = ([f">={start}"] if start not in (None, "0") else []) + [f"{end_op}{end}"]
                alternatives.append(",".join(parts))
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
                start = None
        if start is not None:  # introduced and never fixed
            alternatives.append(f">={start}" if start != "0" else ">=0")
    if not alternatives and versions:
        alternatives = [f"=={v}" for v in versions[:30]]
    return " || ".join(alternatives), fixed


def advisory_to_records(vuln: dict[str, Any], package: str | None = None) -> list[dict[str, Any]]:
    """Records (one per affected PyPI package) for an OSV advisory. ``package`` restricts to one package."""
    if vuln.get("withdrawn"):
        return []
    score, severity = score_and_severity(vuln)
    aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
    summary = (vuln.get("summary") or vuln.get("details") or vuln["id"]).strip().splitlines()[0][:160]
    details = re.sub(r"\s+", " ", vuln.get("details") or summary).strip()[:600]
    out = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != "PyPI":
            continue
        name = normalize(pkg.get("name", ""))
        if package and name != normalize(package):
            continue
        spec, fixed = _spec(aff.get("ranges", []), aff.get("versions", []))
        if not spec:
            continue
        out.append({
            "id": aliases[0] if aliases else vuln["id"], "package": name, "ecosystem": "pypi", "affected": spec,
            "fixed": ", ".join(dict.fromkeys(fixed)) or "no fix listed", "cvss": score, "severity": severity,
            "title": summary, "description": details, "source": "OSV", "osv_id": vuln["id"], "aliases": aliases,
            "modified": vuln.get("modified", ""),
        })
    return out


# ---- live lookup --------------------------------------------------------------------------------------------------
def live_enabled() -> bool:
    return not settings.offline and os.getenv("OSV_LIVE", "1").strip().lower() not in {"0", "false", "no"}


class Cache:
    """Responses cached for a day in the app database (Postgres when configured), shared by all visitors."""

    DDL = "CREATE TABLE IF NOT EXISTS osv_cache (key TEXT PRIMARY KEY, fetched DOUBLE PRECISION, body TEXT)"

    def __init__(self, db=None):
        from .session import shared_db

        self.db = db or shared_db()
        self.db.script(self.DDL)

    def get(self, key: str) -> Any | None:
        with self.db.transaction() as tx:
            row = tx.execute("SELECT fetched, body FROM osv_cache WHERE key=?", (key,)).fetchone()
        return json.loads(row["body"]) if row and time.time() - row["fetched"] < CACHE_TTL else None

    def put(self, key: str, value: Any) -> None:
        with self.db.transaction() as tx:
            tx.execute("DELETE FROM osv_cache WHERE key=?", (key,))
            tx.execute("INSERT INTO osv_cache VALUES (?,?,?)", (key, time.time(), json.dumps(value)))


def _post(path: str, body: dict[str, Any]) -> dict[str, Any]:
    r = requests.post(f"{API}{path}", json=body, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return r.json()


def _get(path: str) -> dict[str, Any]:
    r = requests.get(f"{API}{path}", timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return r.json()


def pinned_components(inventory: list[dict[str, str]]) -> list[tuple[str, str]]:
    seen: dict[tuple[str, str], None] = {}
    for c in inventory:
        if c.get("ecosystem") == "pypi" and PINNED.match(c.get("version") or ""):
            seen[(normalize(c["name"]), c["version"])] = None
    return list(seen)[:MAX_COMPONENTS]


def live_lookup(inventory: list[dict[str, str]], cache: Cache | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Advisories OSV lists for the exact versions in the inventory: ([match, ...], info for the trace).

    Never raises: any network or format problem returns what was gathered and an ``error`` note.
    """
    comps = pinned_components(inventory)
    info: dict[str, Any] = {"queried": len(comps), "advisories": 0, "cached": 0, "error": ""}
    if not comps or not live_enabled():
        return [], info
    matches: list[dict[str, Any]] = []
    try:
        cache = cache or Cache()
        ids_by_comp: dict[tuple[str, str], list[str]] = {}
        todo = []
        for comp in comps:
            hit = cache.get(f"q:{comp[0]}@{comp[1]}")
            if hit is None:
                todo.append(comp)
            else:
                ids_by_comp[comp] = hit
                info["cached"] += 1
        if todo:
            data = _post("/querybatch", {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in todo]})
            for comp, res in zip(todo, data.get("results", [])):
                ids = [v["id"] for v in res.get("vulns", [])]
                ids_by_comp[comp] = ids
                cache.put(f"q:{comp[0]}@{comp[1]}", ids)
        wanted = list(dict.fromkeys(i for ids in ids_by_comp.values() for i in ids))[:MAX_ADVISORIES]

        def detail(vid: str) -> dict[str, Any] | None:
            hit = cache.get(f"v:{vid}")
            if hit is not None:
                return hit
            try:
                body = _get(f"/vulns/{vid}")
            except requests.RequestException:
                return None
            cache.put(f"v:{vid}", body)
            return body

        with ThreadPoolExecutor(max_workers=6) as pool:
            details = dict(zip(wanted, pool.map(detail, wanted)))
        for (name, version), ids in ids_by_comp.items():
            for vid in ids:
                for rec in advisory_to_records(details.get(vid) or {"id": vid, "affected": []}, name):
                    matches.append({**rec, "installed": version})
        info["advisories"] = len({m["osv_id"] for m in matches})
    except Exception as exc:  # noqa: BLE001 - OSV being down must never fail an assessment
        info["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
    return matches, info
