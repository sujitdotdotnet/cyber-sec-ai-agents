"""Daily knowledge sync: refresh the local files from authoritative sources.

    python -m secagents.knowledge_sync                  # all sources
    python -m secagents.knowledge_sync --only kev,osv   # some of them
    python -m secagents.knowledge_sync --dry-run        # fetch and check, write nothing

Sources (all public, no key needed):

* **CISA KEV**: the Known Exploited Vulnerabilities catalog      -> ``knowledge/kev.jsonl``
* **OSV.dev**: advisories for the PyPI packages in ``watchlist.txt`` -> ``knowledge/cves_synced.jsonl``
* **MITRE ATT&CK**: the Enterprise matrix (STIX)                  -> ``knowledge/attack_synced.jsonl``

The hand-written ``cves.jsonl`` / ``attack.jsonl`` are never touched and win over synced records with the same id, so
the demo scenario stays stable. A source that fails, or that returns implausibly little data, leaves its file as it was
(and the run exits with status 2), so a broken feed cannot wipe the knowledge base. Files are only rewritten when their
content changed, which lets a scheduled job commit nothing on a quiet day.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import requests

from . import osv
from .config import settings

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OSV_PAGE_LIMIT = 10  # result pages per package (each is large); the newest advisories come first
MIN_KEV, MIN_ATTACK, MIN_OSV = 500, 150, 100  # a feed returning less than this is treated as broken
HEADERS = {"User-Agent": osv.USER_AGENT}


class SyncError(Exception):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get(url: str, timeout: int = 120) -> requests.Response:
    last: Exception | None = None
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=timeout, headers=HEADERS)
            r.raise_for_status()
            return r
        except requests.RequestException as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    raise SyncError(f"could not download {url}: {last}")


# ---- CISA KEV ---------------------------------------------------------------------------------------------------
def parse_kev(doc: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = doc.get("vulnerabilities")
    if not isinstance(rows, list):
        raise SyncError("KEV feed has no 'vulnerabilities' list")
    records = [{
        "id": v["cveID"], "vendor": v.get("vendorProject", ""), "product": v.get("product", ""), "name": v.get("vulnerabilityName", ""),
        "date_added": v.get("dateAdded", ""), "due_date": v.get("dueDate", ""), "ransomware": v.get("knownRansomwareCampaignUse", ""),
        "action": v.get("requiredAction", ""),
    } for v in rows if str(v.get("cveID", "")).startswith("CVE-")]
    if len(records) < MIN_KEV:
        raise SyncError(f"KEV feed returned only {len(records)} entries (expected at least {MIN_KEV})")
    records.sort(key=lambda r: r["id"])
    return records, {"count": len(records), "source_date": str(doc.get("dateReleased", ""))[:10] or str(doc.get("catalogVersion", "")), "url": KEV_URL}


def fetch_kev() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return parse_kev(_get(KEV_URL).json())


# ---- MITRE ATT&CK -----------------------------------------------------------------------------------------------
def _clean(text: str, limit: int) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\(https?://[^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


def _ext_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def parse_attack(bundle: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    objs = bundle.get("objects")
    if not isinstance(objs, list):
        raise SyncError("ATT&CK bundle has no 'objects' list")
    live = [o for o in objs if isinstance(o, dict) and "id" in o and not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in live}
    mitigations: dict[str, list[str]] = {}
    detections: dict[str, list[str]] = {}
    parents: dict[str, str] = {}
    for o in live:
        if o.get("type") != "relationship":
            continue
        src, dst = by_id.get(o.get("source_ref", "")), by_id.get(o.get("target_ref", ""))
        if not src or not dst:
            continue
        if o["relationship_type"] == "mitigates" and src["type"] == "course-of-action":
            mitigations.setdefault(dst["id"], []).append(f"{src['name']} ({_ext_id(src)})")
        elif o["relationship_type"] == "detects" and src["type"] == "x-mitre-detection-strategy":
            # ATT&CK v18+ keeps detection advice in strategies made of analytics, not on the technique itself
            analytics = [_clean(by_id[a].get("description", ""), 260) for a in src.get("x_mitre_analytic_refs", []) if a in by_id][:2]
            detections.setdefault(dst["id"], []).append(f"{src['name']}: " + " ".join(a for a in analytics if a))
        elif o["relationship_type"] == "subtechnique-of":
            parents[src["id"]] = dst["id"]
    records = []
    for o in live:
        if o.get("type") != "attack-pattern" or not _ext_id(o):
            continue
        name = o["name"]
        if o["id"] in parents and parents[o["id"]] in by_id:
            name = f"{by_id[parents[o['id']]]['name']}: {name}"
        tactics = [p["phase_name"].replace("-", " ").title() for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        records.append({
            "id": _ext_id(o), "name": name, "tactic": ", ".join(tactics) or "Unknown", "description": _clean(o.get("description", ""), 1200),
            "detection": _clean(o.get("x_mitre_detection", "") or " ".join(detections.get(o["id"], [])[:2]), 700), "mitigation": "; ".join(sorted(set(mitigations.get(o["id"], [])))[:6]),
        })
    if len(records) < MIN_ATTACK:
        raise SyncError(f"ATT&CK bundle returned only {len(records)} techniques (expected at least {MIN_ATTACK})")
    records.sort(key=lambda r: r["id"])
    collection = next((o for o in objs if o.get("type") == "x-mitre-collection"), {})
    return records, {"count": len(records), "version": collection.get("x_mitre_version", ""),
                     "source_date": str(collection.get("modified", ""))[:10], "url": ATTACK_URL}


def fetch_attack() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return parse_attack(_get(ATTACK_URL, timeout=300).json())


# ---- OSV --------------------------------------------------------------------------------------------------------
def read_watchlist(path: Path) -> list[str]:
    names: dict[str, None] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                names[osv.normalize(line)] = None
    except OSError:
        pass
    return list(names)


def _query_package(name: str) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    body: dict[str, Any] = {"package": {"name": name, "ecosystem": "PyPI"}}
    for _ in range(OSV_PAGE_LIMIT):
        last: Exception | None = None
        for attempt in range(3):
            try:
                page = osv._post("/query", body)
                break
            except requests.RequestException as exc:
                last = exc
                time.sleep(2 * (attempt + 1))
        else:
            raise SyncError(f"OSV query for {name} failed: {last}")
        vulns += page.get("vulns", [])
        if not page.get("next_page_token"):
            break
        body = {**body, "page_token": page["next_page_token"]}
    return vulns


def build_osv_records(per_package: dict[str, list[dict[str, Any]]], kev: set[str]) -> list[dict[str, Any]]:
    """One record per (advisory, package); ids are the CVE where there is one, made unique if two packages share it."""
    records: dict[str, dict[str, Any]] = {}
    for name, vulns in per_package.items():
        for vuln in vulns:
            for rec in osv.advisory_to_records(vuln, name):
                rec["kev"] = any(a in kev for a in rec["aliases"])
                key = rec["id"]
                if key in records and records[key]["package"] != rec["package"]:
                    key = rec["id"] = f"{rec['id']}:{rec['package']}"
                records.setdefault(key, rec)
    return sorted(records.values(), key=lambda r: r["id"])


def fetch_osv(kev: set[str], watchlist: list[str], progress: Callable[[str], None] = lambda _: None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not watchlist:
        raise SyncError("watchlist.txt is empty or missing")
    per_package: dict[str, list[dict[str, Any]]] = {}
    for i, name in enumerate(watchlist, 1):
        per_package[name] = _query_package(name)
        progress(f"OSV {i}/{len(watchlist)} {name}: {len(per_package[name])}")
    records = build_osv_records(per_package, kev)
    if len(records) < MIN_OSV:
        raise SyncError(f"OSV returned only {len(records)} advisories for {len(watchlist)} packages (expected at least {MIN_OSV})")
    newest = max((r["modified"] for r in records if r["modified"]), default="")
    return records, {"count": len(records), "packages": len(watchlist), "source_date": newest[:10], "url": "https://osv.dev"}


# ---- writing ----------------------------------------------------------------------------------------------------
def to_jsonl(records: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=False) + "\n" for r in records)


def write_if_changed(path: Path, text: str) -> bool:
    """Atomically replace ``path`` when its content differs. Returns True if it was rewritten."""
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return True


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


SOURCES = {
    "kev": ("cisa_kev", "kev.jsonl"),
    "osv": ("osv", "cves_synced.jsonl"),
    "attack": ("mitre_attack", "attack_synced.jsonl"),
}


def run(only: list[str] | None = None, dry_run: bool = False, directory: Path | None = None, log: Callable[[str], None] = print) -> dict[str, str]:
    """Refresh the chosen sources. Returns {source: "changed" | "unchanged" | "failed: reason"}."""
    kdir = directory or settings.knowledge_dir
    wanted = only or list(SOURCES)
    meta_file = kdir / "meta.json"
    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {}
    meta.setdefault("sources", {})
    results: dict[str, str] = {}
    kev_ids: set[str] = set()
    kev_file = kdir / "kev.jsonl"
    if kev_file.exists():
        kev_ids = {json.loads(line)["id"] for line in kev_file.read_text(encoding="utf-8").splitlines() if line.strip()}
    any_change = False
    for key in [k for k in ("kev", "osv", "attack") if k in wanted]:
        name, filename = SOURCES[key]
        try:
            if key == "kev":
                records, info = fetch_kev()
                kev_ids = {r["id"] for r in records}
            elif key == "osv":
                records, info = fetch_osv(kev_ids, read_watchlist(kdir / "watchlist.txt"), log)
            else:
                records, info = fetch_attack()
            text = to_jsonl(records)
            changed = (not (kdir / filename).exists()) or (kdir / filename).read_text(encoding="utf-8") != text
            if not dry_run:
                write_if_changed(kdir / filename, text)
                entry = {**meta["sources"].get(name, {}), **info, "hash": digest(text)}
                if changed or "updated" not in entry:
                    entry["updated"] = now_iso()
                meta["sources"][name] = entry
            any_change |= changed
            results[key] = "changed" if changed else "unchanged"
            log(f"{key}: {len(records)} records, {results[key]}")
        except (SyncError, requests.RequestException, KeyError, ValueError) as exc:
            results[key] = f"failed: {exc}"
            log(f"{key}: FAILED ({exc}); the existing file is kept")
    if not dry_run and any_change:
        meta["updated_at"] = now_iso()
    if not dry_run and (any_change or not meta_file.exists()):
        meta_file.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return results


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--only", help="comma-separated: kev, osv, attack (default: all)")
    p.add_argument("--dry-run", action="store_true", help="fetch and check, write nothing")
    args = p.parse_args(argv)
    only = [s.strip() for s in args.only.split(",")] if args.only else None
    unknown = set(only or []) - set(SOURCES)
    if unknown:
        p.error(f"unknown source(s): {', '.join(sorted(unknown))}")
    results = run(only, args.dry_run)
    return 2 if any(v.startswith("failed") for v in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
