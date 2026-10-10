"""Threat Intelligence Agent: matches the inventory to CVEs, checks IOCs, and correlates attacks with weaknesses.

It answers "are we affected?" three ways:
1. Version matching of every inventoried component against the CVE knowledge base.
2. Agentic RAG over CVE / ATT&CK data for exploit attempts seen in the logs (e.g. a JNDI string
   maps to Log4Shell), then checking whether the vulnerable component is actually present.
3. Correlating attack types in the logs with matching code weaknesses from the scanner, which
   turns "someone tried SQL injection" into "SQL injection is exploitable here".
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..config import settings
from ..llm import get_router
from ..rag import agentic_retrieve, get_kb
from .base import sev_rank, severity_counts, sort_by_severity, trace_event

AGENT = "threat_intel"

ATTACK_TO_CWE = {
    "SQL injection": "CWE-89",
    "Path traversal": "CWE-22",
    "Command injection": "CWE-78",
    "Cross-site scripting": "CWE-79",
}
EXPLOIT_QUERIES = {
    "Log4Shell (JNDI injection)": "JNDI LDAP lookup injection remote code execution log4j",
}


# ---- version matching -------------------------------------------------------------
def version_key(v: str) -> tuple:
    parts = re.findall(r"\d+|[a-z]+", v.lower())
    return tuple((1, int(p)) if p.isdigit() else (0, p) for p in parts)


def satisfies(version: str, spec: str) -> bool | None:
    """True/False if `version` is inside `spec` (e.g. '>=2.0,<2.15.0'); None if spec is not machine-readable."""
    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    if not clauses or not all(re.match(r"^(<=|>=|<|>|==)\s*[\w.]+$", c) for c in clauses):
        return None
    v = version_key(version)
    for c in clauses:
        op, target = re.match(r"^(<=|>=|<|>|==)\s*([\w.]+)$", c).groups()
        t = version_key(target)
        ok = {"<": v < t, "<=": v <= t, ">": v > t, ">=": v >= t, "==": v == t}[op]
        if not ok:
            return False
    return True


def match_inventory(kb, inventory: list[dict[str, str]]) -> list[dict[str, Any]]:
    matches = []
    for comp in inventory:
        if comp.get("version") in (None, "", "unpinned"):
            continue
        for cve in kb.all("cves"):
            if cve["package"].lower() != comp["name"].lower():
                continue
            if satisfies(comp["version"], cve["affected"]):
                matches.append({
                    "cve": cve["id"], "title": cve["title"], "package": comp["name"], "installed": comp["version"],
                    "fixed": cve["fixed"], "cvss": cve["cvss"], "severity": cve["severity"], "source": comp.get("source", ""),
                    "affected": True, "ecosystem": comp["ecosystem"],
                    "note": "Version-based match; distro backports may already carry the fix." if comp["ecosystem"] == "os" else "",
                })
    return sorted(matches, key=lambda m: m["cvss"], reverse=True)


def load_feed() -> dict[str, Any]:
    try:
        return json.loads((settings.knowledge_dir / "threat_feed.json").read_text())
    except (OSError, json.JSONDecodeError):
        return {"ips": {}, "suspicious_ports": []}


INTEL_SYSTEM = (
    "You are a threat intelligence analyst. Using only the provided CVE matches, exploit attempts, "
    "IOC hits and correlations, assess the organization's real exposure. Be specific and do not invent CVEs."
)


def run_threat_intel(state: dict[str, Any]) -> dict[str, Any]:
    kb, router = get_kb(), get_router()
    logs = state.get("log_findings", {}) or {}
    vulns = state.get("vuln_findings", {}) or {}
    inventory = vulns.get("inventory", [])
    events = logs.get("events", [])
    trace = []

    cve_matches = match_inventory(kb, inventory)
    installed = {c["name"].lower() for c in inventory}

    # Exploit attempts in logs -> which CVE are they targeting, and do we run that component?
    exploit_attempts = []
    for e in events:
        attack = e["type"].removeprefix("Web attack: ")
        query = EXPLOIT_QUERIES.get(attack)
        if not query:
            continue
        rag = agentic_retrieve(kb, router, "cves", query + " " + " ".join(e.get("evidence", [])[:1]), k=3, agent=AGENT)
        trace.extend(rag["trace"])
        top = rag["hits"][0]["record"] if rag["hits"] else None
        if top:
            present = top["package"].lower() in installed
            exploit_attempts.append({
                "event": e["id"], "attack": attack, "src_ip": e.get("src_ip"), "cve": top["id"], "title": top["title"],
                "component": top["package"], "component_present": present,
                "verdict": "AFFECTED: vulnerable component present" if present else f"Attempt only: {top['package']} not found in inventory",
                "severity": "CRITICAL" if present else "MEDIUM",
            })

    # Correlate attack types with code weaknesses found by the scanner.
    code_by_cwe: dict[str, list[dict[str, Any]]] = {}
    for f in vulns.get("findings", []):
        if f.get("cwe"):
            code_by_cwe.setdefault(f["cwe"], []).append(f)
    correlations = []
    for e in events:
        attack = e["type"].removeprefix("Web attack: ")
        cwe = ATTACK_TO_CWE.get(attack)
        if cwe and cwe in code_by_cwe:
            f = code_by_cwe[cwe][0]
            confirmed = bool(e.get("possibly_successful"))
            correlations.append({
                "event": e["id"], "finding": f["id"], "attack": attack, "cwe": cwe, "src_ip": e.get("src_ip"),
                "location": f"{f.get('file')}:{f.get('line')}",
                "severity": "CRITICAL" if confirmed else "HIGH",
                "verdict": ("Likely exploited: attack returned HTTP 2xx and the code is vulnerable" if confirmed
                            else "Exploitable: matching weakness exists in code"),
            })

    # IOC lookups for every IP involved in a detection.
    feed = load_feed()
    ioc_hits = []
    seen_ips = set()
    for e in events:
        for ip in filter(None, [e.get("src_ip"), (e.get("target") or "").split(":")[0]]):
            if ip in feed.get("ips", {}) and ip not in seen_ips:
                seen_ips.add(ip)
                ioc_hits.append({"indicator": ip, **feed["ips"][ip], "seen_in": e["id"]})

    # ATT&CK context via agentic RAG for the most severe log detections.
    technique_ctx = []
    for e in [e for e in events if e["severity"] == "CRITICAL"][:3]:
        rag = agentic_retrieve(kb, router, "attack", f"{e['type']}: {e['description']}", k=2, agent=AGENT)
        trace.extend(rag["trace"])
        technique_ctx += [{"event": e["id"], "technique": h["id"], "name": h["record"]["name"], "mitigation": h["record"]["mitigation"]} for h in rag["hits"]]

    risk_items = cve_matches + exploit_attempts + correlations
    overall = max((sev_rank(i["severity"]) for i in risk_items), default=0)
    if any(e["severity"] == "CRITICAL" for e in events):
        overall = max(overall, 4)
    overall_label = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(overall, "LOW")

    summary = None
    if risk_items or ioc_hits:
        payload = json.dumps({
            "cve_matches": [{k: m[k] for k in ("cve", "package", "installed", "fixed", "cvss")} for m in cve_matches],
            "exploit_attempts": exploit_attempts, "correlations": correlations, "ioc_hits": ioc_hits,
        }, indent=1)
        result = router.complete(
            INTEL_SYSTEM,
            f"{payload}\n\nWrite a markdown threat assessment under 300 words: overall exposure, the top 3 risks in priority "
            "order with why each matters, and which issues are confirmed versus theoretical.",
            agent=AGENT, max_tokens=5000,
        )
        summary = result.text if result else None
    if not summary:
        summary = _fallback_summary(cve_matches, exploit_attempts, correlations, ioc_hits, overall_label)

    out = {
        "overall_risk": overall_label,
        "cve_matches": cve_matches,
        "exploit_attempts": exploit_attempts,
        "correlations": sort_by_severity(correlations),
        "ioc_hits": ioc_hits,
        "techniques": technique_ctx,
        "counts": severity_counts(cve_matches),
        "rag_trace": trace,
        "summary": summary,
    }
    msg = (f"{len(cve_matches)} CVEs affect the inventory, {len(correlations)} attack/weakness correlations, "
           f"{len(ioc_hits)} IOC hits; overall risk {overall_label}")
    return {"threat_intel": out, "completed": [AGENT], "trace": [trace_event(AGENT, msg)]}


def _fallback_summary(cves, attempts, corr, iocs, overall) -> str:
    lines = [f"**Overall exposure: {overall}**", ""]
    if corr:
        lines.append("Confirmed or exploitable attack paths:")
        lines += [f"- {c['attack']} from {c['src_ip']} -> {c['location']} ({c['verdict']})" for c in corr]
    if cves:
        lines.append("\nVulnerable components:")
        lines += [f"- {m['cve']} ({m['cvss']}) {m['package']} {m['installed']} -> upgrade to {m['fixed']}" for m in cves[:8]]
    if attempts:
        lines.append("\nExploit attempts:")
        lines += [f"- {a['attack']} targeting {a['cve']}: {a['verdict']}" for a in attempts]
    if iocs:
        lines.append("\nKnown-bad indicators seen: " + ", ".join(f"{i['indicator']} ({'/'.join(i['tags'])})" for i in iocs))
    return "\n".join(lines)
