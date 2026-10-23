"""The supervisor's correlation step: one view that ties the specialists' findings together.

Each specialist sees one slice (logs, code, CVEs, policy). Here the supervisor links them per incident: which log
events make it up, which code weaknesses those attacks hit, which CVEs apply, which ATT&CK techniques and known-bad
addresses are involved, and which control gaps the attack exposes. Purely deterministic: it only joins what the agents
already established, so it can be checked line by line.
"""

from __future__ import annotations

from typing import Any

# Which policy checks (see agents/policy_checker.py) a kind of attack shows to be missing.
ATTACK_CHECKS: dict[str, tuple[str, ...]] = {
    "brute force": ("account_lockout", "mfa_enabled", "ssh_hardening", "password_policy"),
    "password spraying": ("account_lockout", "mfa_enabled", "password_policy"),
    "backdoor": ("ssh_hardening", "ids_enabled"),
    "privilege": ("ssh_hardening",),
    "sql injection": ("secure_code",),
    "path traversal": ("secure_code",),
    "command injection": ("secure_code",),
    "cross-site": ("secure_code",),
    "log4shell": ("no_critical_vulns", "patch_sla"),
    "outbound": ("firewall_default_deny", "ids_enabled"),
    "port scan": ("firewall_default_deny", "ids_enabled"),
    "payload download": ("ids_enabled", "firewall_default_deny"),
}


def _checks_for(events: list[dict[str, Any]]) -> list[str]:
    wanted: dict[str, None] = {}
    for e in events:
        text = e.get("type", "").lower()
        for key, checks in ATTACK_CHECKS.items():
            if key in text:
                wanted.update({c: None for c in checks})
    return list(wanted)


def correlate(state: dict[str, Any]) -> dict[str, Any]:
    logs, vulns = state.get("log_findings", {}) or {}, state.get("vuln_findings", {}) or {}
    intel, plan, comp = state.get("threat_intel", {}) or {}, state.get("incident_plan", {}) or {}, state.get("compliance", {}) or {}
    events = {e["id"]: e for e in logs.get("events", [])}
    gaps = {g["check"]: g for g in comp.get("gaps", [])}
    links, covered = [], set()
    for inc in plan.get("incidents", []):
        ids = [i for i in inc.get("events", []) if i in events]
        covered.update(ids)
        evs = [events[i] for i in ids]
        ips = sorted({e["src_ip"] for e in evs if e.get("src_ip")})
        weaknesses = [c for c in intel.get("correlations", []) if c["event"] in ids]
        attempts = [a for a in intel.get("exploit_attempts", []) if a["event"] in ids]
        present = {a["component"].lower() for a in attempts if a.get("component_present")}
        cves = sorted({m["cve"] for m in intel.get("cve_matches", []) if m["package"].lower() in present} | {a["cve"] for a in attempts if a.get("component_present")})
        links.append({
            "incident": inc["id"], "title": inc["title"], "priority": inc.get("priority", ""),
            "events": ids, "attackers": ips,
            "weaknesses": sorted({c["finding"] for c in weaknesses}),
            "confirmed_exploited": sorted({c["finding"] for c in weaknesses if "Likely exploited" in c.get("verdict", "")}),
            "exploit_attempts": [{"event": a["event"], "cve": a["cve"], "component_present": a["component_present"]} for a in attempts],
            "cves": cves,
            "techniques": sorted({m for e in evs for m in e.get("mitre", [])}),
            "known_bad": sorted({h["indicator"] for h in intel.get("ioc_hits", []) if h["indicator"] in ips}),
            "control_gaps": [gaps[c]["title"] for c in _checks_for(evs) if c in gaps],
        })
    unlinked = [{"id": e["id"], "type": e["type"], "severity": e["severity"]} for e in events.values()
                if e["id"] not in covered and e.get("severity") in ("CRITICAL", "HIGH")]
    parts = []
    for ln in links:
        bits = [f"{len(ln['events'])} log events"]
        if ln["weaknesses"]:
            bits.append(f"{len(ln['weaknesses'])} code weaknesses hit ({len(ln['confirmed_exploited'])} likely exploited)")
        if ln["cves"]:
            bits.append(f"CVEs {', '.join(ln['cves'][:3])}")
        if ln["control_gaps"]:
            bits.append(f"{len(ln['control_gaps'])} control gaps exposed")
        parts.append(f"{ln['incident']}: " + ", ".join(bits))
    if unlinked:
        parts.append(f"{len(unlinked)} high-severity events are not part of any incident")
    return {"links": links, "unlinked_events": unlinked, "summary": "; ".join(parts) or "No incidents to correlate.",
            "sources": {"log_events": len(events), "code_findings": len(vulns.get("findings", [])), "cve_matches": len(intel.get("cve_matches", []))}}
