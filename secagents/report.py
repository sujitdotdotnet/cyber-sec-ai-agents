"""Assemble the agents' outputs into one markdown incident and posture report."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _table(rows: list[list[Any]], header: list[str]) -> str:
    if not rows:
        return "_None._\n"
    esc = lambda v: str(v).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def build_report(state: dict[str, Any]) -> str:
    logs = state.get("log_findings", {}) or {}
    vulns = state.get("vuln_findings", {}) or {}
    intel = state.get("threat_intel", {}) or {}
    ir = state.get("incident_plan", {}) or {}
    comp = state.get("compliance", {}) or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    parts = [
        "# Security Assessment Report",
        f"_Generated {now} by SecAgents (Log Monitor, Threat Intel, Vulnerability Scanner, Incident Response, Policy Checker)._",
        "",
        "## Executive summary",
        f"- **Overall risk:** {intel.get('overall_risk', 'n/a')}",
        f"- **Incidents:** {len(ir.get('incidents', []))} (highest priority {ir.get('highest_priority', 'n/a')})",
        f"- **Log detections:** {len(logs.get('events', []))} | **Code/config findings:** {len(vulns.get('findings', []))} | "
        f"**CVEs affecting inventory:** {len(intel.get('cve_matches', []))}",
        "- **Compliance:** " + ", ".join(f"{f['framework']} {f['score']}%" for f in comp.get("frameworks", [])),
        "",
        ir.get("briefing", ""),
        "",
        "## 1. Log Monitor: what happened",
        logs.get("narrative", ""),
        "",
        _table([[e["id"], e["severity"], e["type"], e.get("src_ip", ""), e.get("count", ""), ", ".join(e.get("mitre", []))] for e in logs.get("events", [])],
               ["ID", "Severity", "Detection", "Source", "Count", "ATT&CK"]),
        "## 2. Threat Intelligence: are we affected?",
        intel.get("summary", ""),
        "",
        "### CVEs affecting deployed components",
        _table([[m["cve"], m["package"], m["installed"], m["fixed"], m["cvss"], m.get("note", "")] for m in intel.get("cve_matches", [])],
               ["CVE", "Component", "Installed", "Fixed in", "CVSS", "Note"]),
        "### Attacks that hit real weaknesses",
        _table([[c["attack"], c["src_ip"], c["location"], c["verdict"]] for c in intel.get("correlations", [])], ["Attack", "Source", "Code location", "Verdict"]),
        "### Exploit attempts",
        _table([[a["attack"], a["cve"], a["verdict"]] for a in intel.get("exploit_attempts", [])], ["Attack", "CVE", "Verdict"]),
        "### Known-bad indicators",
        _table([[i["indicator"], i["reputation"], ", ".join(i["tags"])] for i in intel.get("ioc_hits", [])], ["Indicator", "Reputation", "Tags"]),
        "## 3. Vulnerability Scanner",
        _table([[f["id"], f["severity"], f["title"], f"{f.get('file', '')}:{f.get('line', '')}", f.get("cwe", "")] for f in vulns.get("findings", [])],
               ["ID", "Severity", "Finding", "Location", "CWE"]),
        "### Suggested fixes",
        vulns.get("remediation", ""),
        "",
        "## 4. Incident Response playbook",
        _table([[i["id"], i["priority"], i["title"], i["summary"]] for i in ir.get("incidents", [])], ["Incident", "Priority", "Title", "Summary"]),
        _table([[s["step"], s["phase"], s["priority"], s["action"], f"`{s['command']}`" if s.get("command") else "", s["owner"]] for s in ir.get("steps", [])],
               ["#", "Phase", "Priority", "Action", "Command", "Owner"]),
        "## 5. Policy Checker: compliance gaps",
        _table([[f["framework"], f"{f['score']}%", f["pass"], f["partial"], f["fail"]] for f in comp.get("frameworks", [])], ["Framework", "Score", "Pass", "Partial", "Fail"]),
        comp.get("roadmap", ""),
        "",
        "### Control detail",
        _table([[c["framework"], c["id"], c["title"], c["status"], c["evidence"]] for c in comp.get("controls", []) if c["status"] != "PASS"],
               ["Framework", "Control", "Title", "Status", "Evidence"]),
    ]
    return "\n".join(parts)
