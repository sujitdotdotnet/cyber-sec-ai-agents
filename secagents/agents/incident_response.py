"""Incident Response Agent: turns detections and intel into prioritized incidents and a playbook.

The playbook follows NIST SP 800-61 phases. Baseline steps are generated from the evidence
(the actual attacker IPs, accounts and hosts), so they are always concrete; the LLM adds an
executive briefing and any extra steps the situation calls for.
"""

from __future__ import annotations

import json
from typing import Any

from ..llm import get_router
from .base import trace_event
from .threat_intel import version_key

AGENT = "incident_response"
PHASES = ["Detection & Analysis", "Containment", "Eradication", "Recovery", "Post-Incident"]


def _step(incident: str, phase: str, action: str, command: str = "", owner: str = "SecOps", priority: str = "P2") -> dict[str, Any]:
    return {"incident": incident, "phase": phase, "action": action, "command": command, "owner": owner, "priority": priority}


def build_incidents(logs: dict[str, Any], intel: dict[str, Any], vulns: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    events = logs.get("events", [])
    by_type = lambda word: [e for e in events if word.lower() in e["type"].lower()]  # noqa: E731
    incidents: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []

    # INC: host compromise via SSH.
    compromise = by_type("Successful login after brute force")
    backdoors = by_type("Backdoor account")
    outbound = by_type("suspicious port")
    if compromise or backdoors or outbound:
        iid = f"INC-{len(incidents) + 1:02d}"
        users = sorted({e["target"] for e in compromise})
        attackers = sorted({e["src_ip"] for e in compromise if e.get("src_ip")})
        bd_users = sorted({e["target"] for e in backdoors})
        c2 = sorted({e["target"] for e in outbound})
        incidents.append({
            "id": iid, "priority": "P1", "severity": "CRITICAL", "title": "Host compromise on web-01 via SSH brute force",
            "summary": f"Attacker {', '.join(attackers) or 'unknown'} gained access as {', '.join(users) or 'unknown'}, "
                       f"escalated to root, created {', '.join(bd_users) or 'no'} backdoor account(s) and connected out to {', '.join(c2) or 'n/a'}.",
            "events": [e["id"] for e in compromise + backdoors + outbound + by_type("sudo") + by_type("Privilege")],
        })
        steps += [
            _step(iid, "Detection & Analysis", "Confirm scope: list active sessions and recent logins for the compromised account(s)", "who; last -F | head -50", priority="P1"),
            _step(iid, "Detection & Analysis", "Preserve evidence before changing anything: snapshot the disk and copy logs off-host", "tar czf /tmp/evidence-$(hostname).tgz /var/log /etc/passwd /etc/shadow /root/.bash_history", priority="P1"),
            _step(iid, "Containment", "Isolate web-01 from the network (keep console access)", "sudo ufw default deny incoming && sudo ufw default deny outgoing", "Infra", "P1"),
        ]
        for ip in attackers:
            steps.append(_step(iid, "Containment", f"Block attacker {ip} at the edge firewall", f"sudo ufw insert 1 deny from {ip}", "Infra", "P1"))
        for dst in c2:
            host = dst.split(":")[0]
            steps.append(_step(iid, "Containment", f"Block command-and-control destination {dst}", f"sudo ufw insert 1 deny out to {host}", "Infra", "P1"))
        for u in users:
            steps.append(_step(iid, "Containment", f"Lock compromised account '{u}' and kill its sessions", f"sudo usermod -L {u} && sudo pkill -KILL -u {u}", priority="P1"))
        for u in bd_users:
            steps.append(_step(iid, "Eradication", f"Remove backdoor account '{u}' (UID 0)", f"sudo userdel -r {u}", priority="P1"))
        steps += [
            _step(iid, "Eradication", "Hunt for persistence: cron jobs, systemd units, SSH keys, SUID binaries", "sudo crontab -l; ls -la /etc/cron.* ~/.ssh /root/.ssh; systemctl list-unit-files --state=enabled; find / -perm -4000 -newer /etc/hostname 2>/dev/null", priority="P1"),
            _step(iid, "Eradication", "Rotate every credential on the host (SSH keys, app secrets, DB and cloud keys)", owner="SecOps + App team", priority="P1"),
            _step(iid, "Recovery", "Rebuild web-01 from a known-good image rather than cleaning it in place", owner="Infra", priority="P2"),
            _step(iid, "Recovery", "Harden SSH: disable passwords and root login, enable MFA and fail2ban", "PasswordAuthentication no / PermitRootLogin no in sshd_config; apt install fail2ban", "Infra", "P2"),
        ]

    # INC: web application exploitation.
    corr = intel.get("correlations", [])
    if corr:
        iid = f"INC-{len(incidents) + 1:02d}"
        exploited = [c for c in corr if c["severity"] == "CRITICAL"]
        incidents.append({
            "id": iid, "priority": "P1" if exploited else "P2", "severity": "CRITICAL" if exploited else "HIGH",
            "title": "Web application exploitation (" + ", ".join(sorted({c["attack"] for c in corr})) + ")",
            "summary": f"{len(corr)} attack type(s) hit code paths with matching weaknesses; {len(exploited)} returned success responses.",
            "events": [c["event"] for c in corr],
        })
        steps.append(_step(iid, "Detection & Analysis", "Review application and DB logs for data accessed by the injection requests", "grep -E \"UNION|/etc/passwd|;cat\" /var/log/nginx/access.log", priority="P1"))
        steps.append(_step(iid, "Containment", "Enable WAF rules for SQLi, path traversal and command injection; rate-limit the scanner IP", owner="Infra", priority="P1"))
        for c in corr:
            steps.append(_step(iid, "Eradication", f"Fix {c['attack']} ({c['cwe']}) at {c['location']}", owner="App team", priority="P1"))
        steps.append(_step(iid, "Recovery", "Assume the database was read: rotate DB credentials and force user password resets", owner="App team", priority="P2"))

    # INC: vulnerable components.
    cves = intel.get("cve_matches", [])
    if cves:
        iid = f"INC-{len(incidents) + 1:02d}"
        crit = [c for c in cves if c["cvss"] >= 9]
        incidents.append({
            "id": iid, "priority": "P2" if crit else "P3", "severity": "HIGH",
            "title": f"{len(cves)} known CVEs in deployed components",
            "summary": "Top: " + ", ".join(f"{c['cve']} ({c['package']} {c['installed']})" for c in cves[:3]),
            "events": [],
        })
        upgrades: dict[str, str] = {}
        for c in cves:
            if c["ecosystem"] == "pypi":
                upgrades[c["package"]] = max(upgrades.get(c["package"], "0"), c["fixed"], key=version_key)
        if upgrades:
            steps.append(_step(iid, "Eradication", "Upgrade vulnerable Python packages to fixed versions",
                               "pip install --upgrade " + " ".join(f"'{p}>={v}'" for p, v in sorted(upgrades.items())), "App team", "P2"))
        for c in cves:
            if c["ecosystem"] == "os":
                steps.append(_step(iid, "Eradication", f"Patch {c['package']} for {c['cve']} (fixed in {c['fixed']})", f"sudo apt-get install --only-upgrade {c['package']}", "Infra", "P2"))
        base = vulns.get("container", {}).get("base_image")
        if base:
            steps.append(_step(iid, "Eradication", f"Replace end-of-life base image {base} with python:3.12-slim and run as non-root", owner="App team", priority="P2"))

    # INC: reconnaissance only.
    recon = by_type("scan")
    if recon and not incidents:
        iid = "INC-01"
        incidents.append({"id": iid, "priority": "P4", "severity": "MEDIUM", "title": "Reconnaissance activity", "summary": "Scanning detected; no exploitation.", "events": [e["id"] for e in recon]})
        for e in recon:
            if e.get("src_ip"):
                steps.append(_step(iid, "Containment", f"Rate-limit or block scanner {e['src_ip']}", f"sudo ufw deny from {e['src_ip']}", "Infra", "P3"))

    if incidents:
        steps += [
            _step("ALL", "Post-Incident", "Notify stakeholders; assess breach-notification obligations (GDPR 72h, contracts)", owner="Legal + CISO", priority="P2"),
            _step("ALL", "Post-Incident", "Hold a blameless post-mortem within 5 days and track fixes to closure", owner="CISO", priority="P3"),
            _step("ALL", "Post-Incident", "Add detections from this incident to the SIEM (brute-force-then-success, UID 0 user creation, outbound 4444)", owner="SecOps", priority="P3"),
        ]
    return incidents, steps


IR_SYSTEM = (
    "You are an incident commander following NIST SP 800-61. You receive incidents and a baseline playbook "
    "generated from evidence. Brief leadership and add only steps that are genuinely missing."
)


def run_incident_response(state: dict[str, Any]) -> dict[str, Any]:
    logs, intel, vulns = state.get("log_findings", {}) or {}, state.get("threat_intel", {}) or {}, state.get("vuln_findings", {}) or {}
    incidents, steps = build_incidents(logs, intel, vulns)
    router = get_router()

    briefing = None
    if incidents:
        resp = router.complete_json(
            IR_SYSTEM,
            "Incidents:\n" + json.dumps(incidents, indent=1)
            + "\n\nBaseline steps:\n" + "\n".join(f"- [{s['phase']}] {s['action']}" for s in steps)
            + "\n\nATT&CK mitigations:\n" + "\n".join(f"- {t['technique']} {t['name']}: {t['mitigation']}" for t in intel.get("techniques", []))
            + '\n\nReturn {"briefing": "markdown executive briefing, under 200 words, covering impact, what to do in the next hour, and decisions needed", '
            '"additional_steps": [{"incident": "INC-xx", "phase": one of ' + json.dumps(PHASES) + ', "action": "...", "command": "", "owner": "...", "priority": "P1|P2|P3"}]} '
            "with at most 5 additional steps.",
            agent=AGENT, max_tokens=6000,
        )
        if isinstance(resp, dict):
            briefing = resp.get("briefing")
            for s in resp.get("additional_steps", [])[:5]:
                if isinstance(s, dict) and s.get("action") and s.get("phase") in PHASES:
                    steps.append(_step(s.get("incident", "ALL"), s["phase"], s["action"], s.get("command", ""), s.get("owner", "SecOps"), s.get("priority", "P2")) | {"source": "llm"})
    if not briefing:
        briefing = _fallback_briefing(incidents)

    steps.sort(key=lambda s: (PHASES.index(s["phase"]), s["priority"]))
    for i, s in enumerate(steps, 1):
        s["step"] = i
    top = min((i["priority"] for i in incidents), default="none")
    out = {"incidents": incidents, "steps": steps, "briefing": briefing, "highest_priority": top}
    msg = f"{len(incidents)} incident(s), highest priority {top}; playbook with {len(steps)} steps"
    return {"incident_plan": out, "completed": [AGENT], "trace": [trace_event(AGENT, msg)]}


def _fallback_briefing(incidents: list[dict[str, Any]]) -> str:
    if not incidents:
        return "No incidents declared. Continue routine monitoring."
    lines = [f"**{len(incidents)} incident(s) declared.** Highest priority: {min(i['priority'] for i in incidents)}.", ""]
    lines += [f"- **{i['id']} [{i['priority']}] {i['title']}**: {i['summary']}" for i in incidents]
    lines += ["", "Next hour: isolate affected hosts, block attacker infrastructure, lock compromised accounts, preserve evidence."]
    return "\n".join(lines)
