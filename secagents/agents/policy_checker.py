"""Policy Checker Agent: evaluates the environment against NIST 800-53, NIST CSF 2.0, ISO 27001 and SOC 2.

Each control in the knowledge base lists the technical checks that evidence it. Checks read the
system configuration snapshot plus the other agents' findings, so a hardcoded secret found by
the scanner fails A.8.28 / SA-11, and an incident without a tested IR plan fails IR-4 / CC7.4.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml

from ..llm import get_router
from ..rag import agentic_retrieve, get_kb
from .base import trace_event

AGENT = "policy_checker"

Check = Callable[[dict[str, Any], dict[str, Any]], tuple[bool, str]]


def _g(cfg: dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _vulns(ctx: dict[str, Any], **match: Any) -> list[dict[str, Any]]:
    return [f for f in ctx.get("vuln_findings", {}).get("findings", []) if all(f.get(k) == v for k, v in match.items())]


CHECKS: dict[str, tuple[str, Check, str]] = {
    "mfa_enabled": ("MFA enforced", lambda c, x: (bool(_g(c, "authentication.mfa_enabled")), f"authentication.mfa_enabled={_g(c, 'authentication.mfa_enabled')}"), "Enforce MFA for all users, starting with admins and SSH."),
    "account_lockout": ("Account lockout after failed logins", lambda c, x: (0 < (_g(c, "authentication.max_failed_logins", 0) or 0) <= 5, f"max_failed_logins={_g(c, 'authentication.max_failed_logins')}"), "Lock accounts after 5 failed attempts (pam_faillock / fail2ban)."),
    "password_policy": ("Password length >= 12 with complexity", lambda c, x: ((_g(c, "authentication.password_min_length", 0) or 0) >= 12 and bool(_g(c, "authentication.password_complexity")), f"min_length={_g(c, 'authentication.password_min_length')}, complexity={_g(c, 'authentication.password_complexity')}"), "Require 12+ character passwords and block known-breached passwords."),
    "ssh_hardening": ("SSH: no root login, no password auth", lambda c, x: (str(_g(c, "ssh.permit_root_login")).lower() == "no" and str(_g(c, "ssh.password_authentication")).lower() == "no", f"PermitRootLogin={_g(c, 'ssh.permit_root_login')}, PasswordAuthentication={_g(c, 'ssh.password_authentication')}"), "Set PermitRootLogin no and PasswordAuthentication no; use keys + MFA."),
    "centralized_logging": ("Logs shipped to a central SIEM", lambda c, x: (bool(_g(c, "logging.centralized")), f"centralized={_g(c, 'logging.centralized')}, siem={_g(c, 'logging.siem')}"), "Forward auth, web and firewall logs to a SIEM with alerting."),
    "log_retention": ("Log retention >= 90 days", lambda c, x: ((_g(c, "logging.retention_days", 0) or 0) >= 90, f"retention_days={_g(c, 'logging.retention_days')}"), "Retain logs for at least 90 days online and 1 year archived."),
    "ids_enabled": ("Intrusion detection enabled", lambda c, x: (bool(_g(c, "monitoring.ids_enabled")), f"ids_enabled={_g(c, 'monitoring.ids_enabled')}"), "Deploy host and network IDS (e.g. Wazuh, Suricata)."),
    "tls_min_version": ("TLS 1.2+ only", lambda c, x: (str(_g(c, "network.tls_min_version", "0")) >= "1.2", f"tls_min_version={_g(c, 'network.tls_min_version')}"), "Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3)."),
    "encryption_at_rest": ("Encryption at rest", lambda c, x: (bool(_g(c, "storage.encryption_at_rest")), f"encryption_at_rest={_g(c, 'storage.encryption_at_rest')}"), "Enable disk/volume and database encryption with managed keys."),
    "firewall_default_deny": ("Firewall default deny", lambda c, x: (str(_g(c, "network.firewall_default_policy")).lower() == "deny", f"firewall_default_policy={_g(c, 'network.firewall_default_policy')}"), "Default-deny inbound and outbound; allow by exception."),
    "backups": ("Backups enabled and restore-tested within a year", lambda c, x: (bool(_g(c, "backups.enabled")) and (_g(c, "backups.last_restore_test_days_ago", 9999) or 9999) <= 365, f"enabled={_g(c, 'backups.enabled')}, last_restore_test_days_ago={_g(c, 'backups.last_restore_test_days_ago')}"), "Run and document a restore test at least annually."),
    "vuln_scan_cadence": ("Vulnerability scans at least monthly", lambda c, x: ((_g(c, "vulnerability_management.scan_frequency_days", 9999) or 9999) <= 30, f"scan_frequency_days={_g(c, 'vulnerability_management.scan_frequency_days')}"), "Scan at least monthly and on every release (this agent can run in CI)."),
    "patch_sla": ("Critical patches within 15 days", lambda c, x: ((_g(c, "vulnerability_management.critical_patch_sla_days", 9999) or 9999) <= 15, f"critical_patch_sla_days={_g(c, 'vulnerability_management.critical_patch_sla_days')}"), "Set a 15-day SLA for critical and 30-day for high vulnerabilities."),
    "incident_response_plan": ("IR plan documented and tested within a year", lambda c, x: (bool(_g(c, "incident_response.plan_documented")) and (_g(c, "incident_response.last_tested_days_ago", 9999) or 9999) <= 365, f"plan_documented={_g(c, 'incident_response.plan_documented')}, last_tested_days_ago={_g(c, 'incident_response.last_tested_days_ago')}"), "Run a tabletop exercise using this incident as the scenario."),
    "code_review_required": ("Code review required before merge", lambda c, x: (bool(_g(c, "development.code_review_required")), f"code_review_required={_g(c, 'development.code_review_required')}"), "Require pull-request review and status checks on the main branch."),
    "debug_disabled": ("Debug mode off in production", lambda c, x: (not _g(c, "development.debug_mode_in_production", False) and not _vulns(x, rule="B201"), f"debug_mode_in_production={_g(c, 'development.debug_mode_in_production')}, debug findings={len(_vulns(x, rule='B201'))}"), "Disable debug mode; configure it per environment."),
    "container_non_root": ("Containers run as non-root", lambda c, x: (not _g(c, "containers.run_as_root", False) and not _vulns(x, rule="DS002"), f"run_as_root={_g(c, 'containers.run_as_root')}, Dockerfile without USER={bool(_vulns(x, rule='DS002'))}"), "Add a USER instruction and run with a read-only root filesystem."),
    "no_hardcoded_secrets": ("No secrets in code or images", lambda c, x: (not _vulns(x, category="secret") and not _vulns(x, rule="SECRET-ENV"), f"{len(_vulns(x, category='secret')) + len(_vulns(x, rule='SECRET-ENV'))} secret finding(s)"), "Move secrets to a secrets manager, rotate exposed ones, add secret scanning to CI."),
    "secure_code": ("No high-severity code weaknesses", lambda c, x: (not [f for f in _vulns(x, category="code") if f["severity"] in ("HIGH", "CRITICAL")], f"{len([f for f in _vulns(x, category='code') if f['severity'] in ('HIGH', 'CRITICAL')])} high-severity code finding(s)"), "Fix injection, unsafe deserialization and weak crypto findings; add SAST to CI."),
    "no_critical_vulns": ("No known critical/high CVEs deployed", lambda c, x: (not [m for m in x.get("threat_intel", {}).get("cve_matches", []) if m["cvss"] >= 7], f"{len([m for m in x.get('threat_intel', {}).get('cve_matches', []) if m['cvss'] >= 7])} CVE(s) with CVSS >= 7"), "Upgrade affected components to fixed versions."),
}


def evaluate(config: dict[str, Any], ctx: dict[str, Any]) -> dict[str, dict[str, Any]]:
    results = {}
    for key, (title, fn, fix) in CHECKS.items():
        try:
            passed, evidence = fn(config, ctx)
        except Exception as exc:  # noqa: BLE001 - a malformed config value fails the check, with the reason
            passed, evidence = False, f"could not evaluate: {exc}"
        results[key] = {"check": key, "title": title, "passed": bool(passed), "evidence": evidence, "fix": fix}
    return results


POLICY_SYSTEM = "You are a GRC (governance, risk and compliance) lead. Turn control gaps into a prioritized, practical remediation roadmap."


def run_policy_checker(state: dict[str, Any]) -> dict[str, Any]:
    cfg_path = state.get("inputs", {}).get("config_path")
    config: dict[str, Any] = {}
    if cfg_path and Path(cfg_path).exists():
        config = yaml.safe_load(Path(cfg_path).read_text()) or {}
    kb, router = get_kb(), get_router()
    checks = evaluate(config, state)

    controls = []
    for ctl in kb.all("controls"):
        results = [checks[c] for c in ctl["checks"] if c in checks]
        failed = [r for r in results if not r["passed"]]
        controls.append({
            "framework": ctl["framework"], "id": ctl["id"], "title": ctl["title"],
            "status": "PASS" if not failed else ("PARTIAL" if len(failed) < len(results) else "FAIL"),
            "failed_checks": [r["check"] for r in failed],
            "evidence": "; ".join(r["evidence"] for r in failed) or "; ".join(r["evidence"] for r in results),
        })

    frameworks: dict[str, dict[str, Any]] = {}
    for c in controls:
        f = frameworks.setdefault(c["framework"], {"framework": c["framework"], "total": 0, "pass": 0, "partial": 0, "fail": 0})
        f["total"] += 1
        f[c["status"].lower()] += 1
    for f in frameworks.values():
        f["score"] = round(100 * (f["pass"] + 0.5 * f["partial"]) / f["total"])

    failed_checks = [c for c in checks.values() if not c["passed"]]
    impact = {k: sum(1 for c in controls if k in c["failed_checks"]) for k in checks}
    gaps = sorted(
        [{**c, "controls_affected": impact[c["check"]],
          "controls": [f"{x['framework']} {x['id']}" for x in controls if c["check"] in x["failed_checks"]]} for c in failed_checks],
        key=lambda g: g["controls_affected"], reverse=True,
    )

    # Agentic RAG: ground the roadmap in the control text for the biggest gaps.
    rag_trace, grounding = [], []
    for g in gaps[:3]:
        rag = agentic_retrieve(kb, router, "controls", f"{g['title']}: {g['fix']}", k=2, agent=AGENT)
        rag_trace += rag["trace"]
        grounding += [f"{h['record']['framework']} {h['id']}: {h['record']['description']}" for h in rag["hits"]]

    roadmap = None
    if gaps:
        result = router.complete(
            POLICY_SYSTEM,
            "Failed checks (with how many controls each one blocks):\n"
            + "\n".join(f"- {g['title']} ({g['controls_affected']} controls: {', '.join(g['controls'][:5])}). Evidence: {g['evidence']}" for g in gaps)
            + "\n\nFramework scores: " + ", ".join(f"{f['framework']} {f['score']}%" for f in frameworks.values())
            + "\n\nRelevant control text:\n" + "\n".join(f"- {t}" for t in grounding)
            + "\n\nWrite a markdown remediation roadmap under 300 words: quick wins this week, 30-day items, 90-day items. "
            "Name the controls each item closes.",
            agent=AGENT, max_tokens=5000,
        )
        roadmap = result.text if result else None
    if not roadmap:
        roadmap = "\n".join(
            [f"Fixes ranked by how many controls they close:"] + [f"{i}. **{g['title']}** ({g['controls_affected']} controls): {g['fix']}" for i, g in enumerate(gaps, 1)]
        ) if gaps else "All checks pass."

    out = {
        "frameworks": list(frameworks.values()),
        "controls": controls,
        "checks": list(checks.values()),
        "gaps": gaps,
        "roadmap": roadmap,
        "rag_trace": rag_trace,
    }
    msg = "Compliance: " + ", ".join(f"{f['framework']} {f['score']}%" for f in frameworks.values()) + f"; {len(gaps)} failed checks"
    return {"compliance": out, "completed": [AGENT], "trace": [trace_event(AGENT, msg)]}
