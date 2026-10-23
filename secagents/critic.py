"""The uncertainty critic: reviews every finding before the report and makes the doubt visible.

Detection is rule-based and the model only writes the explanation, so what can mislead a reader is overstated
certainty: a version-based CVE match presented like a confirmed exposure, an exploit attempt against a component that
is not even installed, or a package whose version was never pinned and therefore never checked. The critic

* re-checks each CVE match's version against the advisory's affected range on its own (a guardrail independent of
  the matcher),
* gives every CVE match, exploit attempt, correlation and indicator a ``confidence`` (high / medium / low) with a
  ``confidence_reason``,
* lists exposures that could not be verified at all (unpinned dependencies),
* and appends the caveats to the narrative the model wrote, so the written summary cannot sound surer than the data.

It changes no detections and calls no model: the same input always gives the same review.
"""

from __future__ import annotations

import copy
from typing import Any

from .agents.base import trace_event
from .agents.threat_intel import satisfies

HIGH, MEDIUM, LOW = "high", "medium", "low"


def _mark(item: dict[str, Any], level: str, reason: str) -> dict[str, Any]:
    item["confidence"], item["confidence_reason"] = level, reason
    return item


def _review_cve(m: dict[str, Any]) -> tuple[str, str]:
    spec = m.get("affected_spec", "")
    if spec and satisfies(m["installed"], spec) is False:
        return LOW, f"on review, version {m['installed']} is NOT inside the affected range {spec}"
    how = "re-checked against the affected range" if spec else "matched by OSV for this exact version" if m.get("data_source") == "OSV (live)" else "version-matched"
    kev = "; listed by CISA as exploited in the wild" if m.get("exploited_in_the_wild") else ""
    if m.get("ecosystem") == "os":
        return MEDIUM, f"{how}, but this is a distribution package: vendor backports may already include the fix{kev}"
    if not m.get("cvss") or str(m.get("severity", "")).upper() == "UNKNOWN":
        return MEDIUM, f"{how}; no CVSS score is published, so the severity is not established{kev}"
    return HIGH, f"{how}{kev}"


def review(state: dict[str, Any]) -> dict[str, Any]:
    intel = copy.deepcopy(state.get("threat_intel", {}) or {})
    plan = copy.deepcopy(state.get("incident_plan", {}) or {})
    logs = state.get("log_findings", {}) or {}
    inventory = (state.get("vuln_findings", {}) or {}).get("inventory", [])
    uncertain: list[dict[str, Any]] = []

    def flag(kind: str, ident: str, item: dict[str, Any]) -> None:
        if item["confidence"] != HIGH:
            uncertain.append({"kind": kind, "id": ident, "confidence": item["confidence"], "reason": item["confidence_reason"]})

    cves = intel.get("cve_matches", [])
    for m in cves:
        flag("CVE match", f"{m['cve']} · {m['package']} {m['installed']}", _mark(m, *_review_cve(m)))
    for a in intel.get("exploit_attempts", []):
        if a.get("component_present"):
            _mark(a, HIGH, f"the targeted component {a['component']} is installed")
        else:
            _mark(a, LOW, f"attempt only: {a['component']} is not in the inventory, so no exposure is shown")
        flag("Exploit attempt", f"{a['event']} → {a['cve']}", a)
    for c in intel.get("correlations", []):
        if "Likely exploited" in c.get("verdict", ""):
            _mark(c, HIGH, "the attack returned HTTP 2xx and the matching weakness exists in the code")
        else:
            _mark(c, MEDIUM, "the weakness exists, but nothing shows the attack succeeded")
        flag("Attack ↔ weakness", f"{c['event']} → {c['finding']}", c)
    for h in intel.get("ioc_hits", []):
        _mark(h, MEDIUM if h.get("reputation") == "malicious" else LOW,
              f"reputation '{h.get('reputation')}' from {h.get('source', 'an indicator feed')}; an address alone does not prove intent")
        flag("Indicator", h["indicator"], h)
    inferred = [e for e in logs.get("events", []) if e.get("possibly_successful")]
    for e in inferred:
        uncertain.append({"kind": "Log detection", "id": f"{e['id']} · {e['type']}", "confidence": MEDIUM,
                          "reason": "success is inferred from the HTTP status code alone, not from evidence of impact"})
    unverified = [{"component": c["name"], "ecosystem": c["ecosystem"], "reason": "version is not pinned, so known CVEs could not be matched"}
                  for c in inventory if c.get("version") in (None, "", "unpinned")]

    levels = [m["confidence"] for m in cves]
    notes = []
    weak = sum(1 for m in cves if m["confidence"] != HIGH)
    if weak:
        notes.append(f"{weak} of {len(cves)} CVE matches are lower confidence")
    theoretical = [a for a in intel.get("exploit_attempts", []) if a["confidence"] == LOW]
    if theoretical:
        notes.append(f"{len(theoretical)} exploit attempt(s) target components that are not installed, so they show no exposure")
    if inferred:
        notes.append(f"{len(inferred)} web attack(s) are marked successful only because the server answered 2xx")
    if unverified:
        notes.append(f"{len(unverified)} dependencies are not pinned, so their vulnerabilities were not checked")
    caveat = ("**Review notes (uncertainty critic):** " + "; ".join(notes) + ". See the confidence column for each item.") if notes else ""
    if caveat:
        intel["summary"] = (intel.get("summary", "") + "\n\n" + caveat).strip()
        plan["briefing"] = (plan.get("briefing", "") + "\n\n" + caveat).strip() if plan.get("briefing") else caveat

    counts = {lvl: sum(1 for i in [*cves, *intel.get("exploit_attempts", []), *intel.get("correlations", []), *intel.get("ioc_hits", [])] if i["confidence"] == lvl)
              for lvl in (HIGH, MEDIUM, LOW)}
    reviewed = sum(counts.values())
    critic = {"reviewed": reviewed, "counts": counts, "uncertain": uncertain, "unverified": unverified, "caveat": caveat,
              "cve_confidence": {lvl: levels.count(lvl) for lvl in (HIGH, MEDIUM, LOW)}}
    msg = (f"reviewed {reviewed} findings: {counts[HIGH]} high, {counts[MEDIUM]} medium, {counts[LOW]} low confidence; "
           f"{len(unverified)} unverified exposure(s)")
    return {"threat_intel": intel, "incident_plan": plan, "critic": critic, "trace": [trace_event("critic", msg)]}
