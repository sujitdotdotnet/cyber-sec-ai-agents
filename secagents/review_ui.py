"""Dashboard panels for the review steps of the pipeline: the critic's doubts, the correlated view, and the human gate.

Kept out of the main app file so the app's stale-module guards reload it with the rest of the package.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from . import approvals, history

CVE_COLUMNS = ["cve", "package", "installed", "fixed", "cvss", "severity", "confidence", "exploited_in_the_wild", "data_source",
               "confidence_reason", "note", "title", "source", "ecosystem"]
STATUS_ICON = {"pending": "⏳", "approved": "✅", "rejected": "⛔"}
CHOICES = {"Pending": "pending", "Approve": "approve", "Reject": "reject"}
INDEX = {"pending": 0, "approved": 1, "rejected": 2}


def cve_frame(intel: dict[str, Any]) -> pd.DataFrame:
    """The CVE matches with the columns people read first on the left (confidence next to severity), helpers dropped."""
    df = pd.DataFrame(intel.get("cve_matches", []))
    if df.empty:
        return df
    first = [c for c in CVE_COLUMNS if c in df.columns]
    return df[first]


def scan_date(scan_id: str) -> str:
    return f"{scan_id[:4]}-{scan_id[4:6]}-{scan_id[6:8]}" if len(scan_id) >= 8 and scan_id[:8].isdigit() else scan_id


def confidence_line(result: dict[str, Any]) -> str:
    c = (result.get("critic") or {}).get("counts")
    return f"Confidence of the findings: {c['high']} high · {c['medium']} medium · {c['low']} low" if c else ""


def critic_panel(result: dict[str, Any]) -> None:
    critic = result.get("critic") or {}
    if not critic:
        return
    with st.expander("🧪 Critic review: what to treat with caution", expanded=False):
        st.caption("Every CVE match, exploit attempt, correlation and indicator was re-checked and given a confidence. "
                   "The critic changes no detections; it makes the doubt visible and adds it to the written summaries.")
        st.markdown(critic.get("caveat") or "Nothing needs a caveat.")
        if critic.get("uncertain"):
            st.dataframe(pd.DataFrame(critic["uncertain"]).rename(columns={"kind": "Kind", "id": "Item", "confidence": "Confidence", "reason": "Why"}),
                         hide_index=True, use_container_width=True)
        if critic.get("unverified"):
            st.markdown("**Exposures that could not be verified**")
            st.dataframe(pd.DataFrame(critic["unverified"]), hide_index=True, use_container_width=True)


def correlation_panel(result: dict[str, Any]) -> None:
    corr = result.get("correlation") or {}
    if not corr.get("links"):
        return
    st.markdown("**How the findings connect** (the supervisor joins the specialists' results per incident)")
    st.dataframe(pd.DataFrame([{
        "Incident": ln["incident"], "Log events": ", ".join(ln["events"]), "Attackers": ", ".join(ln["attackers"]),
        "Code weaknesses": ", ".join(ln["weaknesses"]), "CVEs": ", ".join(ln["cves"]), "ATT&CK": ", ".join(ln["techniques"]),
        "Known-bad": ", ".join(ln["known_bad"]), "Control gaps exposed": "; ".join(ln["control_gaps"]),
    } for ln in corr["links"]]), hide_index=True, use_container_width=True)
    st.caption(corr.get("summary", ""))


def similar_past(incident: dict[str, Any]) -> None:
    for m in incident.get("similar_past", []):
        st.caption(f"🕘 Resembles an earlier incident: **{m['title']}** ({m['incident']} in the scan of {scan_date(m['scan'])}, similarity {m['score']:.2f})")


def gate_panel(result: dict[str, Any], scan: dict[str, Any] | None, who: str, nonce: int = 0) -> None:
    """The human gate: review, edit, approve or reject each containment/eradication action. Nothing is executed."""
    gate = result.get("containment_gate") or {}
    actions = gate.get("actions", [])
    st.subheader("🧑‍⚖️ Human approval gate")
    if not actions:
        st.caption("No containment or eradication actions were proposed.")
        return
    st.info("SecAgents executes none of these steps. Review each action, edit the command if it needs changing, then approve or reject it. "
            "Approved actions go into a runbook script that you read and run yourself.", icon="🔒")
    n = approvals.counts(gate)
    cols = st.columns(3)
    cols[0].metric("Awaiting approval", n["pending"])
    cols[1].metric("Approved", n["approved"])
    cols[2].metric("Rejected", n["rejected"])
    sid = (scan or {}).get("id", "session")
    key = lambda kind, a: f"gate-{kind}-{sid}-{a['id']}-{nonce}"  # noqa: E731
    with st.form(f"gate-form-{sid}-{nonce}"):
        for a in actions:
            st.markdown(f"{STATUS_ICON[a['status']]} **{a['id']}** · {a['incident']} · {a['phase']} · {a['priority']}: {a['action']}")
            left, right = st.columns([5, 2])
            left.text_input("Command", value=a["approved_command"] or a["command"], key=key("cmd", a), label_visibility="collapsed",
                            placeholder="(no command: a manual step)")
            right.radio("Decision", list(CHOICES), index=INDEX[a["status"]], key=key("choice", a), horizontal=True, label_visibility="collapsed")
        saved = st.form_submit_button("Save decisions", type="primary")
    if saved:
        decisions = {a["id"]: {"decision": CHOICES[st.session_state[key("choice", a)]], "command": st.session_state[key("cmd", a)]} for a in actions}
        try:
            new = approvals.decide(gate, decisions, who)
        except ValueError as exc:
            st.error(str(exc))
        else:
            result["containment_gate"] = new
            if scan and scan.get("id"):
                try:
                    history.set_gate(scan["id"], new)
                except (OSError, ValueError, KeyError):
                    st.warning("Saved for this session only: the scan could not be updated in your history.")
            st.rerun()
    st.download_button("⬇ Approved runbook (.sh)", approvals.runbook(gate, (scan or {}).get("name", "Containment runbook"), who), "containment_runbook.sh",
                       on_click="ignore", help="Only the approved actions, with who approved each. Review it before you run anything.")
    if gate.get("audit"):
        with st.expander(f"Audit trail ({len(gate['audit'])})"):
            st.dataframe(pd.DataFrame(gate["audit"]).rename(columns={"at": "When (UTC)", "by": "By", "action": "Action", "decision": "Decision",
                                                                    "from": "Was", "command_before": "Command before", "command_after": "Command after"}),
                         hide_index=True, use_container_width=True)
