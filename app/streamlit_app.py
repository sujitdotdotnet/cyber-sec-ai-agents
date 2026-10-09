"""SecAgents dashboard: run the five-agent assessment and explore the results.

    streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secagents.config import settings  # noqa: E402
from secagents.graph import default_inputs, stream  # noqa: E402
from secagents.llm import get_router  # noqa: E402
from secagents.qa import ask  # noqa: E402

st.set_page_config(page_title="SecAgents", page_icon="🛡️", layout="wide")

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
STATUS_ICON = {"PASS": "✅", "PARTIAL": "🟡", "FAIL": "❌"}
AGENT_LABEL = {
    "supervisor": "🧭 Supervisor",
    "log_monitor": "📜 Log Monitor",
    "vuln_scanner": "🔍 Vulnerability Scanner",
    "threat_intel": "🌐 Threat Intelligence",
    "incident_response": "🚨 Incident Response",
    "policy_checker": "📋 Policy Checker",
    "reporter": "📝 Reporter",
}
BAR_COLOR = "#2a78d6"


def sev(s: str) -> str:
    return f"{SEV_ICON.get(s, '')} {s}"


def save_uploads(files, folder: Path) -> list[str]:
    paths = []
    for f in files or []:
        p = folder / Path(f.name).name
        p.write_bytes(f.getvalue())
        paths.append(str(p))
    return paths


# ---- sidebar: providers and inputs ------------------------------------------------
with st.sidebar:
    st.title("🛡️ SecAgents")
    st.caption("Five AI agents for detection, intel, scanning, response and compliance.")
    providers = get_router().available_providers()
    st.markdown("**LLM providers:** " + (", ".join(providers) if providers else "none (rule-based mode)"))
    st.caption(f"Claude model: `{settings.claude_model}` · fallback order: {' → '.join(settings.provider_order)}")

    source = st.radio("Data to analyze", ["Demo attack scenario", "Upload my own files"])
    inputs = default_inputs()
    if source == "Upload my own files":
        tmp = Path(tempfile.mkdtemp(prefix="secagents_"))
        logs = st.file_uploader("Log files (auth.log, access.log, firewall.log)", accept_multiple_files=True)
        code = st.file_uploader("Python source files", type=["py"], accept_multiple_files=True)
        reqs = st.file_uploader("requirements.txt", type=["txt"])
        docker = st.file_uploader("Dockerfile")
        cfg = st.file_uploader("System config (YAML)", type=["yaml", "yml"])
        (tmp / "code").mkdir()
        inputs = {
            "log_paths": save_uploads(logs, tmp),
            "code_path": str(tmp / "code") if code else "",
            "requirements_path": save_uploads([reqs], tmp)[0] if reqs else "",
            "dockerfile_path": save_uploads([docker], tmp)[0] if docker else "",
            "config_path": save_uploads([cfg], tmp)[0] if cfg else "",
        }
        save_uploads(code, tmp / "code")
    run = st.button("▶ Run assessment", type="primary", use_container_width=True)

# ---- run the graph with a live agent trace ----------------------------------------
if run:
    state: dict = {}
    trace: list = []
    get_router().calls.clear()
    with st.status("Agents working...", expanded=True) as status:
        for node, update in stream(inputs):
            for t in update.get("trace", []):
                trace.append(t)
                st.write(f"**{AGENT_LABEL.get(t['agent'], t['agent'])}**: {t['message']}")
            state.update({k: v for k, v in update.items() if k not in ("trace", "completed")})
        status.update(label="Assessment complete", state="complete", expanded=False)
    state["trace"] = trace
    state["llm_calls"] = list(get_router().calls)
    st.session_state["result"] = state
    st.session_state.pop("chat", None)

result = st.session_state.get("result")
if not result:
    st.header("AI-powered security operations")
    st.markdown(
        "Press **Run assessment** to have the agents analyze the demo environment: a web server that was "
        "scanned, probed with SQL injection and Log4Shell, brute-forced over SSH and backdoored.\n\n"
        "| Agent | Job |\n|---|---|\n"
        "| 📜 Log Monitor | Detects attacks and anomalies in auth, web and firewall logs |\n"
        "| 🔍 Vulnerability Scanner | Scans code (Bandit), secrets, Dockerfile and dependencies |\n"
        "| 🌐 Threat Intelligence | Matches CVEs, IOCs and ATT&CK via agentic RAG; answers *are we affected?* |\n"
        "| 🚨 Incident Response | Declares incidents and writes a NIST 800-61 playbook |\n"
        "| 📋 Policy Checker | Scores NIST 800-53, NIST CSF 2.0, ISO 27001 and SOC 2 |"
    )
    st.stop()

logs, vulns = result.get("log_findings", {}), result.get("vuln_findings", {})
intel, ir, comp = result.get("threat_intel", {}), result.get("incident_plan", {}), result.get("compliance", {})

tabs = st.tabs(["Overview", "📜 Logs", "🌐 Threat Intel", "🔍 Vulnerabilities", "🚨 Response", "📋 Compliance", "💬 Ask", "📝 Report"])

with tabs[0]:
    c = st.columns([1.5, 1, 1, 1.2, 1.2])
    c[0].metric("Overall risk", sev(intel.get("overall_risk", "n/a")))
    c[1].metric("Incidents", len(ir.get("incidents", [])), help=f"Highest priority {ir.get('highest_priority')}")
    c[2].metric("Log detections", len(logs.get("events", [])))
    c[3].metric("Code & config findings", len(vulns.get("findings", [])))
    c[4].metric("CVEs affecting us", len(intel.get("cve_matches", [])))
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Incident briefing")
        st.markdown(ir.get("briefing", ""))
    with right:
        st.subheader("Compliance score")
        df = pd.DataFrame(comp.get("frameworks", []))
        if not df.empty:
            bars = alt.Chart(df).mark_bar(color=BAR_COLOR, cornerRadiusEnd=4, height=18).encode(
                x=alt.X("score:Q", scale=alt.Scale(domain=[0, 100]), title="Score (%)"),
                y=alt.Y("framework:N", sort="-x", title=None),
                tooltip=["framework", "score", "pass", "partial", "fail"],
            )
            labels = bars.mark_text(align="left", dx=4).encode(text=alt.Text("score:Q", format=".0f"))
            st.altair_chart((bars + labels).properties(height=180), use_container_width=True)
        st.subheader("Attacker IPs")
        st.write(", ".join(f"`{ip}`" for ip in logs.get("attackers", [])) or "None")
    with st.expander("Agent trace"):
        for t in result.get("trace", []):
            st.write(f"`{t['ts']}` **{AGENT_LABEL.get(t['agent'], t['agent'])}**: {t['message']}")
        if result.get("llm_calls"):
            st.dataframe(pd.DataFrame(result["llm_calls"]), hide_index=True, use_container_width=True)

with tabs[1]:
    st.markdown(logs.get("narrative", ""))
    if logs.get("techniques"):
        st.caption("MITRE ATT&CK: " + " · ".join(f"{t['id']} {t['name']}" for t in logs["techniques"]))
    for e in logs.get("events", []):
        with st.expander(f"{SEV_ICON.get(e['severity'], '')} {e['id']} · {e['type']} · {e.get('src_ip', '')}"):
            st.write(e["description"])
            st.caption(f"{e.get('first_seen', '')} → {e.get('last_seen', '')} · source {e['source']} · ATT&CK {', '.join(e.get('mitre', []))}")
            st.code("\n".join(e.get("evidence", [])), language="log")

with tabs[2]:
    st.markdown(intel.get("summary", ""))
    st.subheader("Attacks that hit real weaknesses")
    st.dataframe(pd.DataFrame(intel.get("correlations", [])), hide_index=True, use_container_width=True)
    st.subheader("CVEs affecting deployed components")
    st.dataframe(pd.DataFrame(intel.get("cve_matches", [])), hide_index=True, use_container_width=True)
    a, b = st.columns(2)
    a.subheader("Exploit attempts")
    a.dataframe(pd.DataFrame(intel.get("exploit_attempts", [])), hide_index=True, use_container_width=True)
    b.subheader("Known-bad indicators")
    b.dataframe(pd.DataFrame(intel.get("ioc_hits", [])), hide_index=True, use_container_width=True)
    with st.expander("Agentic RAG trace"):
        st.write(intel.get("rag_trace", []))

with tabs[3]:
    df = pd.DataFrame(vulns.get("findings", []))
    if not df.empty:
        cats = st.multiselect("Category", sorted(df["category"].unique()), default=sorted(df["category"].unique()))
        df = df[df["category"].isin(cats)]
        df["severity"] = df["severity"].map(sev)
        cols = [c for c in ["id", "severity", "category", "title", "file", "line", "cwe", "tool", "snippet"] if c in df]
        st.dataframe(df[cols], hide_index=True, use_container_width=True)
    st.subheader("Suggested fixes")
    st.markdown(vulns.get("remediation", ""))
    with st.expander("Software inventory"):
        st.dataframe(pd.DataFrame(vulns.get("inventory", [])), hide_index=True, use_container_width=True)

with tabs[4]:
    for inc in ir.get("incidents", []):
        st.markdown(f"**{sev(inc['severity'])} {inc['id']} [{inc['priority']}] {inc['title']}**  \n{inc['summary']}")
    st.divider()
    phase = None
    for s in ir.get("steps", []):
        if s["phase"] != phase:
            phase = s["phase"]
            st.subheader(phase)
        label = f"**{s['priority']}** {s['action']} · _{s['owner']}_" + (" · 🤖 suggested" if s.get("source") == "llm" else "")
        st.checkbox(label, key=f"step-{s['step']}")
        if s.get("command"):
            st.code(s["command"], language="bash")

with tabs[5]:
    st.markdown(comp.get("roadmap", ""))
    frameworks = ["All"] + [f["framework"] for f in comp.get("frameworks", [])]
    pick = st.selectbox("Framework", frameworks)
    rows = [c for c in comp.get("controls", []) if pick == "All" or c["framework"] == pick]
    st.dataframe(
        pd.DataFrame([{"Status": f"{STATUS_ICON[c['status']]} {c['status']}", "Framework": c["framework"], "Control": c["id"],
                       "Title": c["title"], "Evidence": c["evidence"]} for c in rows]),
        hide_index=True, use_container_width=True,
    )
    with st.expander("Technical checks"):
        st.dataframe(pd.DataFrame(comp.get("checks", [])), hide_index=True, use_container_width=True)

with tabs[6]:
    st.caption("Ask a question; it is routed to the relevant agents' results and grounded with RAG.")
    chat = st.session_state.setdefault("chat", [])
    for role, text in chat:
        st.chat_message(role).markdown(text)
    q = st.chat_input("e.g. Are we affected by Log4Shell? What should we do in the next hour?")
    if q:
        st.chat_message("user").markdown(q)
        with st.spinner("Agents thinking..."):
            ans = ask(q, result)
        reply = ans["answer"] + f"\n\n_Agents: {', '.join(ans['agents'])} · sources: {', '.join(ans['sources'])}_"
        st.chat_message("assistant").markdown(reply)
        chat += [("user", q), ("assistant", reply)]

with tabs[7]:
    report = result.get("report_md", "")
    a, b = st.columns(2)
    a.download_button("⬇ Download report (Markdown)", report, "security_report.md", use_container_width=True)
    b.download_button("⬇ Download results (JSON)", json.dumps(result, indent=2, default=str), "security_results.json", use_container_width=True)
    st.markdown(report)
