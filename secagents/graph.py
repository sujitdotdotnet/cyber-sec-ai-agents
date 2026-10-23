"""LangGraph orchestration: a supervisor plans the work, fans it out to the specialists, then reviews and gates it.

    START -> supervisor --(wave of ready specialists, in parallel)--> specialists --> supervisor ... (until all are done)
          -> correlator -> critic -> human_gate -> reporter -> END

* The **supervisor** plans waves from the dependency table and dispatches every specialist whose inputs are ready, all
  at once: Log Monitor and Vulnerability Scanner first; Threat Intelligence once it has both; Incident Response and
  the Policy Checker together once it has the intel.
* The **correlator** (the supervisor's join step) ties the specialists' findings together per incident.
* The **critic** gives every finding a confidence and writes the caveats into the narrative.
* The **human gate** turns containment steps into proposed actions that wait for a person; nothing is executed.
* The **reporter** assembles the final report.
"""

from __future__ import annotations

from typing import Any, Iterator

from langgraph.graph import END, START, StateGraph

from .agents import AGENTS
from .agents.base import trace_event
from .approvals import counts as gate_counts, propose
from .config import settings
from .correlate import correlate
from .critic import review
from .report import build_report
from .state import SecState

# What each specialist reads from earlier ones. The Policy Checker scores controls from the logs, scan and CVE results,
# not from the incident plan, so it can run alongside Incident Response.
DEPENDENCIES: dict[str, list[str]] = {
    "log_monitor": [],
    "vuln_scanner": [],
    "threat_intel": ["log_monitor", "vuln_scanner"],
    "incident_response": ["threat_intel"],
    "policy_checker": ["threat_intel"],
}


def eligible(completed: list[str]) -> list[str]:
    """Every specialist that has not run and whose inputs are all done: the next wave, to run in parallel."""
    done = set(completed)
    return [name for name, deps in DEPENDENCIES.items() if name not in done and all(d in done for d in deps)]


def plan_waves() -> list[list[str]]:
    waves: list[list[str]] = []
    done: list[str] = []
    while len(done) < len(DEPENDENCIES):
        wave = eligible(done)
        if not wave:  # a cycle in DEPENDENCIES would otherwise loop forever
            raise ValueError("DEPENDENCIES has a cycle")
        waves.append(wave)
        done += wave
    return waves


def next_agent(completed: list[str]) -> str:
    """The first ready specialist (the sequential view of the plan), or "reporter" once all have run."""
    wave = eligible(completed)
    return wave[0] if wave else "reporter"


def supervisor(state: SecState) -> dict[str, Any]:
    done = state.get("completed", [])
    wave = eligible(done)
    trace = []
    if not done:
        trace.append(trace_event("supervisor", "plan: " + " → ".join(" + ".join(w) for w in plan_waves())))
    if not wave:
        label = "all specialists finished, correlating their findings"
    elif len(wave) > 1:
        label = f"dispatching {' + '.join(wave)} in parallel"
    else:
        label = f"dispatching {wave[0]}"
    return {"next_agents": wave, "next_agent": wave[0] if wave else "correlator", "trace": trace + [trace_event("supervisor", label)]}


def correlator(state: SecState) -> dict[str, Any]:
    out = correlate(dict(state))
    return {"correlation": out, "trace": [trace_event("correlator", out["summary"])]}


def critic(state: SecState) -> dict[str, Any]:
    return review(dict(state))


def human_gate(state: SecState) -> dict[str, Any]:
    gate = propose(state.get("incident_plan", {}) or {})
    n = gate_counts(gate)["pending"]
    msg = (f"{n} containment/eradication actions are proposed and wait for a person's approval; this tool executes none of them"
           if n else "no containment actions to approve")
    return {"containment_gate": gate, "trace": [trace_event("human_gate", msg)]}


def reporter(state: SecState) -> dict[str, Any]:
    return {"report_md": build_report(state), "trace": [trace_event("reporter", "report ready")]}


def build_graph():
    g = StateGraph(SecState)
    g.add_node("supervisor", supervisor)
    for name, fn in AGENTS.items():
        g.add_node(name, fn)
        g.add_edge(name, "supervisor")  # all specialists of a wave finish in one step, so the supervisor runs once per wave
    g.add_node("correlator", correlator)
    g.add_node("critic", critic)
    g.add_node("human_gate", human_gate)
    g.add_node("reporter", reporter)
    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", lambda s: s["next_agents"] or "correlator", {**{n: n for n in AGENTS}, "correlator": "correlator"})
    g.add_edge("correlator", "critic")
    g.add_edge("critic", "human_gate")
    g.add_edge("human_gate", "reporter")
    g.add_edge("reporter", END)
    return g.compile()


def default_inputs() -> dict[str, Any]:
    s = settings.samples_dir
    return {
        "log_paths": [str(p) for p in sorted((s / "logs").glob("*.log"))],
        "code_path": str(s / "vulnerable_app"),
        "requirements_path": str(s / "vulnerable_app" / "requirements.txt"),
        "dockerfile_path": str(s / "vulnerable_app" / "Dockerfile"),
        "config_path": str(s / "config" / "system_config.yaml"),
    }


def run(inputs: dict[str, Any] | None = None) -> SecState:
    return build_graph().invoke({"inputs": inputs or default_inputs(), "completed": [], "trace": []})


def stream(inputs: dict[str, Any] | None = None) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (node_name, state_update) as each node finishes, for live UIs."""
    graph = build_graph()
    for chunk in graph.stream({"inputs": inputs or default_inputs(), "completed": [], "trace": []}, stream_mode="updates"):
        for node, update in chunk.items():
            yield node, update or {}
