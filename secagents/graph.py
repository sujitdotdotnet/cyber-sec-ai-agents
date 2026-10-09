"""LangGraph orchestration: a supervisor routes work between the five agents.

Dependencies decide what is eligible next (Threat Intel needs the log and scan results,
Incident Response needs the intel, Policy Checker needs everything). The supervisor runs every
eligible agent in turn, then a reporter node assembles the final report.
"""

from __future__ import annotations

from typing import Any, Iterator

from langgraph.graph import END, START, StateGraph

from .agents import AGENTS
from .agents.base import trace_event
from .config import settings
from .report import build_report
from .state import SecState

DEPENDENCIES: dict[str, list[str]] = {
    "log_monitor": [],
    "vuln_scanner": [],
    "threat_intel": ["log_monitor", "vuln_scanner"],
    "incident_response": ["threat_intel"],
    "policy_checker": ["incident_response", "vuln_scanner"],
}


def next_agent(completed: list[str]) -> str:
    done = set(completed)
    for name, deps in DEPENDENCIES.items():
        if name not in done and all(d in done for d in deps):
            return name
    return "reporter"


def supervisor(state: SecState) -> dict[str, Any]:
    nxt = next_agent(state.get("completed", []))
    label = "all agents finished, compiling report" if nxt == "reporter" else f"dispatching {nxt}"
    return {"next_agent": nxt, "trace": [trace_event("supervisor", label)]}


def reporter(state: SecState) -> dict[str, Any]:
    return {"report_md": build_report(state), "trace": [trace_event("reporter", "report ready")]}


def build_graph():
    g = StateGraph(SecState)
    g.add_node("supervisor", supervisor)
    for name, fn in AGENTS.items():
        g.add_node(name, fn)
        g.add_edge(name, "supervisor")
    g.add_node("reporter", reporter)
    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", lambda s: s["next_agent"], {**{n: n for n in AGENTS}, "reporter": "reporter"})
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
