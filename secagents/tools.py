"""Tool registry for the chat agent (and the MCP server).

A tool is a name, a description, a JSON schema and a plain function. Read-only tools run freely; tools that change
something (run an assessment, write log lines, delete a memory) are flagged ``needs_approval`` and the agent loop
stops for a human decision before calling them. Results are always short strings: the model reads them, so they are
capped, and a failing tool returns its error as text instead of raising.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

MAX_RESULT_CHARS = 6000
KINDS = ("cves", "attack", "controls")
SECTIONS = {
    "logs": ("log_findings", "events"),
    "vulnerabilities": ("vuln_findings", "findings"),
    "threat_intel": ("threat_intel", "cve_matches"),
    "incidents": ("incident_plan", "incidents"),
    "compliance_gaps": ("compliance", "gaps"),
}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class ToolContext:
    """What tools may touch: the latest assessment, the memory store and the caller's scope."""

    state: dict[str, Any] = field(default_factory=dict)  # the latest SecState (empty until an assessment ran)
    memory: Any = None  # secagents.memory.Memory or None
    workspace: str = "default"
    run_inputs: Callable[[], dict[str, Any] | None] | None = None  # inputs for run_assessment (None = built-in samples)


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[[ToolContext, dict[str, Any]], Any]
    needs_approval: bool = False

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


def clip(text: str, limit: int = MAX_RESULT_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n... [{len(text) - limit} more characters cut]"


def as_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, default=str, indent=1)


def _obj(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required or []}


def _slim(item: Any) -> Any:
    """Drop bulky fields (raw evidence) from a finding before the model reads it."""
    if isinstance(item, dict):
        return {k: v for k, v in item.items() if k not in ("evidence", "raw")}
    return item


# ---- read-only tools -------------------------------------------------------------------------------------
def search_knowledge(ctx: ToolContext, a: dict[str, Any]) -> Any:
    from .rag import get_kb

    kind = a.get("kind", "cves")
    hits = get_kb().search(kind, a["query"], k=max(1, min(int(a.get("k", 3)), 6)))
    return [{"id": h["id"], "score": h["score"], "text": h["text"][:700]} for h in hits]


def lookup_record(ctx: ToolContext, a: dict[str, Any]) -> Any:
    from .rag import get_kb

    wanted = a["id"].strip().upper()
    kb = get_kb()
    for kind in KINDS:
        rec = kb.get(kind, a["id"].strip()) or next((r for r in kb.all(kind) if r["id"].upper() == wanted), None)
        if rec:
            return {"kind": kind, **rec}
    return f"No CVE, ATT&CK technique or control with id {a['id']!r} in the knowledge base. Try search_knowledge."


def analyze_log_text(ctx: ToolContext, a: dict[str, Any]) -> Any:
    """Run the detectors over pasted log lines. Read-only: nothing is written anywhere."""
    from .agents.log_monitor import detect_named, line_kind

    lines = [ln.rstrip() for ln in a["text"].replace("\r\n", "\n").splitlines() if ln.strip()]
    if not lines:
        return "No log lines were given."
    by_file: dict[str, list[str]] = {}
    for ln in lines:
        by_file.setdefault({"auth": "auth.log", "web": "access.log", "firewall": "firewall.log"}.get(line_kind(ln) or "", "unknown.log"), []).append(ln)
    events = detect_named(list(by_file.items()))
    if not events:
        return f"{len(lines)} lines read, no attack pattern found (the parsers read SSH auth, web access and firewall formats)."
    return {"lines": len(lines), "detections": [_slim(e) for e in events[:15]], "total_detections": len(events)}


def assessment_summary(ctx: ToolContext, a: dict[str, Any]) -> Any:
    s = ctx.state
    if not s:
        return "No assessment has run yet. Use run_assessment (needs approval) or ask the user to press Run Assessment."
    return {
        "overall_risk": s.get("threat_intel", {}).get("overall_risk"),
        "log_detections": s.get("log_findings", {}).get("counts"),
        "vulnerabilities": s.get("vuln_findings", {}).get("counts"),
        "intel": s.get("threat_intel", {}).get("counts"),
        "incidents": [{"id": i.get("id"), "title": i.get("title"), "severity": i.get("severity")} for i in s.get("incident_plan", {}).get("incidents", [])],
        "highest_priority": s.get("incident_plan", {}).get("highest_priority"),
        "compliance_gaps": len(s.get("compliance", {}).get("gaps", [])),
    }


def get_findings(ctx: ToolContext, a: dict[str, Any]) -> Any:
    if not ctx.state:
        return "No assessment has run yet."
    key, field_ = SECTIONS[a["section"]]
    items = list(ctx.state.get(key, {}).get(field_, []))
    sev = (a.get("severity") or "").upper()
    if sev:
        items = [i for i in items if str(i.get("severity", "")).upper() == sev]
    limit = max(1, min(int(a.get("limit", 10)), 25))
    return {"section": a["section"], "total": len(items), "shown": [_slim(i) for i in items[:limit]]}


def incident_steps(ctx: ToolContext, a: dict[str, Any]) -> Any:
    steps = ctx.state.get("incident_plan", {}).get("steps", []) if ctx.state else []
    if not steps:
        return "No response plan yet: run an assessment first."
    return steps[: max(1, min(int(a.get("limit", 10)), 30))]


def recall_memory(ctx: ToolContext, a: dict[str, Any]) -> Any:
    if ctx.memory is None:
        return "Memory is not enabled."
    hits = ctx.memory.recall(a["query"], workspace=ctx.workspace, k=5)
    return [{"id": h["id"], "fact": h["text"], "saved": h["created"]} for h in hits] or "Nothing relevant remembered."


# ---- tools that change things (human approval first) ----------------------------------------------------
def remember(ctx: ToolContext, a: dict[str, Any]) -> Any:
    if ctx.memory is None:
        return "Memory is not enabled."
    mid = ctx.memory.remember(a["fact"], workspace=ctx.workspace)
    return f"Remembered as {mid}." if mid else "Not saved: the text looked like a secret or was empty."


def forget(ctx: ToolContext, a: dict[str, Any]) -> Any:
    if ctx.memory is None:
        return "Memory is not enabled."
    return "Forgotten." if ctx.memory.forget(a["id"], workspace=ctx.workspace) else f"No memory {a['id']!r}."


def run_assessment(ctx: ToolContext, a: dict[str, Any]) -> Any:
    from .graph import run

    ctx.state = dict(run(ctx.run_inputs() if ctx.run_inputs else None))
    return assessment_summary(ctx, {})


def add_live_log_lines(ctx: ToolContext, a: dict[str, Any]) -> Any:
    from .live import append_routed

    written, ignored = append_routed(a["text"])
    return {"written": written, "not_understood": len(ignored)}


TOOLS: dict[str, Tool] = {t.name: t for t in [
    Tool("search_knowledge", "Semantic search of the security knowledge base: CVEs (cves), MITRE ATT&CK techniques (attack) or compliance controls (controls).",
         _obj({"query": {"type": "string"}, "kind": {"type": "string", "enum": list(KINDS)}, "k": {"type": "integer"}}, ["query"]), search_knowledge),
    Tool("lookup_record", "Fetch one knowledge-base record by exact id, e.g. CVE-2021-44228, T1110.001 or AC-7.",
         _obj({"id": {"type": "string"}}, ["id"]), lookup_record),
    Tool("analyze_log_text", "Run the attack detectors (SSH brute force, web attacks, port scans, C2) over log lines the user pasted. Read-only.",
         _obj({"text": {"type": "string", "description": "raw log lines"}}, ["text"]), analyze_log_text),
    Tool("get_assessment_summary", "Headline results of the latest assessment: overall risk, counts, incidents, compliance gaps.",
         _obj({}), assessment_summary),
    Tool("get_findings", "List findings from the latest assessment for one section, optionally one severity.",
         _obj({"section": {"type": "string", "enum": list(SECTIONS)}, "severity": {"type": "string", "enum": list(SEVERITIES)},
               "limit": {"type": "integer"}}, ["section"]), get_findings),
    Tool("get_incident_steps", "The ordered incident-response steps from the latest assessment.",
         _obj({"limit": {"type": "integer"}}), incident_steps),
    Tool("recall_memory", "Search what was remembered about this user/workspace in earlier conversations.",
         _obj({"query": {"type": "string"}}, ["query"]), recall_memory),
    Tool("remember", "Save a durable fact (a preference, an asset, a decision) for later conversations. Never save secrets.",
         _obj({"fact": {"type": "string"}}, ["fact"]), remember, needs_approval=True),
    Tool("forget_memory", "Delete one remembered fact by id.", _obj({"id": {"type": "string"}}, ["id"]), forget, needs_approval=True),
    Tool("run_assessment", "Run the full five-agent assessment on the configured inputs (takes a while, may use LLM budget).",
         _obj({}), run_assessment, needs_approval=True),
    Tool("add_live_log_lines", "Append log lines to the live-scan log files so Live Scan analyses them.",
         _obj({"text": {"type": "string"}}, ["text"]), add_live_log_lines, needs_approval=True),
]}

READ_ONLY = tuple(n for n, t in TOOLS.items() if not t.needs_approval and n != "recall_memory")


def schemas(names: list[str] | tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    return [TOOLS[n].schema() for n in (names or TOOLS) if n in TOOLS]


def check_arguments(tool: Tool, args: dict[str, Any]) -> str | None:
    """A message describing what is wrong with the model's arguments, or None if they are usable."""
    if "_unparsed" in args:
        return "the arguments were not valid JSON"
    props = tool.parameters["properties"]
    for name in tool.parameters["required"]:
        if args.get(name) in (None, ""):
            return f"missing required argument {name!r}"
    for name, value in args.items():
        spec = props.get(name)
        if spec is None:
            return f"unknown argument {name!r} (allowed: {', '.join(props) or 'none'})"
        if spec["type"] == "string" and not isinstance(value, str):
            return f"argument {name!r} must be a string"
        if spec["type"] == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            return f"argument {name!r} must be an integer"
        if "enum" in spec and value not in spec["enum"]:
            return f"argument {name!r} must be one of {', '.join(spec['enum'])}"
    return None


def call_tool(name: str, args: dict[str, Any], ctx: ToolContext) -> str:
    """Run a tool and return text for the model. Never raises."""
    tool = TOOLS.get(name)
    if tool is None:
        return f"Error: no tool named {name!r}. Available: {', '.join(TOOLS)}."
    problem = check_arguments(tool, args or {})
    if problem:
        return f"Error calling {name}: {problem}."
    try:
        return clip(as_text(tool.fn(ctx, args or {})))
    except Exception as exc:  # noqa: BLE001 - the model should see the failure and decide what to do
        return f"Error: {name} failed ({type(exc).__name__}: {str(exc)[:300]})."
