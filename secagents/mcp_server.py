"""SecAgents as an MCP server: the read-only security tools, knowledge resources and a triage prompt.

Run it for Claude Desktop, Cursor or any MCP client:

    python -m secagents.mcp_server                      # stdio (default)
    python -m secagents.mcp_server --http --port 8765   # streamable HTTP at /mcp

Only read-only tools are exposed: nothing here writes files, runs an assessment or changes memory. The tool bodies are
the same functions the chat agent uses (secagents.tools), so both paths behave identically.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import tools
from .agents import log_monitor as _warm  # noqa: F401 - import now: a first import inside a tool call stalled the stdio reply
from .tools import ToolContext, call_tool

SERVED = ("search_knowledge", "lookup_record", "analyze_log_text")  # read-only; no assessment state lives in this process

mcp = FastMCP("secagents", instructions="Security knowledge (CVEs, MITRE ATT&CK, compliance controls) and log attack detection.")
_ctx = ToolContext()


@mcp.tool()
def search_knowledge(query: str, kind: str = "cves", k: int = 3) -> str:
    """Semantic search of the knowledge base. kind is one of: cves, attack, controls."""
    return call_tool("search_knowledge", {"query": query, "kind": kind, "k": k}, _ctx)


@mcp.tool()
def lookup_record(id: str) -> str:
    """Fetch one record by exact id, e.g. CVE-2021-44228, T1110.001 or AC-7."""
    return call_tool("lookup_record", {"id": id}, _ctx)


@mcp.tool()
def analyze_log_text(text: str) -> str:
    """Run the attack detectors (SSH brute force, web attacks, port scans, C2) over pasted log lines."""
    return call_tool("analyze_log_text", {"text": text}, _ctx)


@mcp.resource("knowledge://{kind}/{record_id}")
def knowledge_record(kind: str, record_id: str) -> str:
    """One knowledge-base record as JSON (kind: cves, attack, controls)."""
    from .rag import get_kb

    if kind not in tools.KINDS:
        return json.dumps({"error": f"kind must be one of {', '.join(tools.KINDS)}"})
    return json.dumps(get_kb().get(kind, record_id) or {"error": f"no {kind} record {record_id!r}"}, indent=1)


@mcp.prompt()
def triage_logs(log_lines: str) -> str:
    """Ask the model to triage pasted log lines using this server's tools."""
    return ("Triage these log lines. Call analyze_log_text first, then lookup_record for any CVE or ATT&CK technique ids you "
            "mention, then give: what happened, how severe, and the first three containment steps.\n\n" + log_lines)


def served_tools() -> list[dict[str, Any]]:
    return tools.schemas(SERVED)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--http", action="store_true", help="serve streamable HTTP at /mcp instead of stdio")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args()
    if args.http:
        mcp.settings.host, mcp.settings.port = args.host, args.port
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
