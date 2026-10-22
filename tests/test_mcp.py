"""MCP: our server over a real stdio subprocess, the client hub, and the agent routing tool calls through MCP."""

import json

import pytest

from secagents.agent import Agent
from secagents.llm import ChatResult, ToolCall
from secagents.mcp_client import McpHub, load_config
from secagents.mcp_server import SERVED, mcp
from secagents.tools import ToolContext


@pytest.fixture(scope="module")
def hub():
    h = McpHub()
    assert h.connect() == {}
    yield h
    h.close()


def test_server_offers_only_read_only_tools():
    from secagents.tools import TOOLS

    assert all(not TOOLS[n].needs_approval for n in SERVED)
    import asyncio

    listed = {t.name for t in asyncio.run(mcp.list_tools())}
    assert listed == set(SERVED)


def test_hub_lists_prefixed_tools_with_schemas(hub):
    assert set(hub.tools) == {f"secagents__{n}" for n in SERVED}
    schema = {s["name"]: s for s in hub.schemas()}["secagents__lookup_record"]
    assert "id" in schema["parameters"]["properties"] and schema["description"].startswith("[secagents]")


def test_calls_cross_the_protocol_and_return_real_data(hub):
    rec = json.loads(hub.call("secagents__lookup_record", {"id": "CVE-2021-44228"}))
    assert rec["kind"] == "cves"
    assert "Brute" in hub.call("secagents__search_knowledge", {"query": "ssh password guessing", "kind": "attack"})
    assert "Error" in hub.call("secagents__nope", {})


def test_tool_errors_are_returned_as_text(hub):
    assert hub.call("secagents__lookup_record", {}).startswith("Error")


def test_agent_can_route_its_tool_calls_through_mcp(hub):
    class Router:
        def __init__(self):
            self.n = 0

        def chat(self, system, messages, tools=None, **kw):
            self.n += 1
            if self.n == 1:
                return ChatResult("", [ToolCall("a", "lookup_record", {"id": "AC-7"})], provider="s", model="m")
            return ChatResult("done", provider="s", model="m")

    events = list(Agent(ToolContext(), Router(), tool_runner=hub.runner()).send("t", "AC-7?"))
    assert events[1]["type"] == "tool_result" and '"AC-7"' in events[1]["text"]


def test_runner_falls_back_to_local_tools_not_served_over_mcp(hub):
    out = hub.runner()("get_assessment_summary", {}, ToolContext())
    assert "No assessment" in out  # not an MCP tool: handled locally


def test_a_server_that_cannot_start_is_reported_and_skipped():
    h = McpHub({"broken": {"command": "definitely-not-a-real-binary-xyz", "args": []}})
    try:
        errors = h.connect()
        assert "broken" in errors and h.tools == {}
        assert h.call("broken__x", {}).startswith("Error")
    finally:
        h.close()


def test_config_file_adds_servers_and_underscore_disables(tmp_path):
    cfg = tmp_path / "m.json"
    cfg.write_text(json.dumps({"mcpServers": {"extra": {"command": "x"}, "_off": {"command": "y"}, "bad": "nope"}}))
    assert set(load_config(cfg)) == {"secagents", "extra"}
    assert set(load_config(tmp_path / "missing.json")) == {"secagents"}
    cfg.write_text("{not json")
    assert set(load_config(cfg)) == {"secagents"}
