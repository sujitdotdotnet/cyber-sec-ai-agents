"""Tool registry: schemas, argument checking, read-only tools on real results, approval flags."""

import json

import pytest

from secagents import tools
from secagents.graph import run
from secagents.memory import Memory
from secagents.tools import TOOLS, ToolContext, call_tool, schemas

SSH = ["Jan 10 03:01:%02d web01 sshd[1]: Failed password for root from 203.0.113.9 port 4%03d ssh2" % (i, i) for i in range(12)]


@pytest.fixture(scope="module")
def assessed():
    return dict(run())


@pytest.fixture
def ctx(assessed, tmp_path):
    return ToolContext(state=assessed, memory=Memory(tmp_path / "m.db"), workspace="t")


def test_every_tool_has_a_valid_schema():
    for s in schemas():
        assert s["name"] in TOOLS and s["description"]
        assert s["parameters"]["type"] == "object"
        assert set(s["parameters"]["required"]) <= set(s["parameters"]["properties"])
    json.dumps(schemas())


def test_only_state_changing_tools_need_approval():
    assert {n for n, t in TOOLS.items() if t.needs_approval} == {"remember", "forget_memory", "run_assessment", "add_live_log_lines"}
    assert set(tools.READ_ONLY).isdisjoint({"remember", "run_assessment"})


def test_bad_arguments_come_back_as_text_not_exceptions(ctx):
    assert "missing required argument 'query'" in call_tool("search_knowledge", {}, ctx)
    assert "unknown argument" in call_tool("lookup_record", {"id": "x", "evil": 1}, ctx)
    assert "must be one of" in call_tool("get_findings", {"section": "passwords"}, ctx)
    assert "must be an integer" in call_tool("get_findings", {"section": "logs", "limit": "5"}, ctx)
    assert "not valid JSON" in call_tool("lookup_record", {"_unparsed": "{x"}, ctx)
    assert "no tool named" in call_tool("rm_rf", {}, ctx)


def test_lookup_and_search_use_the_knowledge_base(ctx):
    rec = json.loads(call_tool("lookup_record", {"id": "cve-2021-44228"}, ctx))
    assert rec["kind"] == "cves" and "log4" in json.dumps(rec).lower()
    assert "No CVE" in call_tool("lookup_record", {"id": "CVE-0000-0000"}, ctx)
    hits = json.loads(call_tool("search_knowledge", {"query": "ssh password guessing", "kind": "attack"}, ctx))
    assert hits and all({"id", "text"} <= set(h) for h in hits)


def test_assessment_tools_read_the_latest_results(ctx):
    summary = json.loads(call_tool("get_assessment_summary", {}, ctx))
    assert summary["overall_risk"] and summary["incidents"]
    found = json.loads(call_tool("get_findings", {"section": "logs", "limit": 3}, ctx))
    assert found["total"] >= 3 and len(found["shown"]) == 3 and all("evidence" not in e for e in found["shown"])
    high = json.loads(call_tool("get_findings", {"section": "vulnerabilities", "severity": "HIGH"}, ctx))
    assert all(f["severity"] == "HIGH" for f in high["shown"])
    assert call_tool("get_incident_steps", {"limit": 2}, ctx).count("\n") > 1


def test_no_assessment_yet_is_explained(tmp_path):
    empty = ToolContext(memory=Memory(tmp_path / "e.db"))
    assert "No assessment" in call_tool("get_assessment_summary", {}, empty)
    assert "No assessment" in call_tool("get_findings", {"section": "logs"}, empty)


def test_analyze_log_text_detects_without_writing(ctx):
    out = json.loads(call_tool("analyze_log_text", {"text": "\n".join(SSH)}, ctx))
    assert out["total_detections"] >= 1 and "203.0.113.9" in json.dumps(out)
    assert "no attack pattern" in call_tool("analyze_log_text", {"text": "hello world"}, ctx)


def test_memory_tools_round_trip_and_refuse_secrets(ctx):
    assert call_tool("remember", {"fact": "we run nginx on ubuntu"}, ctx).startswith("Remembered as ")
    assert "nginx" in call_tool("recall_memory", {"query": "nginx servers"}, ctx)
    assert "Not saved" in call_tool("remember", {"fact": "api_key=abcdef123456"}, ctx)
    mid = ctx.memory.facts("t")[0]["id"]
    assert call_tool("forget_memory", {"id": mid}, ctx) == "Forgotten."
    assert "not enabled" in call_tool("recall_memory", {"query": "x"}, ToolContext())


def test_add_live_log_lines_writes_to_the_live_folder(ctx, tmp_path, monkeypatch):
    from secagents import session

    monkeypatch.setattr(session, "_live", type("V", (), {"get": staticmethod(lambda: tmp_path / "live")})())
    out = json.loads(call_tool("add_live_log_lines", {"text": SSH[0] + "\nnot a log line"}, ctx))
    assert out["written"] == {"auth.log": 1} and out["not_understood"] == 1
    assert (tmp_path / "live" / "auth.log").exists()


def test_results_are_clipped(ctx, monkeypatch):
    monkeypatch.setitem(TOOLS, "big", tools.Tool("big", "d", tools._obj({}), lambda c, a: "x" * 50000))
    out = call_tool("big", {}, ctx)
    assert len(out) < tools.MAX_RESULT_CHARS + 100 and "more characters cut" in out


def test_a_crashing_tool_is_reported_not_raised(ctx, monkeypatch):
    def boom(c, a):
        raise RuntimeError("disk on fire")

    monkeypatch.setitem(TOOLS, "boom", tools.Tool("boom", "d", tools._obj({}), boom))
    assert "RuntimeError: disk on fire" in call_tool("boom", {}, ctx)
