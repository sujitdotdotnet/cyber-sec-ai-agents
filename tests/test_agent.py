"""Agent loop with a scripted model: tool use, approval pause/resume, denial, budgets, memory, restored history."""

import json

import pytest

from secagents.agent import Agent
from secagents.llm import ChatResult, ToolCall
from secagents.memory import Memory
from secagents.tools import ToolContext


class ScriptedRouter:
    """Stands in for LLMRouter: replays prepared ChatResults and records what the model was shown."""

    def __init__(self, *script):
        self.script, self.seen = list(script), []

    def chat(self, system, messages, tools=None, **kw):
        self.seen.append({"system": system, "messages": [dict(m) for m in messages], "tools": [t["name"] for t in tools or []]})
        return self.script.pop(0) if self.script else ChatResult("(script ended)", provider="stub", model="m")


def says(text, *calls, tokens=10):
    return ChatResult(text, [ToolCall(f"id{i}", n, a) for i, (n, a) in enumerate(calls)], provider="stub", model="m", input_tokens=tokens, output_tokens=0)


@pytest.fixture
def ctx(tmp_path):
    return ToolContext(memory=Memory(tmp_path / "m.db"), workspace="w")


def kinds(events):
    return [e["type"] for e in events]


def test_read_only_tool_runs_without_asking_and_the_answer_comes_back(ctx):
    router = ScriptedRouter(says("", ("lookup_record", {"id": "CVE-2021-44228"})), says("Log4Shell is a JNDI injection."))
    events = list(Agent(ctx, router).send("t", "What is CVE-2021-44228?"))
    assert kinds(events) == ["tool_call", "tool_result", "message"]
    assert events[1]["name"] == "lookup_record" and "log4" in events[1]["text"].lower()
    assert events[2]["text"] == "Log4Shell is a JNDI injection."
    second_call = router.seen[1]["messages"]
    assert [m["role"] for m in second_call] == ["user", "assistant", "tool"]  # the tool result went back to the model


def test_write_tool_pauses_for_approval_then_runs_once_approved(ctx):
    agent = Agent(ctx, ScriptedRouter(says("", ("remember", {"fact": "prod runs nginx"})), says("Saved.")))
    first = list(agent.send("t", "remember prod runs nginx"))
    assert kinds(first) == ["tool_call", "approval"]
    assert first[1]["tool"] == "remember" and agent.pending("t")["arguments"] == {"fact": "prod runs nginx"}
    assert ctx.memory.facts("w") == []  # nothing happened yet
    rest = list(agent.resume("t", True))
    assert kinds(rest) == ["tool_result", "message"] and rest[0]["denied"] is False
    assert [f["text"] for f in ctx.memory.facts("w")] == ["prod runs nginx"]
    assert agent.pending("t") is None


def test_denied_action_does_not_run_and_the_model_is_told(ctx):
    router = ScriptedRouter(says("", ("remember", {"fact": "x y z"})), says("Understood, not saved."))
    agent = Agent(ctx, router)
    list(agent.send("t", "save it"))
    rest = list(agent.resume("t", False))
    assert rest[0]["denied"] is True and ctx.memory.facts("w") == []
    assert "denied" in router.seen[1]["messages"][-1]["content"].lower()


def test_several_calls_in_one_turn_resume_without_repeating_earlier_ones(ctx, monkeypatch):
    ran = []
    agent = Agent(ctx, ScriptedRouter(
        says("", ("lookup_record", {"id": "AC-7"}), ("remember", {"fact": "one fact"}), ("remember", {"fact": "two fact"})), says("Done.")))
    monkeypatch.setattr(agent, "run_tool", lambda n, a, c: ran.append((n, json.dumps(a))) or "ok")
    list(agent.send("t", "go"))
    list(agent.resume("t", True))
    list(agent.resume("t", True))
    assert ran == [("lookup_record", '{"id": "AC-7"}'), ("remember", '{"fact": "one fact"}'), ("remember", '{"fact": "two fact"}')]


def test_auto_approve_skips_the_pause(ctx):
    agent = Agent(ctx, ScriptedRouter(says("", ("remember", {"fact": "auto fact"})), says("ok")), auto_approve=True)
    assert "approval" not in kinds(list(agent.send("t", "x")))
    assert ctx.memory.facts("w")


def test_tools_outside_the_allowed_list_are_refused(ctx):
    agent = Agent(ctx, ScriptedRouter(says("", ("run_assessment", {})), says("cannot")), tool_names=["lookup_record"])
    events = list(agent.send("t", "scan"))
    assert "approval" not in kinds(events) and "not available" in events[1]["text"]


def test_step_limit_stops_a_runaway_loop(ctx):
    loop = [says("", ("lookup_record", {"id": "AC-7"})) for _ in range(20)]
    events = list(Agent(ctx, ScriptedRouter(*loop), max_steps=3).send("t", "again and again"))
    assert kinds(events)[-1] == "stopped" and "3 model steps" in events[-1]["text"]
    assert kinds(events).count("tool_call") == 3


def test_token_budget_stops_the_turn(ctx):
    router = ScriptedRouter(says("", ("lookup_record", {"id": "AC-7"}), tokens=500), says("never reached"))
    events = list(Agent(ctx, router, max_tokens=400).send("t", "q"))
    assert kinds(events)[-1] == "stopped" and "token budget" in events[-1]["text"]
    assert len(router.seen) == 1


def test_a_host_can_refuse_further_model_calls(ctx):
    router = ScriptedRouter(says("hi"))
    events = list(Agent(ctx, router, allow=lambda: "Daily limit reached.").send("t", "q"))
    assert events == [{"type": "stopped", "text": "Daily limit reached.", "provider": "", "model": ""}] and router.seen == []


def test_no_model_available_is_a_clear_message(ctx):
    class Dead:
        def chat(self, *a, **k):
            return None

    events = list(Agent(ctx, Dead()).send("t", "hello"))
    assert events[0]["type"] == "stopped" and "No language model" in events[0]["text"]


def test_usage_hook_counts_tokens(ctx):
    used = []
    list(Agent(ctx, ScriptedRouter(says("a", tokens=7)), on_usage=used.append).send("t", "q"))
    assert used == [7]


def test_remembered_facts_reach_the_system_prompt(ctx):
    ctx.memory.remember("Our public web servers run nginx on Ubuntu", "w")
    router = ScriptedRouter(says("ok"))
    list(Agent(ctx, router).send("t", "which web servers do we run?"))
    assert "nginx on Ubuntu" in router.seen[0]["system"]
    assert "No assessment has run yet" in router.seen[0]["system"]


def test_restored_history_seeds_a_new_graph_once(ctx):
    history = [{"role": "user", "content": "earlier question"}, {"role": "assistant", "content": "earlier answer"}]
    router = ScriptedRouter(says("a"), says("b"))
    agent = Agent(ctx, router)
    list(agent.send("t", "follow-up", history=history))
    list(agent.send("t", "and another", history=history))  # already known to the graph: not seeded twice
    assert [m["content"] for m in router.seen[0]["messages"]] == ["earlier question", "earlier answer", "follow-up"]
    assert [m["content"] for m in router.seen[1]["messages"]].count("earlier question") == 1
    assert len(agent.messages("t")) == 6


def test_only_the_chosen_tools_are_offered_to_the_model(ctx):
    router = ScriptedRouter(says("x"))
    list(Agent(ctx, router, tool_names=["lookup_record", "search_knowledge"]).send("t", "q"))
    assert router.seen[0]["tools"] == ["lookup_record", "search_knowledge"]
