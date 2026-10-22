"""Tool-calling through the model router: one neutral conversation format, Anthropic and OpenAI-style providers."""

import json
from dataclasses import replace
from types import SimpleNamespace as NS

import pytest

from secagents.config import settings
from secagents.llm import LLMRouter, ToolCall, to_anthropic_messages, to_openai_messages

TOOLS = [{"name": "lookup_cve", "description": "Look up a CVE",
          "parameters": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}}]

HISTORY = [
    {"role": "user", "content": "Are we affected by Log4Shell?"},
    {"role": "assistant", "content": "Let me check.", "tool_calls": [
        {"id": "c1", "name": "lookup_cve", "arguments": {"id": "CVE-2021-44228"}},
        {"id": "c2", "name": "lookup_cve", "arguments": {"id": "CVE-2021-45046"}}]},
    {"role": "tool", "tool_call_id": "c1", "name": "lookup_cve", "content": "log4j-core < 2.15"},
    {"role": "tool", "tool_call_id": "c2", "name": "lookup_cve", "content": "log4j-core < 2.16"},
]


def make_router(**overrides):
    base = {"offline": False, "anthropic_api_key": "a", "openai_api_key": "o", "openrouter_api_key": "r",
            "provider_order": ("openrouter", "anthropic", "openai")}
    return LLMRouter(replace(settings, **{**base, **overrides}))


def openai_response(content="", calls=(), pt=11, ct=7):
    tool_calls = [NS(id=i, function=NS(name=n, arguments=a)) for i, n, a in calls] or None
    return NS(choices=[NS(message=NS(content=content, tool_calls=tool_calls))], usage=NS(prompt_tokens=pt, completion_tokens=ct))


class OpenAIStub:
    def __init__(self, response=None, error=None):
        self.sent, self.response, self.error = [], response, error
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kw):
        self.sent.append(kw)
        if self.error:
            raise self.error
        return self.response


class AnthropicStub:
    def __init__(self, blocks, stop="end_turn"):
        self.sent = []
        self.beta = NS(messages=NS(create=lambda **kw: (self.sent.append(kw), NS(
            content=blocks, stop_reason=stop, model="claude-stub", usage=NS(input_tokens=5, output_tokens=3)))[1]))


def wire(router, **clients):
    router._client = lambda provider: clients[provider]


# ---- message conversion ----------------------------------------------------------------------------
def test_openai_conversion_keeps_ids_and_serialises_arguments():
    out = to_openai_messages("sys", HISTORY)
    assert out[0] == {"role": "system", "content": "sys"}
    assistant = out[2]
    assert assistant["tool_calls"][0]["function"]["name"] == "lookup_cve"
    assert json.loads(assistant["tool_calls"][0]["function"]["arguments"]) == {"id": "CVE-2021-44228"}  # a JSON string, as OpenAI wants
    assert out[3] == {"role": "tool", "tool_call_id": "c1", "content": "log4j-core < 2.15"}
    assert out[4]["tool_call_id"] == "c2"


def test_anthropic_conversion_merges_results_into_one_user_turn():
    out = to_anthropic_messages(HISTORY)
    assert [m["role"] for m in out] == ["user", "assistant", "user"]  # both tool results share one user turn
    assert out[1]["content"][0] == {"type": "text", "text": "Let me check."}
    assert [b["type"] for b in out[1]["content"]] == ["text", "tool_use", "tool_use"]
    assert out[1]["content"][1]["input"] == {"id": "CVE-2021-44228"}
    results = out[2]["content"]
    assert [(b["type"], b["tool_use_id"]) for b in results] == [("tool_result", "c1"), ("tool_result", "c2")]


def test_assistant_turn_without_text_has_no_empty_text_block():
    out = to_anthropic_messages([{"role": "assistant", "content": "", "tool_calls": [{"id": "x", "name": "t", "arguments": {}}]}])
    assert [b["type"] for b in out[0]["content"]] == ["tool_use"]
    assert to_openai_messages("s", [{"role": "assistant", "content": "", "tool_calls": [{"id": "x", "name": "t", "arguments": {}}]}])[1]["content"] is None


# ---- chat() --------------------------------------------------------------------------------------------
def test_openai_style_chat_returns_parsed_tool_calls():
    router = make_router()
    stub = OpenAIStub(openai_response("", [("call_9", "lookup_cve", '{"id": "CVE-2021-44228"}')]))
    wire(router, openrouter=stub)
    res = router.chat("sys", HISTORY[:1], TOOLS, agent="t")
    assert res.tool_calls == [ToolCall("call_9", "lookup_cve", {"id": "CVE-2021-44228"})]
    assert (res.provider, res.input_tokens, res.output_tokens) == ("openrouter", 11, 7)
    sent = stub.sent[0]
    assert sent["tools"][0]["function"]["name"] == "lookup_cve" and sent["tools"][0]["type"] == "function"
    assert sent["messages"][0]["role"] == "system"
    assert router.calls[-1] == {"agent": "t", "provider": "openrouter", "model": router.cfg.openrouter_model, "tokens": "18"}


def test_anthropic_chat_sends_input_schema_and_parses_tool_use():
    router = make_router(provider_order=("anthropic",))
    blocks = [NS(type="text", text="Checking"), NS(type="tool_use", id="tu_1", name="lookup_cve", input={"id": "CVE-1"})]
    stub = AnthropicStub(blocks, stop="tool_use")
    wire(router, anthropic=stub)
    res = router.chat("sys", HISTORY[:1], TOOLS)
    assert res.text == "Checking" and res.tool_calls == [ToolCall("tu_1", "lookup_cve", {"id": "CVE-1"})]
    sent = stub.sent[0]
    assert sent["tools"] == [{"name": "lookup_cve", "description": "Look up a CVE", "input_schema": TOOLS[0]["parameters"]}]
    assert sent["system"] == "sys" and sent["messages"][0] == {"role": "user", "content": "Are we affected by Log4Shell?"}


def test_no_tools_means_no_tools_argument():
    router = make_router(provider_order=("openai",))
    stub = OpenAIStub(openai_response("Hello"))
    wire(router, openai=stub)
    assert router.chat("sys", HISTORY[:1]).text == "Hello"
    assert "tools" not in stub.sent[0]


def test_failover_keeps_the_whole_conversation():
    router = make_router(provider_order=("openrouter", "anthropic"))
    bad = OpenAIStub(error=RuntimeError("402 no credits"))
    good = AnthropicStub([NS(type="text", text="Yes, upgrade log4j.")])
    wire(router, openrouter=bad, anthropic=good)
    res = router.chat("sys", HISTORY, TOOLS)
    assert res.provider == "anthropic" and res.text == "Yes, upgrade log4j."
    assert len(bad.sent) == 1
    roles = [m["role"] for m in good.sent[0]["messages"]]
    assert roles == ["user", "assistant", "user"]  # the tool exchange reached the second provider intact


def test_unparseable_arguments_are_reported_not_crashed():
    router = make_router(provider_order=("openai",))
    wire(router, openai=OpenAIStub(openai_response("", [("c", "lookup_cve", "{not json")])))
    call = router.chat("s", HISTORY[:1], TOOLS).tool_calls[0]
    assert call.arguments == {"_unparsed": "{not json"}


def test_missing_tool_call_id_is_generated():
    router = make_router(provider_order=("openai",))
    wire(router, openai=OpenAIStub(openai_response("", [(None, "lookup_cve", "{}")])))
    assert router.chat("s", HISTORY[:1], TOOLS).tool_calls[0].id.startswith("call_")


def test_chat_returns_none_without_a_working_provider():
    assert make_router(anthropic_api_key="", openai_api_key="", openrouter_api_key="").chat("s", HISTORY[:1]) is None
    router = make_router(provider_order=("openai",))
    wire(router, openai=OpenAIStub(error=RuntimeError("down")))
    assert router.chat("s", HISTORY[:1]) is None


def test_chat_respects_the_enabled_switch_and_typed_keys():
    router = make_router(anthropic_api_key="", openai_api_key="", openrouter_api_key="")
    router.key_overrides = {"openai": "typed"}
    router.preferred = "openai"
    wire(router, openai=OpenAIStub(openai_response("typed key works")))
    assert router.chat("s", HISTORY[:1]).text == "typed key works"
    router.enabled = False
    assert router.chat("s", HISTORY[:1]) is None
