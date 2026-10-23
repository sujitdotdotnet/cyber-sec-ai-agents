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


# ---- token limit parameter, and why a call failed -------------------------------------------------------------
def test_openai_gets_max_completion_tokens_and_openrouter_keeps_max_tokens():
    for provider, wanted, unwanted in (("openai", "max_completion_tokens", "max_tokens"), ("openrouter", "max_tokens", "max_completion_tokens")):
        router = make_router(provider_order=(provider,))
        stub = OpenAIStub(openai_response("hi"))
        wire(router, **{provider: stub})
        router.complete("sys", "prompt", agent="t", max_tokens=123)
        router.chat("sys", HISTORY[:1], TOOLS, max_tokens=456)
        for call, n in zip(stub.sent, (123, 456)):
            assert call[wanted] == n and unwanted not in call


def test_complete_records_why_each_provider_failed_without_leaking_keys():
    router = make_router(provider_order=("openrouter", "openai"))
    wire(router, openrouter=OpenAIStub(error=RuntimeError("402 insufficient credits for key sk-or-v1-abcdef1234567890abcdef")),
         openai=OpenAIStub(error=RuntimeError("400 unsupported parameter: max_tokens")))
    assert router.complete("s", "p") is None
    assert len(router.last_errors) == 2
    assert "402 insufficient credits" in router.last_errors[0] and "sk-or-v1" not in router.last_errors[0]
    assert router.last_errors[1].startswith("openai (") and "unsupported parameter" in router.last_errors[1]
    wire(router, openrouter=OpenAIStub(openai_response("fine")), openai=OpenAIStub(openai_response("x")))
    assert router.complete("s", "p").text == "fine" and router.last_errors == []  # reset on the next call


# ---- Claude call hardening --------------------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code


class ClaudeStub:
    """Records which endpoint was used; the beta endpoint can be made to fail like an account without beta access."""

    def __init__(self, beta_error=None, content=None, stop="end_turn", category=None):
        self.beta_sent, self.plain_sent, self.beta_error = [], [], beta_error
        self.content = content if content is not None else [NS(type="text", text="hello")]
        reply = NS(content=self.content, stop_reason=stop, model="claude-stub", usage=NS(input_tokens=5, output_tokens=3),
                   stop_details=NS(category=category) if category else None)
        self.beta = NS(messages=NS(create=lambda **kw: self._beta(kw, reply)))
        self.messages = NS(create=lambda **kw: (self.plain_sent.append(kw), reply)[1])

    def _beta(self, kw, reply):
        self.beta_sent.append(kw)
        if self.beta_error:
            raise self.beta_error
        return reply


def claude_router(stub):
    router = make_router(provider_order=("anthropic",))
    wire(router, anthropic=stub)
    return router


def test_claude_is_asked_with_the_refusal_fallback_and_a_roomy_token_limit():
    stub = ClaudeStub()
    assert claude_router(stub).complete("s", "p", max_tokens=4000).text == "hello"
    sent = stub.beta_sent[0]
    assert sent["betas"] == ["server-side-fallback-2026-07-01"] and sent["fallbacks"] == "default"
    assert sent["max_tokens"] == 16000  # thinking shares the budget on Opus 5.5, so 4,000 is raised
    claude_router(stub).complete("s", "p", max_tokens=64000)
    assert stub.beta_sent[1]["max_tokens"] == 64000  # a larger request is left alone


def test_an_account_without_the_fallback_beta_still_gets_an_answer():
    for status, message in ((400, "Unexpected value(s) `server-side-fallback-2026-07-01` for the `anthropic-beta` header"),
                            (403, "This organization does not have access to the beta feature"), (404, "fallbacks is not available")):
        stub = ClaudeStub(beta_error=ApiError(status, message))
        res = claude_router(stub).complete("s", "p")
        assert res.text == "hello" and len(stub.plain_sent) == 1
        assert "betas" not in stub.plain_sent[0] and "fallbacks" not in stub.plain_sent[0]
        assert stub.plain_sent[0]["output_config"] == {"effort": settings.claude_effort}  # everything else is unchanged


def test_other_api_errors_are_not_retried_and_are_reported():
    for status, message in ((401, "invalid x-api-key"), (404, "model: claude-opus-5-5 not found"), (429, "rate limited")):
        stub = ClaudeStub(beta_error=ApiError(status, message))
        router = claude_router(stub)
        assert router.complete("s", "p") is None and stub.plain_sent == []
        assert message in router.last_errors[0] and router.last_errors[0].startswith("anthropic (")


def test_a_refusal_names_its_category_and_an_empty_reply_says_why():
    router = claude_router(ClaudeStub(content=[], stop="refusal", category="cyber"))
    assert router.complete("s", "p") is None and "Claude declined the request (cyber)" in router.last_errors[0]
    router = claude_router(ClaudeStub(content=[NS(type="thinking", thinking="...")], stop="max_tokens"))
    assert router.chat("s", HISTORY[:1], TOOLS) is None
    assert "returned no text (stop_reason=max_tokens)" in router.last_errors[0]


def test_a_reply_that_only_calls_a_tool_is_fine():
    router = claude_router(ClaudeStub(content=[NS(type="tool_use", id="tu", name="lookup_cve", input={"id": "CVE-1"})], stop="tool_use"))
    res = router.chat("s", HISTORY[:1], TOOLS)
    assert res.text == "" and res.tool_calls == [ToolCall("tu", "lookup_cve", {"id": "CVE-1"})]
