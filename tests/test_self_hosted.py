"""Self-hosted model option: a model server of your own, and a mode where nothing is sent to anyone else."""

from dataclasses import replace
from types import SimpleNamespace as NS

import pytest

from secagents.config import Settings, settings
from secagents.llm import LLMRouter
from secagents.rag.store import KnowledgeBase

URL = "http://localhost:11434/v1"


def cfg(monkeypatch, **env):
    for name in ("LLM_PROVIDER_ORDER", "LOCAL_LLM_BASE_URL", "LOCAL_LLM_MODEL", "LOCAL_LLM_API_KEY", "SELF_HOSTED_ONLY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings()


def test_nothing_changes_without_a_local_model(monkeypatch):
    assert cfg(monkeypatch).provider_order == ("openrouter", "anthropic", "openai")


def test_a_configured_local_model_is_offered_as_the_last_fallback(monkeypatch):
    c = cfg(monkeypatch, LOCAL_LLM_BASE_URL=URL, LOCAL_LLM_MODEL="qwen2.5:14b")
    assert c.provider_order == ("openrouter", "anthropic", "openai", "local") and c.local_llm_model == "qwen2.5:14b"


def test_an_explicit_order_is_respected_including_putting_the_local_model_first(monkeypatch):
    assert cfg(monkeypatch, LOCAL_LLM_BASE_URL=URL, LLM_PROVIDER_ORDER="local,openai").provider_order == ("local", "openai")
    assert cfg(monkeypatch, LOCAL_LLM_BASE_URL=URL, LLM_PROVIDER_ORDER="openai").provider_order == ("openai", "local")


def test_self_hosted_only_leaves_the_local_model_as_the_only_provider(monkeypatch):
    c = cfg(monkeypatch, SELF_HOSTED_ONLY="1", LOCAL_LLM_BASE_URL=URL, LLM_PROVIDER_ORDER="openai,anthropic")
    assert c.provider_order == ("local",) and c.self_hosted_only is True


class Stub:
    def __init__(self):
        self.sent = []
        reply = NS(choices=[NS(message=NS(content="local answer", tool_calls=None))], usage=NS(prompt_tokens=3, completion_tokens=2))
        self.chat = NS(completions=NS(create=lambda **kw: (self.sent.append(kw), reply)[1]))


def local_router(monkeypatch, **extra):
    c = replace(cfg(monkeypatch, LOCAL_LLM_BASE_URL=URL, LOCAL_LLM_MODEL="llama3.1"), offline=False, **extra)
    router = LLMRouter(c)
    return router, Stub()


def test_the_local_model_needs_no_key_and_is_a_normal_provider(monkeypatch):
    router, stub = local_router(monkeypatch, anthropic_api_key="", openai_api_key="", openrouter_api_key="")
    router._client = lambda provider: stub
    assert router.available_providers() == ["local"] and router.key_source("local") == ".env" and router.model_for("local") == "llama3.1"
    res = router.complete("sys", "hello")
    assert res.text == "local answer" and res.provider == "local"
    sent = stub.sent[0]
    assert sent["model"] == "llama3.1" and "max_tokens" in sent and "max_completion_tokens" not in sent  # the classic parameter local servers expect


def test_the_client_talks_to_your_server_not_to_a_cloud(monkeypatch):
    created = []
    monkeypatch.setattr("openai.OpenAI", lambda **kw: created.append(kw) or object())
    router, _ = local_router(monkeypatch, local_llm_api_key="")
    router._client("local")
    assert created == [{"api_key": "not-needed", "base_url": URL}]
    router2, _ = local_router(monkeypatch, local_llm_api_key="my-gateway-key")
    router2._clients.clear()
    router2._client("local")
    assert created[-1] == {"api_key": "my-gateway-key", "base_url": URL}


def test_without_a_base_url_the_local_provider_is_never_available(monkeypatch):
    router = LLMRouter(replace(cfg(monkeypatch, LLM_PROVIDER_ORDER="local,openai"), offline=False, openai_api_key="", anthropic_api_key="", openrouter_api_key=""))
    assert router.available_providers() == [] and router.key_source("local") == "none"


def test_self_hosted_only_never_uses_a_cloud_provider_even_with_keys_typed_in(monkeypatch):
    c = replace(cfg(monkeypatch, SELF_HOSTED_ONLY="1", LOCAL_LLM_BASE_URL=URL), offline=False,
                openai_api_key="sk-cloud", anthropic_api_key="sk-ant", openrouter_api_key="sk-or")
    router = LLMRouter(c)
    router.key_overrides = {"openai": "typed", "anthropic": "typed"}
    router.preferred = "openai"
    assert router.available_providers() == ["local"]
    stub = Stub()
    router._client = lambda provider: (_ for _ in ()).throw(AssertionError(f"{provider} must not be contacted")) if provider != "local" else stub
    assert router.complete("s", "p").provider == "local"


def test_self_hosted_only_also_keeps_embeddings_local(monkeypatch):
    base = cfg(monkeypatch)
    online = KnowledgeBase(replace(base, openai_api_key="", offline=False), persist=False)
    assert online.backend == "hash"  # no key: local embeddings anyway
    sealed = replace(base, self_hosted_only=True, offline=False, openai_api_key="sk-cloud")
    kb = KnowledgeBase(sealed, persist=False)
    assert kb.backend == "hash"
    kb.use_key("sk-another")  # typing a key in the sidebar must not switch the embeddings to OpenAI
    assert kb.backend == "hash"
