import pytest
from dataclasses import replace

from secagents.config import settings
from secagents.llm import LLMResult, LLMRouter, parse_json


def make_router(**overrides):
    base = {"offline": False, "anthropic_api_key": "a", "openai_api_key": "o", "openrouter_api_key": "r"}
    cfg = replace(settings, **{**base, **overrides})
    return LLMRouter(cfg)


def test_failover_to_next_provider(monkeypatch):
    router = make_router(provider_order=("anthropic", "openai", "openrouter"))

    def boom(*a, **k):
        raise RuntimeError("Claude declined the request")

    monkeypatch.setattr(router, "_call_anthropic", boom)
    monkeypatch.setattr(router, "_call_openai_compatible", lambda p, *a, **k: LLMResult("ok from " + p, p, "m"))
    res = router.complete("sys", "hi", agent="test")
    assert res.provider == "openai" and res.text == "ok from openai"
    assert router.calls == [{"agent": "test", "provider": "openai", "model": "m"}]


def test_default_order_and_preferred_provider():
    router = make_router(provider_order=("openrouter", "anthropic", "openai"))
    assert router.available_providers() == ["openrouter", "anthropic", "openai"]
    router.preferred = "openai"
    assert router.available_providers() == ["openai", "openrouter", "anthropic"]


def test_provider_order_and_missing_keys():
    router = make_router(provider_order=("openrouter", "anthropic"), anthropic_api_key="")
    assert router.available_providers() == ["openrouter"]


def test_all_providers_fail_returns_none(monkeypatch):
    router = make_router()

    def boom(*a, **k):
        raise RuntimeError("down")

    monkeypatch.setattr(router, "_call_anthropic", boom)
    monkeypatch.setattr(router, "_call_openai_compatible", boom)
    assert router.complete("s", "p") is None


def test_parse_json_variants():
    assert parse_json('{"a": 1}') == {"a": 1}
    assert parse_json('Here you go:\n```json\n{"a": [1, 2]}\n```') == {"a": [1, 2]}
    assert parse_json('Sure! {"relevant": [0]} hope that helps') == {"relevant": [0]}
    assert parse_json("no json here") is None


def test_disabled_router_uses_no_provider():
    router = make_router()
    assert router.available_providers()
    router.enabled = False
    assert router.available_providers() == []
    assert router.complete("sys", "hi") is None  # agents fall back to their rule-based output


def test_typed_key_beats_env_key_and_env_stays_the_fallback():
    router = make_router(provider_order=("openrouter", "anthropic", "openai"))
    assert router.api_key("openrouter") == "r" and router.key_source("openrouter") == ".env"
    router.key_overrides = {"openrouter": "  typed-key  ", "openai": ""}
    assert router.api_key("openrouter") == "typed-key" and router.key_source("openrouter") == "typed"
    assert router.api_key("openai") == "o" and router.key_source("openai") == ".env"  # blank box -> .env
    assert router.api_key("anthropic") == "a"  # providers without an override keep their .env key


def test_typed_key_makes_a_provider_without_env_key_available():
    router = make_router(openrouter_api_key="")
    assert "openrouter" not in router.available_providers() and router.key_source("openrouter") == "none"
    router.key_overrides = {"openrouter": "sk-or-typed"}
    assert router.available_providers()[0] == "openrouter"


def test_client_is_built_with_the_typed_key_and_rebuilt_when_it_changes():
    router = make_router()
    env_client = router._client("openrouter")
    assert env_client.api_key == "r"
    router.key_overrides = {"openrouter": "typed"}
    typed_client = router._client("openrouter")
    assert typed_client.api_key == "typed" and typed_client is not env_client
    router.key_overrides = {}
    assert router._client("openrouter") is env_client  # back to .env: the original client is reused


# ---- embeddings key switching -------------------------------------------------
class _StubOpenAI:
    """Stands in for openai.OpenAI: 'good' keys return 8-dim vectors, anything else raises like a bad key would."""

    calls: list[str] = []

    def __init__(self, api_key: str = "", **_):
        self.api_key = api_key
        _StubOpenAI.calls.append(api_key)
        self.embeddings = self

    def create(self, model, input):  # noqa: A002 - mirrors the SDK signature
        if not self.api_key.startswith("good"):
            raise RuntimeError("401 invalid key")
        from types import SimpleNamespace

        return SimpleNamespace(data=[SimpleNamespace(embedding=[float(len(t) % 7 + i) for i in range(8)]) for t in input])


def make_kb(tmp_path, **overrides):
    from secagents.rag.store import KnowledgeBase

    base = {"offline": False, "openai_api_key": "", "chroma_dir": tmp_path / "chroma"}
    return KnowledgeBase(replace(settings, **{**base, **overrides}))


def test_typed_key_switches_embeddings_to_openai_and_back(tmp_path, monkeypatch):
    import openai

    monkeypatch.setattr(openai, "OpenAI", _StubOpenAI)
    kb = make_kb(tmp_path)
    assert kb.backend == "hash"
    assert kb.use_key("good-typed") is True
    assert kb.backend == "openai"
    assert {c.name for c in kb.client.list_collections()} >= {"cves_hash", "cves_openai", "attack_openai", "controls_openai"}
    assert kb.search("cves", "log4j remote code execution", k=2)  # queries embed with the typed key too
    assert kb.use_key("good-typed") is False  # unchanged key: nothing happens
    assert kb.use_key("") is True and kb.backend == "hash"  # cleared: back to the (empty) .env key -> local


def test_env_key_is_the_fallback_when_nothing_is_typed(tmp_path, monkeypatch):
    import openai

    monkeypatch.setattr(openai, "OpenAI", _StubOpenAI)
    kb = make_kb(tmp_path, openai_api_key="good-env")
    assert kb.backend == "openai" and kb.api_key == "good-env"
    assert kb.use_key("") is False  # blank box keeps using .env
    assert kb.use_key("good-typed") is True and kb.api_key == "good-typed"  # typed beats .env
    assert kb.use_key("   ") is True and kb.api_key == "good-env"  # clearing it returns to .env


def test_bad_typed_key_falls_back_to_local_and_is_not_retried(tmp_path, monkeypatch):
    import openai

    monkeypatch.setattr(openai, "OpenAI", _StubOpenAI)
    kb = make_kb(tmp_path)
    _StubOpenAI.calls.clear()
    kb.use_key("bad-key")
    assert kb.backend == "hash"  # the probe failed, so retrieval keeps working locally
    attempts = len(_StubOpenAI.calls)
    kb.use_key("bad-key")
    kb.use_key("bad-key")
    assert len(_StubOpenAI.calls) == attempts  # no hammering the API on every rerun
    assert kb.search("cves", "log4j", k=1)
    assert kb.use_key("good-after-fix") is True and kb.backend == "openai"  # a corrected key is tried again


def test_offline_flag_wins_over_a_typed_key(tmp_path):
    kb = make_kb(tmp_path, offline=True)
    kb.use_key("good-typed")
    assert kb.backend == "hash"


def test_search_survives_chroma_index_not_ready_and_ranks_identically(tmp_path, monkeypatch):
    """Simulates Chroma's 'hnsw segment ... Nothing found on disk': results must match the normal path."""
    import chromadb.api.models.Collection as chroma_collection

    kb = make_kb(tmp_path)  # local (hash) embeddings
    normal = kb.search("cves", "log4j remote code execution jndi", k=3)

    calls = {"n": 0}

    def not_ready(self, *a, **k):
        calls["n"] += 1
        raise RuntimeError("Error creating hnsw segment reader: Nothing found on disk")

    monkeypatch.setattr(chroma_collection.Collection, "query", not_ready)
    monkeypatch.setattr("secagents.rag.store.time.sleep", lambda s: None)
    fallback = kb.search("cves", "log4j remote code execution jndi", k=3)

    assert calls["n"] == 8  # retried for a few seconds before giving up on the index
    assert [h["id"] for h in fallback] == [h["id"] for h in normal]
    assert [h["score"] for h in fallback] == pytest.approx([h["score"] for h in normal], abs=1e-3)


def test_search_retries_then_succeeds_when_the_index_becomes_ready(tmp_path, monkeypatch):
    import chromadb.api.models.Collection as chroma_collection

    kb = make_kb(tmp_path)
    real_query = chroma_collection.Collection.query
    state = {"n": 0}

    def flaky(self, *a, **k):
        state["n"] += 1
        if state["n"] < 3:
            raise RuntimeError("Nothing found on disk")
        return real_query(self, *a, **k)

    monkeypatch.setattr(chroma_collection.Collection, "query", flaky)
    monkeypatch.setattr("secagents.rag.store.time.sleep", lambda s: None)
    assert kb.search("cves", "log4j", k=2) and state["n"] == 3


def test_embedding_backend_reports_the_backend_about_to_be_used(tmp_path, monkeypatch):
    import openai

    from secagents.rag import store

    monkeypatch.setattr(openai, "OpenAI", _StubOpenAI)
    cfg = replace(settings, offline=False, openai_api_key="", chroma_dir=tmp_path / "chroma")
    monkeypatch.setattr(store, "default_settings", cfg)
    monkeypatch.setattr(store, "_kb", store.KnowledgeBase(cfg))
    monkeypatch.setattr(store, "_typed_key", "")
    assert store.embedding_backend() == "hash"
    store.set_embedding_key("good-typed")
    assert store.embedding_backend() == "openai"  # planned, before any agent run rebuilds the knowledge base
    store.get_kb()
    assert store.embedding_backend() == "openai" and store._kb.backend == "openai"
    store.set_embedding_key("")
    assert store.embedding_backend() == "hash"  # caption flips immediately when the key is cleared
    store.set_embedding_key("bad-key")
    store.get_kb()
    assert store.embedding_backend() == "hash"  # the key failed, so what is really in use is local
