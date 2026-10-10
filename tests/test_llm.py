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
