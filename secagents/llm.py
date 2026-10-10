"""Model router: one call site for Claude, OpenAI and OpenRouter with automatic failover.

Every agent does its detection deterministically first and uses the LLM for reasoning and
write-ups. If no provider is configured (or all fail) callers get ``None`` and fall back to
their rule-based output, so the pipeline always completes.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from .config import Settings, settings as default_settings

log = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str


class LLMRouter:
    def __init__(self, cfg: Settings | None = None):
        self.cfg = cfg or default_settings
        self._clients: dict[tuple[str, str], Any] = {}  # (provider, key) -> client, so a changed key gets a new client
        self.calls: list[dict[str, str]] = []  # lightweight trace for the dashboard
        self.preferred: str | None = None  # tried first when set; the rest follow provider_order
        self.enabled = True  # False: skip every provider, so agents use their rule-based output (fast, free)
        self.key_overrides: dict[str, str] = {}  # keys typed in the dashboard; they win over the .env keys

    # ---- provider plumbing -------------------------------------------------
    def ordered_providers(self) -> list[str]:
        """Configured fallback order, with the preferred provider moved to the front."""
        order = list(self.cfg.provider_order)
        if self.preferred in order:
            order.remove(self.preferred)
            order.insert(0, self.preferred)
        return order

    def model_for(self, provider: str) -> str:
        """Model configured (via .env) for a provider."""
        return {
            "anthropic": self.cfg.claude_model,
            "openai": self.cfg.openai_model,
            "openrouter": self.cfg.openrouter_model,
        }.get(provider, "")

    def api_key(self, provider: str) -> str:
        """The key to use: one entered in the dashboard first, otherwise the one from .env."""
        typed = self.key_overrides.get(provider, "").strip()
        if typed:
            return typed
        return {
            "anthropic": self.cfg.anthropic_api_key,
            "openai": self.cfg.openai_api_key,
            "openrouter": self.cfg.openrouter_api_key,
        }.get(provider, "")

    def key_source(self, provider: str) -> str:
        """Where api_key() gets its value from: "typed", ".env" or "none" (never the key itself)."""
        if self.key_overrides.get(provider, "").strip():
            return "typed"
        return ".env" if self.api_key(provider) else "none"

    def available_providers(self) -> list[str]:
        if self.cfg.offline or not self.enabled:
            return []
        return [p for p in self.ordered_providers() if self.api_key(p)]

    def _client(self, provider: str):
        key = self.api_key(provider)
        if (provider, key) not in self._clients:
            if provider == "anthropic":
                import anthropic

                client = anthropic.Anthropic(api_key=key)
            elif provider == "openai":
                from openai import OpenAI

                client = OpenAI(api_key=key)
            elif provider == "openrouter":
                from openai import OpenAI

                client = OpenAI(api_key=key, base_url=OPENROUTER_BASE_URL)
            else:
                raise ValueError(f"unknown provider {provider}")
            self._clients[(provider, key)] = client
        return self._clients[(provider, key)]

    def _call_anthropic(self, system: str, prompt: str, max_tokens: int) -> LLMResult:
        client = self._client("anthropic")
        # Opus 5.5 runs adaptive thinking by default; effort is the depth control.
        # fallbacks="default" lets the API re-route a declined request (security content can
        # trip the cyber classifier) to Anthropic's recommended fallback model.
        resp = client.beta.messages.create(
            model=self.cfg.claude_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            output_config={"effort": self.cfg.claude_effort},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if resp.stop_reason == "refusal":
            raise RuntimeError("Claude declined the request")
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return LLMResult(text=text, provider="anthropic", model=resp.model)

    def _call_openai_compatible(self, provider: str, system: str, prompt: str, max_tokens: int) -> LLMResult:
        client = self._client(provider)
        model = self.cfg.openai_model if provider == "openai" else self.cfg.openrouter_model
        resp = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        )
        return LLMResult(text=resp.choices[0].message.content or "", provider=provider, model=model)

    # ---- public API --------------------------------------------------------
    def complete(self, system: str, prompt: str, *, agent: str = "", max_tokens: int = 8000) -> LLMResult | None:
        """Return the first successful completion across providers, or None if none worked."""
        for provider in self.available_providers():
            try:
                if provider == "anthropic":
                    result = self._call_anthropic(system, prompt, max_tokens)
                else:
                    result = self._call_openai_compatible(provider, system, prompt, max_tokens)
                self.calls.append({"agent": agent, "provider": result.provider, "model": result.model})
                return result
            except Exception as exc:  # noqa: BLE001 - any provider failure means "try the next one"
                log.warning("LLM provider %s failed for %s: %s", provider, agent or "call", exc)
        return None

    def complete_json(self, system: str, prompt: str, *, agent: str = "", max_tokens: int = 8000) -> Any | None:
        """Ask for JSON and parse it leniently (strips code fences / surrounding prose)."""
        result = self.complete(
            system + "\n\nRespond with a single valid JSON value and nothing else.",
            prompt,
            agent=agent,
            max_tokens=max_tokens,
        )
        return parse_json(result.text) if result else None


def parse_json(text: str) -> Any | None:
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start, end = text.find(open_ch), text.rfind(close_ch)
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    return None


_router: LLMRouter | None = None


def get_router() -> LLMRouter:
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router
