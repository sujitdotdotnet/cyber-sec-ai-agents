"""Model router: one call site for Claude, OpenAI and OpenRouter with automatic failover.

Every agent does its detection deterministically first and uses the LLM for reasoning and
write-ups. If no provider is configured (or all fail) callers get ``None`` and fall back to
their rule-based output, so the pipeline always completes.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from .config import Settings, settings as default_settings

log = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str


@dataclass
class ToolCall:
    """A tool the model asked for. ``arguments`` is already parsed; ``id`` links the result back to the call."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ChatResult:
    """One assistant turn: text, tool calls, or both."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


# Conversation messages use one provider-neutral shape, so a chat can fail over between providers mid-way:
#   {"role": "user", "content": str}
#   {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "arguments"}]}   (tool_calls optional)
#   {"role": "tool", "tool_call_id": str, "name": str, "content": str}
# Tools are {"name", "description", "parameters": <JSON schema>}.


def _scrub(text: str) -> str:
    """Remove anything that looks like an API key from an error message before it is shown."""
    return re.sub(r"(sk-[A-Za-z0-9_\-]{6,}|[A-Za-z0-9_\-]{32,})", "[redacted]", text)


def _call_id(raw: Any) -> str:
    return str(raw) if raw else f"call_{uuid.uuid4().hex[:12]}"


def to_openai_messages(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for m in messages:
        if m["role"] == "assistant" and m.get("tool_calls"):
            out.append({
                "role": "assistant", "content": m.get("content") or None,
                "tool_calls": [{"id": c["id"], "type": "function",
                                "function": {"name": c["name"], "arguments": json.dumps(c.get("arguments") or {})}}
                               for c in m["tool_calls"]],
            })
        elif m["role"] == "tool":
            out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m.get("content", "")})
        else:
            out.append({"role": m["role"], "content": m.get("content", "")})
    return out


def to_anthropic_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Anthropic wants tool results as ``tool_result`` blocks inside a user turn, one turn for consecutive results."""
    out: list[dict[str, Any]] = []
    for m in messages:
        if m["role"] == "tool":
            block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m.get("content", "")}
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        elif m["role"] == "assistant" and m.get("tool_calls"):
            blocks: list[dict[str, Any]] = [{"type": "text", "text": m["content"]}] if m.get("content") else []
            blocks += [{"type": "tool_use", "id": c["id"], "name": c["name"], "input": c.get("arguments") or {}}
                       for c in m["tool_calls"]]
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": m["role"], "content": m.get("content", "")})
    return out


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return {"_unparsed": str(raw)[:500]}  # the tool reports this back to the model, which can retry
    return value if isinstance(value, dict) else {"_unparsed": str(raw)[:500]}


class LLMRouter:
    def __init__(self, cfg: Settings | None = None):
        self.cfg = cfg or default_settings
        self._clients: dict[tuple[str, str], Any] = {}  # (provider, key) -> client, so a changed key gets a new client
        self.calls: list[dict[str, str]] = []  # lightweight trace for the dashboard
        self.preferred: str | None = None  # tried first when set; the rest follow provider_order
        self.enabled = True  # False: skip every provider, so agents use their rule-based output (fast, free)
        self.key_overrides: dict[str, str] = {}  # keys typed in the dashboard; they win over the .env keys
        self.last_errors: list[str] = []  # why each provider failed on the latest chat() call (keys redacted), for the UI
        self.budget: Any = None  # public deployments: an object with blocked() -> str | None and spend(tokens)

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
        capped = self.budget is not None and self.budget.blocked()  # the host's shared keys are used up ...
        return [p for p in self.ordered_providers() if self.api_key(p) and not (capped and self.key_source(p) != "typed")]  # ... a typed key is the visitor's own

    def _spend(self, provider: str, tokens: int) -> None:
        """Charge the host's budget, unless the visitor paid with their own typed key."""
        if self.budget is not None and self.key_source(provider) != "typed":
            self.budget.spend(tokens)

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

    # ---- tool calling ------------------------------------------------------
    def _chat_anthropic(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int) -> ChatResult:
        client = self._client("anthropic")
        extra: dict[str, Any] = {}
        if tools:
            extra["tools"] = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools]
        resp = client.beta.messages.create(
            model=self.cfg.claude_model, max_tokens=max_tokens, system=system, messages=to_anthropic_messages(messages),
            output_config={"effort": self.cfg.claude_effort}, betas=["server-side-fallback-2026-07-01"], fallbacks="default",
            **extra,
        )
        if resp.stop_reason == "refusal":
            raise RuntimeError("Claude declined the request")
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        calls = [ToolCall(_call_id(b.id), b.name, _parse_arguments(b.input)) for b in resp.content if getattr(b, "type", "") == "tool_use"]
        usage = getattr(resp, "usage", None)
        return ChatResult(text, calls, "anthropic", resp.model, getattr(usage, "input_tokens", 0) or 0, getattr(usage, "output_tokens", 0) or 0)

    def _chat_openai_compatible(self, provider: str, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int) -> ChatResult:
        client = self._client(provider)
        model = self.cfg.openai_model if provider == "openai" else self.cfg.openrouter_model
        extra: dict[str, Any] = {}
        if tools:
            extra["tools"] = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}} for t in tools]
        resp = client.chat.completions.create(model=model, max_tokens=max_tokens, messages=to_openai_messages(system, messages), **extra)
        msg = resp.choices[0].message
        calls = [ToolCall(_call_id(c.id), c.function.name, _parse_arguments(c.function.arguments)) for c in (getattr(msg, "tool_calls", None) or [])]
        usage = getattr(resp, "usage", None)
        return ChatResult(msg.content or "", calls, provider, model, getattr(usage, "prompt_tokens", 0) or 0, getattr(usage, "completion_tokens", 0) or 0)

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None, *,
             agent: str = "chat", max_tokens: int = 4000) -> ChatResult | None:
        """One assistant turn with optional tool calling, failing over across providers like ``complete``.

        The conversation uses the neutral message shape described above, so if one provider fails halfway through a
        conversation the next one picks it up with the same history. Returns None when no provider worked.
        """
        self.last_errors = []
        for provider in self.available_providers():
            try:
                result = (self._chat_anthropic(system, messages, tools or [], max_tokens) if provider == "anthropic"
                          else self._chat_openai_compatible(provider, system, messages, tools or [], max_tokens))
                self.calls.append({"agent": agent, "provider": result.provider, "model": result.model,
                                   "tokens": str(result.input_tokens + result.output_tokens)})
                self._spend(provider, result.input_tokens + result.output_tokens)
                return result
            except Exception as exc:  # noqa: BLE001 - any provider failure means "try the next one"
                log.warning("LLM provider %s failed for %s: %s", provider, agent, exc)
                self.last_errors.append(f"{provider} ({self.model_for(provider)}): {_scrub(str(exc))[:300]}")
        return None

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
                self._spend(provider, (len(system) + len(prompt) + len(result.text)) // 4)  # complete() reports no usage: estimate
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
    """The router of the current visitor's session (public deployments), else the shared one."""
    from .session import current_router

    mine = current_router()
    if mine is not None:
        return mine
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router
