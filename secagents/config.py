"""Central settings, read once from the environment (and an optional .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY"))
    openai_api_key: str = field(default_factory=lambda: _env("OPENAI_API_KEY"))
    openrouter_api_key: str = field(default_factory=lambda: _env("OPENROUTER_API_KEY"))

    # Order in which providers are tried; a provider without a key is skipped.
    provider_order: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            p.strip() for p in _env("LLM_PROVIDER_ORDER", "openrouter,anthropic,openai").split(",") if p.strip()
        )
    )
    claude_model: str = field(default_factory=lambda: _env("CLAUDE_MODEL", "claude-opus-5-5"))
    claude_effort: str = field(default_factory=lambda: _env("CLAUDE_EFFORT", "medium"))
    openai_model: str = field(default_factory=lambda: _env("OPENAI_MODEL", "gpt-4.1-mini"))
    openrouter_model: str = field(default_factory=lambda: _env("OPENROUTER_MODEL", "anthropic/claude-sonnet-4.5"))
    embedding_model: str = field(default_factory=lambda: _env("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small"))

    # Set SECAGENTS_OFFLINE=1 to force rule-based mode (no LLM or embedding calls).
    offline: bool = field(default_factory=lambda: _env("SECAGENTS_OFFLINE") in {"1", "true", "yes"})

    knowledge_dir: Path = ROOT / "knowledge"
    samples_dir: Path = ROOT / "samples"
    chroma_dir: Path = field(default_factory=lambda: Path(_env("CHROMA_DIR", str(ROOT / ".chroma"))))
    live_dir: Path = field(default_factory=lambda: Path(_env("LIVE_LOGS_DIR", str(ROOT / "live_logs"))))
    history_dir: Path = field(default_factory=lambda: Path(_env("HISTORY_DIR", str(ROOT / ".history"))))

    # Agent: memory file, MCP servers file, per-turn limits.
    memory_db: Path = field(default_factory=lambda: Path(_env("MEMORY_DB", str(ROOT / ".memory" / "memory.db"))))
    mcp_config: Path = field(default_factory=lambda: Path(_env("MCP_CONFIG", str(ROOT / "mcp_servers.json"))))
    agent_max_steps: int = field(default_factory=lambda: int(_env("AGENT_MAX_STEPS", "6") or 6))
    agent_turn_tokens: int = field(default_factory=lambda: int(_env("AGENT_TURN_TOKENS", "40000") or 40000))

    # Public deployment (Streamlit Community Cloud): no local paths, per-visitor isolation, a daily model-token cap.
    public: bool = field(default_factory=lambda: _env("SECAGENTS_PUBLIC") in {"1", "true", "yes"})
    daily_token_cap: int = field(default_factory=lambda: int(_env("DAILY_TOKEN_CAP", "300000") or 300000))
    session_token_cap: int = field(default_factory=lambda: int(_env("SESSION_TOKEN_CAP", "60000") or 60000))

    @property
    def has_any_llm(self) -> bool:
        return not self.offline and any(
            [self.anthropic_api_key, self.openai_api_key, self.openrouter_api_key]
        )


settings = Settings()
