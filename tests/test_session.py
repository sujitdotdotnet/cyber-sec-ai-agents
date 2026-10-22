"""Per-visitor isolation for public deployments: router/keys, folders, budgets, and thread propagation."""

import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from pathlib import Path

import pytest

from secagents import history, live, session
from secagents.config import settings
from secagents.llm import LLMRouter, get_router
from secagents.session import DailyBudget, activate, deactivate, new_session, workspace_id


@pytest.fixture(autouse=True)
def clean():
    deactivate()
    yield
    deactivate()


def test_without_a_session_everything_is_shared_as_before():
    assert get_router() is get_router()
    assert session.live_dir() == settings.live_dir and session.history_dir() == settings.history_dir


def test_two_visitors_never_share_a_router_or_typed_keys(tmp_path):
    a, b = new_session(LLMRouter(), tmp_path), new_session(LLMRouter(), tmp_path)
    activate(a)
    get_router().key_overrides = {"openai": "alice-key"}
    activate(b)
    assert get_router() is b.router and get_router().key_overrides == {}
    activate(a)
    assert get_router().key_overrides == {"openai": "alice-key"}
    assert a.live_dir != b.live_dir and a.workspace != b.workspace


def test_history_and_live_files_land_in_the_session_folders(tmp_path):
    a, b = new_session(LLMRouter(), tmp_path), new_session(LLMRouter(), tmp_path)
    activate(a)
    sid = history.save({"threat_intel": {"overall_risk": "HIGH"}}, "mine", "demo")
    live.append_log_lines("auth.log", "Jan 10 03:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2")
    assert (a.history_dir / f"{sid}.json").exists() and (a.live_dir / "auth.log").exists()
    activate(b)
    assert history.list_scans() == []
    assert not (b.live_dir / "auth.log").exists()


def test_the_session_reaches_langgraph_worker_threads(tmp_path):
    """Agents run in worker threads: the visitor's router must be what they see, not another visitor's."""
    from secagents.graph import build_graph

    seen = []
    mine = new_session(LLMRouter(), tmp_path)
    activate(mine)
    import secagents.agents.log_monitor as lm

    original = lm.run_log_monitor
    try:
        graph_seen = []

        def spy(state):
            graph_seen.append(get_router())
            return original(state)

        from secagents import agents as agents_pkg

        agents_pkg.AGENTS["log_monitor"] = spy
        build_graph().invoke({"inputs": {"log_paths": []}, "completed": [], "trace": []})
    finally:
        agents_pkg.AGENTS["log_monitor"] = original
    assert graph_seen and all(r is mine.router for r in graph_seen)


def test_budget_blocks_the_shared_key_but_not_a_typed_one(tmp_path):
    from dataclasses import replace

    r = LLMRouter(replace(settings, offline=False, anthropic_api_key="", openrouter_api_key="", openai_api_key="shared"))
    s = new_session(r, tmp_path)
    s.budget.session_cap = 100
    assert r.available_providers() == ["openai"]
    r._spend("openai", 120)
    assert "allowance" in s.budget.blocked() and r.available_providers() == []  # shared key exhausted: rule-based mode
    r.key_overrides = {"openai": "my-own"}
    assert r.available_providers() == ["openai"]  # their own key is their own cost
    before = s.budget.session_used
    r._spend("openai", 50)
    assert s.budget.session_used == before  # and is not charged to the host


def test_daily_cap_is_shared_across_sessions_and_resets_each_day(tmp_path):
    f = tmp_path / "usage.json"
    a, b = DailyBudget(f, 1000, 150), DailyBudget(f, 1000, 150)
    a.spend(100)
    assert b.blocked() is None
    b.spend(60)
    assert "today's limit" in a.blocked()
    f.write_text('{"day": "2000-01-01", "tokens": 999999}')
    assert a.blocked() is None  # a new day starts again


def test_workspace_codes_are_stable_and_distinct():
    assert workspace_id("my secret code") == workspace_id(" my secret code ")
    assert workspace_id("a-code-1") != workspace_id("a-code-2")
    assert workspace_id("x").startswith("ws-")


def test_stale_session_folders_are_swept(tmp_path):
    import os, time

    old = tmp_path / "olddir"
    old.mkdir()
    os.utime(old, (time.time() - 3 * 86400,) * 2)
    new_session(LLMRouter(), tmp_path)
    assert not old.exists()
