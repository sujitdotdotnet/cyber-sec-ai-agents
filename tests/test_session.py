"""Per-visitor isolation for public deployments: router/keys, folders, scan history, and thread propagation."""

import os
import time
from dataclasses import replace

import pytest

from secagents import history, identity, live, session
from secagents.config import settings
from secagents.db import Db
from secagents.llm import LLMRouter, get_router
from secagents.session import activate, deactivate, new_session


@pytest.fixture(autouse=True)
def clean():
    deactivate()
    yield
    deactivate()


@pytest.fixture
def db(tmp_path):
    return Db(tmp_path / "app.db")


def make(tmp_path, db, who=None):
    return new_session(LLMRouter(), who, tmp_path / "sessions", db)


def test_without_a_session_everything_is_shared_as_before():
    assert get_router() is get_router()
    assert session.live_dir() == settings.live_dir and session.history_dir() == settings.history_dir
    assert session.scan_store() is None


def test_two_visitors_never_share_a_router_or_typed_keys(tmp_path, db):
    a, b = make(tmp_path, db), make(tmp_path, db)
    activate(a)
    get_router().key_overrides = {"openai": "alice-key"}
    activate(b)
    assert get_router() is b.router and get_router().key_overrides == {}
    activate(a)
    assert get_router().key_overrides == {"openai": "alice-key"}
    assert a.live_dir != b.live_dir and a.workspace != b.workspace


def test_guest_history_and_live_files_land_in_the_session_folders(tmp_path, db):
    a, b = make(tmp_path, db), make(tmp_path, db)
    activate(a)
    sid = history.save({"threat_intel": {"overall_risk": "HIGH"}}, "mine", "demo")
    live.append_log_lines("auth.log", "Jan 10 03:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2")
    assert (a.history_dir / f"{sid}.json").exists() and (a.live_dir / "auth.log").exists()
    activate(b)
    assert history.list_scans() == [] and not (b.live_dir / "auth.log").exists()


def test_signed_in_history_lives_in_the_database_and_follows_the_user(tmp_path, db):
    me = identity.user("sub-123", "me@example.com")
    first = make(tmp_path, db, me)
    activate(first)
    sid = history.save({"threat_intel": {"overall_risk": "HIGH"}, "incident_plan": {"incidents": [1, 2]}}, "weekly", "demo")
    assert not list((first.history_dir).glob("*.json")) if first.history_dir.exists() else True
    # a brand-new session (another device, or after a restart of the host) of the same user sees it
    second = make(tmp_path, db, identity.user("sub-123", "me@example.com"))
    activate(second)
    [scan] = history.list_scans()
    assert scan["id"] == sid and scan["name"] == "weekly" and scan["incidents"] == 2 and scan["risk"] == "HIGH"
    assert history.load(sid)["result"]["threat_intel"]["overall_risk"] == "HIGH"
    history.rename(sid, "renamed")
    assert history.list_scans()[0]["name"] == "renamed"
    # someone else cannot read, rename or delete it
    activate(make(tmp_path, db, identity.user("other", "x@example.com")))
    assert history.list_scans() == []
    with pytest.raises(FileNotFoundError):
        history.load(sid)
    history.delete(sid)
    activate(second)
    assert len(history.list_scans()) == 1
    history.delete(sid)
    assert history.list_scans() == []


def test_the_session_reaches_langgraph_worker_threads(tmp_path, db):
    """Agents run through LangGraph: the visitor's router must be what they see, not another visitor's."""
    from secagents import agents as agents_pkg
    from secagents.graph import build_graph

    mine = make(tmp_path, db)
    activate(mine)
    original, seen = agents_pkg.AGENTS["log_monitor"], []

    def spy(state):
        seen.append(get_router())
        return original(state)

    agents_pkg.AGENTS["log_monitor"] = spy
    try:
        build_graph().invoke({"inputs": {"log_paths": []}, "completed": [], "trace": []})
    finally:
        agents_pkg.AGENTS["log_monitor"] = original
    assert seen and all(r is mine.router for r in seen)


def test_budget_blocks_the_shared_key_but_not_a_typed_one(tmp_path, db, monkeypatch):
    monkeypatch.setattr(session, "settings", replace(settings, session_token_cap=100))
    monkeypatch.setattr("secagents.limits.settings", replace(settings, session_token_cap=100))
    r = LLMRouter(replace(settings, offline=False, anthropic_api_key="", openrouter_api_key="", openai_api_key="shared"))
    s = new_session(r, None, tmp_path / "s", db)
    assert r.available_providers() == ["openai"]
    r._spend("openai", 120)
    assert "allowance" in s.allowance.blocked() and r.available_providers() == []  # shared key used up: rule-based mode
    r.key_overrides = {"openai": "my-own"}
    assert r.available_providers() == ["openai"]  # their own key is their own cost
    before = s.allowance.session_used
    r._spend("openai", 50)
    assert s.allowance.session_used == before  # and is not charged to the host


def test_stale_session_folders_are_swept(tmp_path, db):
    base = tmp_path / "sessions"
    old = base / "olddir"
    old.mkdir(parents=True)
    os.utime(old, (time.time() - 3 * 86400,) * 2)
    new_session(LLMRouter(), None, base, db)
    assert not old.exists()
