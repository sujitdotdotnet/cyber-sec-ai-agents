"""The Agent tab in the real app (Streamlit AppTest) with a scripted model: chat, tools, approvals, memory, public mode."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from secagents.config import settings
from secagents.llm import ChatResult, LLMRouter, ToolCall
from secagents.memory import Memory

APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")


@pytest.fixture
def model(monkeypatch, tmp_path):
    """Script the model's replies; every test starts from an empty memory file and a temporary live/history folder."""
    script: list[ChatResult] = []
    seen: list[dict] = []

    def chat(self, system, messages, tools=None, **kw):
        seen.append({"system": system, "n": len(messages), "tools": [t["name"] for t in tools or []]})
        return script.pop(0) if script else ChatResult("(no more script)", provider="stub", model="stub-1")

    monkeypatch.setattr(LLMRouter, "chat", chat)
    monkeypatch.setattr(LLMRouter, "available_providers", lambda self: ["stub"])
    saved = {k: getattr(settings, k) for k in ("memory_db", "history_dir", "live_dir", "public")}
    object.__setattr__(settings, "memory_db", tmp_path / "memory.db")
    object.__setattr__(settings, "history_dir", tmp_path / "history")
    object.__setattr__(settings, "live_dir", tmp_path / "live")
    yield script, seen
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


def says(text, *calls):
    return ChatResult(text, [ToolCall(f"c{i}", n, a) for i, (n, a) in enumerate(calls)], provider="stub", model="stub-1", input_tokens=5)


def start() -> AppTest:
    return AppTest.from_file(APP, default_timeout=120).run()


def texts(at):
    return " ".join(m.value for m in [*at.markdown, *at.warning, *at.caption, *at.code])


def test_agent_tab_is_there_before_any_assessment(model):
    at = start()
    assert not at.exception
    assert any(t.label == "🤖 Agent" for t in at.tabs)
    assert at.chat_input(key="agent-input-0")  # usable without running an assessment


def test_a_question_uses_a_read_only_tool_and_shows_the_answer(model):
    script, seen = model
    script += [says("", ("lookup_record", {"id": "CVE-2021-44228"})), says("Log4Shell is a JNDI injection flaw.")]
    at = start()
    at.chat_input(key="agent-input-0").set_value("What is CVE-2021-44228?").run()
    assert not at.exception
    body = texts(at)
    assert "Log4Shell is a JNDI injection flaw." in body and "lookup_record" in body
    assert seen[0]["tools"] and "run_assessment" in seen[0]["tools"]
    [thread] = Memory(settings.memory_db).threads("default")
    assert thread["title"] == "What is CVE-2021-44228?"
    assert len(Memory(settings.memory_db).messages(thread["id"], "default")) == 4  # user, call, result, answer


def test_write_actions_wait_for_a_click_and_approving_runs_them(model):
    script, _ = model
    script += [says("", ("remember", {"fact": "prod web servers run nginx"})), says("Saved that.")]
    at = start()
    at.chat_input(key="agent-input-0").set_value("remember that prod runs nginx").run()
    assert "Approval needed" in texts(at) and Memory(settings.memory_db).facts("default") == []
    at.button(key="approve-0").click().run()
    assert not at.exception and "Saved that." in texts(at)
    assert [f["text"] for f in Memory(settings.memory_db).facts("default")] == ["prod web servers run nginx"]
    assert not [b for b in at.button if b.key == "approve-0"]  # the card is gone


def test_denying_keeps_the_action_from_running(model):
    script, _ = model
    script += [says("", ("remember", {"fact": "something to save"})), says("Okay, not saved.")]
    at = start()
    at.chat_input(key="agent-input-0").set_value("save it").run()
    at.button(key="deny-0").click().run()
    assert not at.exception and Memory(settings.memory_db).facts("default") == []
    assert "denied" in texts(at)


def test_a_suggestion_button_asks_the_question(model):
    script, _ = model
    script.append(says("Here is the summary."))
    at = start()
    at.button(key="suggest-0-0").click().run()
    assert "Here is the summary." in texts(at)


def test_the_previous_conversation_can_be_reopened(model):
    script, seen = model
    script += [says("first answer"), says("second answer")]
    at = start()
    at.chat_input(key="agent-input-0").set_value("hello there").run()
    again = start()  # a new browser session: the chat comes back from memory
    pick = again.selectbox(key="agent-thread-0")
    pick.set_value(pick.options[1]).run() if len(pick.options) > 1 else None
    assert "first answer" in texts(again)
    again.chat_input(key="agent-input-0").set_value("and a follow-up").run()
    assert seen[-1]["n"] == 3  # the restored history reached the model


def test_remembered_facts_can_be_added_and_forgotten_in_the_panel(model):
    at = start()
    at.text_input(key="fact-0").set_value("we use Okta for SSO").run()
    at.button(key="remember-0").click().run()
    assert [f["text"] for f in Memory(settings.memory_db).facts("default")] == ["we use Okta for SSO"]
    fid = Memory(settings.memory_db).facts("default")[0]["id"]
    at.button(key=f"forget-{fid}-0").click().run()
    assert Memory(settings.memory_db).facts("default") == []


def test_without_a_model_the_chat_is_disabled_with_a_reason(model, monkeypatch):
    monkeypatch.setattr(LLMRouter, "available_providers", lambda self: [])
    at = start()
    assert at.chat_input(key="agent-input-0").disabled
    assert "needs a language model" in texts(at)


def test_the_agent_run_assessment_becomes_the_dashboard_result(model):
    script, _ = model
    script += [says("", ("run_assessment", {})), says("Assessment finished.")]
    at = start()
    at.chat_input(key="agent-input-0").set_value("run it").run()
    at.button(key="approve-0").click().run()
    assert not at.exception
    assert "result" in at.session_state, texts(at)[-1500:]
    assert at.session_state["result"]["threat_intel"]["overall_risk"]
    assert any(t.label == "Overview" for t in at.tabs)  # the full dashboard is now showing


# ---- public deployment: guest or sign in --------------------------------------------------------------
def public_start() -> AppTest:
    object.__setattr__(settings, "public", True)
    return start()


def as_guest() -> AppTest:
    at = public_start()
    at.button(key="gate-guest").click().run()
    return at


def signed_in(monkeypatch, email="me@example.com", sub="sub-1", verified=True):
    from secagents import gate

    monkeypatch.setattr(gate, "login_state", lambda: gate.LoginState(True, sub, email, "Me", verified))


def test_public_site_asks_for_guest_or_sign_in_before_anything_else(model, monkeypatch):
    from secagents import gate

    monkeypatch.setattr(gate, "auth_configured", lambda: False)  # whatever .streamlit/secrets.toml says on this machine
    at = public_start()
    assert not at.exception and at.button(key="gate-guest")
    assert not at.chat_input and not [s for s in at.selectbox if s.key == "provider-0"]  # nothing of the app is reachable yet
    assert any("Sign-in is not set up" in i.value for i in at.info)  # no [auth] secrets: guest only, and it says so


def test_sign_in_button_appears_once_login_is_configured(model, monkeypatch):
    from secagents import gate

    monkeypatch.setattr(gate, "auth_configured", lambda: True)
    at = public_start()
    assert at.button(key="gate-signin") and at.button(key="gate-guest")


def test_guest_gets_a_private_session_with_server_paths_hidden(model):
    one, two = as_guest(), as_guest()
    assert not one.exception
    v1, v2 = one.session_state["visitor"], two.session_state["visitor"]
    assert v1.identity.is_guest and v1.router is not v2.router and v1.workspace != v2.workspace
    assert v1.router.budget is v1.allowance and v1.scan_db is None
    one.radio[0].set_value("Upload my own files").run()
    assert not [b for b in one.button if "Browse" in b.label]
    assert not [c for c in one.checkbox if "automatically" in c.label]  # no auto-approve for strangers
    one.text_input(key="repo-0").set_value(r"C:\Windows").run()
    assert any("disabled on this public site" in e.value for e in one.error)
    assert "Guest" in texts(one)


def test_guest_chat_is_not_kept_after_the_visit(model):
    script, _ = model
    script.append(says("hello guest"))
    at = as_guest()
    at.chat_input(key="agent-input-0").set_value("hi").run()
    assert "hello guest" in texts(at)
    again = as_guest()  # a new visit: nothing saved
    assert again.selectbox(key="agent-thread-0").options == ["➕ New chat"]
    assert Memory(settings.memory_db).threads(again.session_state["visitor"].workspace) == []  # and nothing written to the database


def test_signed_in_user_keeps_chats_memory_and_scans_across_visits(model, monkeypatch):
    script, _ = model
    script.append(says("welcome back"))
    signed_in(monkeypatch)
    at = public_start()
    visitor = at.session_state["visitor"]
    assert not visitor.identity.is_guest and visitor.scan_db is not None
    assert "me@example.com" in texts(at) and any(b.key == "side-logout" for b in at.button)
    at.chat_input(key="agent-input-0").set_value("remember me").run()
    at.text_input(key="fact-0").set_value("we use Okta for SSO").run()
    at.button(key="remember-0").click().run()
    later = start()  # another visit by the same account (a new browser session)
    assert later.session_state["visitor"].workspace == visitor.workspace and later.session_state["visitor"] is not visitor
    assert len(later.selectbox(key="agent-thread-0").options) == 2
    assert [f["text"] for f in Memory(settings.memory_db).facts(visitor.workspace)] == ["we use Okta for SSO"]


def test_two_signed_in_users_never_see_each_others_data(model, monkeypatch):
    script, _ = model
    script.append(says("private answer"))
    signed_in(monkeypatch, "a@example.com", "sub-a")
    a = public_start()
    a.chat_input(key="agent-input-0").set_value("secret question").run()
    signed_in(monkeypatch, "b@example.com", "sub-b")
    b = start()
    assert b.selectbox(key="agent-thread-0").options == ["➕ New chat"] and "secret question" not in texts(b)


def test_an_account_not_on_the_access_list_is_turned_away(model, monkeypatch):
    from dataclasses import replace

    from secagents import identity

    monkeypatch.setattr(identity, "settings", replace(settings, allowed_emails=("boss@example.com",), allowed_email_domains=()))
    signed_in(monkeypatch, "stranger@evil.com")
    at = public_start()
    assert any("access list" in e.value for e in at.error)
    assert not at.chat_input and "visitor" not in at.session_state


def test_an_unverified_email_is_turned_away(model, monkeypatch):
    signed_in(monkeypatch, verified=False)
    at = public_start()
    assert any("not verified" in e.value for e in at.error) and not at.chat_input


def test_the_download_limit_is_enforced_for_github_links(model, monkeypatch):
    from dataclasses import replace

    calls = []
    monkeypatch.setattr("secagents.sources.resolve", lambda *a, **k: calls.append(a))
    monkeypatch.setattr("secagents.limits.settings", replace(settings, guest_daily_downloads=0))
    at = as_guest()
    at.radio[0].set_value("Upload my own files").run()
    at.text_input(key="repo-0").set_value("https://github.com/owner/repo").run()
    assert any("Download limit" in e.value for e in at.error) and calls == []


def test_the_sidebar_says_bring_your_own_key_instead_of_showing_a_counter(model):
    at = as_guest()
    assert "Bring Your Own Key (BYOK)" in texts(at) and "Shared-key tokens today" not in texts(at)
