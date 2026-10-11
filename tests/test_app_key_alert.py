"""The dashboard warns when the selected LLM provider has no API key (typed or in .env)."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from secagents.config import settings
from secagents.llm import get_router

APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")


@pytest.fixture
def no_keys():
    """Pretend .env has no keys and offline mode is not forced; restore everything afterwards."""
    saved = {k: getattr(settings, k) for k in ("offline", "anthropic_api_key", "openai_api_key", "openrouter_api_key")}
    for k in saved:
        object.__setattr__(settings, k, False if k == "offline" else "")  # Settings is frozen, so bypass the guard
    yield
    for k, v in saved.items():
        object.__setattr__(settings, k, v)
    get_router().key_overrides = {}
    get_router().enabled = True


def sidebar_state(at):
    errors = [e.value for e in at.sidebar.error]
    css = [m.value for m in at.sidebar.markdown if "data-baseweb='input'" in m.value]
    return errors, css


def test_missing_key_shows_error_toast_and_highlights_the_box(no_keys):
    at = AppTest.from_file(APP, default_timeout=120).run()
    assert not at.exception
    errors, css = sidebar_state(at)
    assert len(errors) == 1 and "No API key found for openrouter" in errors[0] and "rule-based" in errors[0]
    assert [t.value for t in at.toast] == ["No API key found for openrouter"]
    assert ".st-key-apikey-openrouter-0 div[data-baseweb='input']{border:2px solid #e74c3c" in css[0]  # the box's own CSS class


def test_toast_is_not_repeated_on_every_rerun_but_the_error_stays(no_keys):
    at = AppTest.from_file(APP, default_timeout=120).run()
    at.run()
    assert [t.value for t in at.toast] == []
    errors, css = sidebar_state(at)
    assert errors and css


def test_typing_a_key_clears_the_alert_and_removing_it_brings_it_back(no_keys):
    at = AppTest.from_file(APP, default_timeout=120).run()
    at.text_input(key="apikey-openrouter-0").set_value("sk-or-typed").run()
    errors, css = sidebar_state(at)
    assert errors == [] and css == []
    assert any("using the key you entered" in c.value for c in at.sidebar.caption)
    at.text_input(key="apikey-openrouter-0").set_value("").run()
    errors, css = sidebar_state(at)
    assert errors and css and [t.value for t in at.toast] == ["No API key found for openrouter"]


def test_error_says_which_provider_it_falls_back_to(no_keys):
    at = AppTest.from_file(APP, default_timeout=120).run()
    at.sidebar.selectbox[0].set_value("anthropic").run()
    at.text_input(key="apikey-anthropic-0").set_value("sk-ant-typed").run()
    at.sidebar.selectbox[0].set_value("openrouter").run()
    errors, _ = sidebar_state(at)
    assert "No API key found for openrouter" in errors[0] and "Falling back to anthropic" in errors[0]


def test_env_key_counts_so_there_is_no_alert(no_keys):
    object.__setattr__(settings, "openrouter_api_key", "sk-or-from-env")
    at = AppTest.from_file(APP, default_timeout=120).run()
    errors, css = sidebar_state(at)
    assert errors == [] and css == [] and [t.value for t in at.toast] == []
    assert any("using the key from .env" in c.value for c in at.sidebar.caption)


def test_offline_mode_is_a_choice_not_an_error(no_keys):
    object.__setattr__(settings, "offline", True)
    at = AppTest.from_file(APP, default_timeout=120).run()
    errors, css = sidebar_state(at)
    assert errors == [] and css == [] and [t.value for t in at.toast] == []
