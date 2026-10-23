"""One version number (the VERSION file) shown in every title, the footer, the reports and the CLI."""

import subprocess
import sys
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from secagents import version
from secagents.config import settings
from secagents.graph import run
from secagents.report import build_report

APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def vfile(tmp_path, monkeypatch):
    f = tmp_path / "VERSION"
    f.write_text("2.3.4\n")
    monkeypatch.setattr(version, "VERSION_FILE", f)
    monkeypatch.delenv("APP_VERSION", raising=False)
    return f


def test_the_repository_ships_a_version_file():
    assert (ROOT / "VERSION").read_text().strip().count(".") == 2


def test_title_is_name_plus_version_in_the_requested_format(vfile):
    assert version.get_version() == "2.3.4"
    assert version.app_title() == "Cyber Security AI Agent (v.2.3.4)"


def test_changing_the_file_changes_the_title_without_a_restart(vfile):
    assert "2.3.4" in version.app_title()
    vfile.write_text("3.0.0-beta\n")
    assert version.app_title() == "Cyber Security AI Agent (v.3.0.0-beta)"


def test_a_leading_v_is_ignored_and_a_missing_file_is_harmless(vfile, tmp_path, monkeypatch):
    vfile.write_text("v1.2.0")
    assert version.get_version() == "1.2.0"
    monkeypatch.setattr(version, "VERSION_FILE", tmp_path / "nope")
    assert version.get_version() == "0.0.0"


def test_the_environment_overrides_the_file(vfile, monkeypatch):
    monkeypatch.setenv("APP_VERSION", "9.9.9")
    assert version.app_title().endswith("(v.9.9.9)")


def test_the_dashboard_shows_the_version_in_the_tab_sidebar_title_and_footer(vfile):
    at = AppTest.from_file(APP, default_timeout=120).run()
    assert not at.exception
    want = "Cyber Security AI Agent (v.2.3.4)"
    titles = [t.value for t in at.title]
    assert len(titles) == 2 and all(want in t for t in titles)  # sidebar title and main title
    assert any(want in c.value for c in at.caption)  # footer
    vfile.write_text("2.4.0\n")
    at.run()
    assert all("v.2.4.0" in t.value for t in at.title) and any("v.2.4.0" in c.value for c in at.caption)


def test_the_footer_is_also_there_after_an_assessment(vfile):
    at = AppTest.from_file(APP, default_timeout=200).run()
    at.session_state["result"] = dict(run())
    at.run()
    assert not at.exception and len(at.tabs) >= 9  # the full dashboard, not the welcome page
    assert any("Cyber Security AI Agent (v.2.3.4)" in c.value for c in at.caption)  # footer
    assert all("v.2.3.4" in t.value for t in at.title)


def test_the_sign_in_page_shows_it_too(vfile):
    object.__setattr__(settings, "public", True)
    try:
        at = AppTest.from_file(APP, default_timeout=120).run()
        assert any("Cyber Security AI Agent (v.2.3.4)" in t.value for t in at.title)
        assert any("v.2.3.4" in c.value for c in at.caption)
    finally:
        object.__setattr__(settings, "public", False)


def test_reports_say_which_version_made_them(vfile):
    assert "SecAgents v.2.3.4" in build_report(dict(run()))


def test_cli_version_flag():
    out = subprocess.run([sys.executable, "-m", "secagents", "--version"], capture_output=True, text=True, cwd=ROOT, check=True).stdout
    assert out.strip() == version.app_title()
