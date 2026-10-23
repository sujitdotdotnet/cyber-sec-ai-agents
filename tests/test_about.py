"""The About panel above the footer: collapsed by default, same text as the README, on every page."""

import re
from pathlib import Path

from streamlit.testing.v1 import AppTest

from secagents.about import ABOUT_MD, ABOUT_TITLE
from secagents.config import settings
from secagents.graph import run

ROOT = Path(__file__).resolve().parent.parent
APP = str(ROOT / "app" / "streamlit_app.py")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_about_text_matches_the_readme_overview_and_agents_table():
    start, end = README.index("## Overview:"), README.index('<img width="1912"')
    readme = re.sub(r"\n{3,}", "\n\n", README[start:end].replace("## Overview:", "### Overview")).strip()
    assert ABOUT_MD.strip() == readme  # word for word: edit the README and about.py together


def test_about_has_the_overview_sections_and_all_five_agents():
    for heading in ("**What it is:**", "**How it works:**", "**What you get:**", "**Real-time:**", "**Where it runs:**"):
        assert heading in ABOUT_MD
    assert "| Agent | What it does |" in ABOUT_MD
    for agent in ("Log Monitor", "Vulnerability Scanner", "Threat Intelligence", "Incident Response", "Policy Checker"):
        assert f"**{agent}**" in ABOUT_MD
    assert "74 tests" not in ABOUT_MD  # no hard-coded test count to go stale


def panel(at):
    return [e for e in at.expander if e.label == ABOUT_TITLE]


def test_the_panel_is_collapsed_by_default_and_sits_above_the_footer():
    at = AppTest.from_file(APP, default_timeout=120).run()
    assert not at.exception
    [p] = panel(at)
    assert p.proto.expanded is False
    assert "What it is:" in " ".join(m.value for m in p.markdown) and "Agent | What it does" in " ".join(m.value for m in p.markdown)
    assert any("Cyber Security AI Agent (v." in c.value for c in at.caption)  # the footer line is still there


def test_the_panel_is_there_after_an_assessment_too():
    at = AppTest.from_file(APP, default_timeout=200).run()
    at.session_state["result"] = dict(run())
    at.run()
    assert not at.exception and len(panel(at)) == 1 and panel(at)[0].proto.expanded is False


def test_the_panel_is_on_the_sign_in_page_too():
    object.__setattr__(settings, "public", True)
    try:
        at = AppTest.from_file(APP, default_timeout=120).run()
        assert len(panel(at)) == 1 and panel(at)[0].proto.expanded is False
    finally:
        object.__setattr__(settings, "public", False)
