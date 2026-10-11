"""Adding the same attack again (a second example, a paste after the example, lines already in the folder) must alert.

The tailer reports an attack once. That is right for a real log that keeps growing, but a test paste is a deliberate
action: if it raised no alert it would look as if pasting did not work.
"""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from secagents.config import settings

APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")
EX = settings.samples_dir / "live_examples"
FILES = ("1_ssh_brute_force_to_compromise.txt", "2_web_attacks.txt", "3_port_scan_and_c2.txt")
ALL = "\n".join(line for f in FILES for line in (EX / f).read_text(encoding="utf-8").strip().splitlines())
SSH = (EX / FILES[0]).read_text(encoding="utf-8").strip().splitlines()


@pytest.fixture
def start(tmp_path):
    saved = settings.live_dir
    state = {"n": 0}

    def make(preload: dict[str, str] | None = None) -> AppTest:
        state["n"] += 1
        folder = tmp_path / f"live_logs_{state['n']}"
        folder.mkdir()
        for name, text in (preload or {}).items():
            (folder / name).write_text(text, encoding="utf-8")
        object.__setattr__(settings, "live_dir", folder)
        at = AppTest.from_file(APP, default_timeout=120).run()
        at.toggle(key="live-0").set_value(True).run()
        return at

    yield make
    object.__setattr__(settings, "live_dir", saved)


def alerts(at):
    a = at.session_state["live"]["alerts"]
    return len(a), sum(1 for x in a if x.get("repeat"))


def add_example(at):
    at.button(key="example-go-0").click().run()
    at.run()


def paste(at, text, target=None):
    if target:
        at.selectbox(key="paste-target-0").set_value(target)
    at.text_area(key="paste-text-0").set_value(text)
    at.button(key="paste-go-0").click().run()
    at.run()


def test_the_first_example_alerts_normally_not_as_a_repeat(start):
    at = start()
    add_example(at)
    assert alerts(at) == (14, 0)


def test_pasting_the_same_lines_after_the_example_alerts_again(start):
    at = start()
    add_example(at)
    paste(at, ALL)
    assert alerts(at) == (28, 14)  # the 14 new ones are the repeats


def test_every_further_paste_alerts_again(start):
    at = start()
    paste(at, ALL)
    paste(at, ALL)
    paste(at, ALL)
    assert alerts(at) == (42, 28)


def test_a_second_example_click_alerts_again(start):
    at = start()
    add_example(at)
    add_example(at)
    assert alerts(at) == (28, 14)


def test_lines_already_in_the_folder_when_live_scan_starts_still_alert_when_added(start):
    """The live folder keeps old test lines between sessions; those become the baseline and used to silence a paste."""
    at = start(preload={"auth.log": "\n".join(SSH) + "\n"})
    assert alerts(at) == (0, 0)  # existing content is the baseline: no alerts at start
    paste(at, "\n".join(SSH), "auth.log")
    assert alerts(at) == (5, 5)


def test_pasting_into_a_fixed_file_alerts_again_too(start):
    at = start()
    paste(at, "\n".join(SSH), "auth.log")
    assert alerts(at) == (5, 0)
    paste(at, "\n".join(SSH), "auth.log")
    assert alerts(at) == (10, 5)


def test_a_new_attack_is_never_alerted_twice(start):
    """A first-time attack goes through the tailer only; the repeat check must not double it."""
    at = start()
    paste(at, "\n".join(SSH))
    paste(at, ALL)  # the SSH attack is a repeat, the web and firewall attacks are new
    total, repeats = alerts(at)
    assert (total, repeats) == (5 + 14, 5)
    ids = [a["id"] for a in at.session_state["live"]["alerts"]]
    assert len(ids) == len(set(ids))


def test_repeated_alerts_are_labelled_in_the_panel(start):
    at = start()
    add_example(at)
    paste(at, ALL)
    shown = " ".join(w.value for w in [*at.main.error, *at.main.warning, *at.main.info])
    assert "added again" in shown


def test_unrelated_old_attacks_are_not_repeated_by_a_different_paste(start):
    at = start()
    paste(at, "\n".join(SSH))
    web_only = "\n".join((EX / FILES[1]).read_text(encoding="utf-8").strip().splitlines())
    paste(at, web_only)
    assert alerts(at) == (5 + 6, 0)  # only the web attacks alert; the SSH ones are not re-announced


def test_clear_starts_the_live_scan_over(start):
    at = start()
    add_example(at)
    assert alerts(at) == (14, 0)
    at.button(key="paste-clear-0").click().run()
    at.run()
    assert "live" not in at.session_state or alerts(at) == (0, 0)  # counters restart from zero
    live = at.session_state["live"]
    assert live["pending"] is False and live["last_run"] == 0.0  # Clear restarts alerts only: no surprise full assessment
    paste(at, ALL)
    assert alerts(at) == (14, 0)  # and the same lines alert as new attacks again, not as repeats
