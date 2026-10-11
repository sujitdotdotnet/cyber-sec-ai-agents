"""Live scan must not look idle: it says which lines it understood, where misplaced ones belong, and what is building up."""

from dataclasses import replace
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from secagents import live
from secagents.agents.log_monitor import line_kind, recognised
from secagents.config import settings
from secagents.live import LogTailer, append_routed, route_lines

EX = settings.samples_dir / "live_examples"
SSH = (EX / "1_ssh_brute_force_to_compromise.txt").read_text().splitlines()
WEB = (EX / "2_web_attacks.txt").read_text().splitlines()
FW = (EX / "3_port_scan_and_c2.txt").read_text().splitlines()
ISO = "2026-10-11 10:00:01 web-01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"


@pytest.fixture
def live_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "settings", replace(settings, live_dir=tmp_path / "live_logs"))
    return tmp_path / "live_logs"


# ---- which parser reads which line -------------------------------------------------------------
def test_line_kind_tells_the_three_log_types_apart():
    assert line_kind(SSH[0]) == "auth" and line_kind(SSH[-1]) == "auth"
    assert line_kind(WEB[0]) == "web"
    assert line_kind(FW[0]) == "firewall"
    assert line_kind(ISO) is None and line_kind("hello world") is None and line_kind("") is None


def test_recognised_follows_the_file_name_routing():
    assert recognised("auth.log", SSH[0]) and not recognised("auth.log", FW[0])  # firewall lines are ignored by the auth parser
    assert recognised("nginx_access.log", WEB[0]) and not recognised("nginx_access.log", SSH[0])
    assert recognised("firewall.log", FW[0]) and not recognised("firewall.log", WEB[0])
    assert recognised("mystery.log", WEB[0]) and not recognised("mystery.log", ISO)  # unknown file: any parser will do


# ---- routing pasted lines by content --------------------------------------------------------------
def test_route_lines_sorts_by_content_and_reports_the_rest():
    routed, ignored = route_lines("\n\n".join([SSH[0], WEB[0], FW[0], "total nonsense", ISO]) + "\r\n")
    assert routed == {"auth.log": [SSH[0]], "nginx_access.log": [WEB[0]], "firewall.log": [FW[0]]}
    assert ignored == ["total nonsense", ISO]


def test_append_routed_writes_each_line_to_its_own_file(live_dir):
    written, ignored = append_routed("\n".join(SSH + WEB + FW + [ISO]))
    assert written == {"auth.log": len(SSH), "nginx_access.log": len(WEB), "firewall.log": len(FW)} and ignored == [ISO]
    assert (live_dir / "auth.log").read_text().splitlines() == SSH
    assert (live_dir / "firewall.log").read_text().splitlines() == FW


def test_pasting_all_examples_with_auto_detect_raises_every_alert(live_dir):
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    append_routed("\n".join(WEB + FW + SSH))  # deliberately mixed up and in no particular order
    assert len(tailer.poll()) == 14


# ---- what the tailer can report ----------------------------------------------------------------------
def test_tailer_counts_understood_lines_per_file(live_dir):
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    live.append_log_lines("auth.log", "\n".join(SSH[:5]))
    tailer.poll()
    assert tailer.read_by_file == {"auth.log": 5} and tailer.recognised_by_file == {"auth.log": 5}
    assert tailer.unrecognised("auth.log") == 0 and not tailer.misfiled


def test_wrong_file_lines_are_counted_and_attributed(live_dir):
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    live.append_log_lines("auth.log", "\n".join(FW[:6] + WEB[:2]))  # firewall + web lines pasted as auth
    tailer.poll()
    assert tailer.recognised_by_file.get("auth.log", 0) == 0 and tailer.unrecognised("auth.log") == 8
    assert dict(tailer.misfiled["auth.log"]) == {"firewall": 6, "web": 2}
    assert tailer.events == []  # which is exactly why nothing was detected


def test_lines_in_no_known_format_are_unrecognised_but_not_misfiled(live_dir):
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    live.append_log_lines("auth.log", ISO)
    tailer.poll()
    assert tailer.unrecognised("auth.log") == 1 and "auth.log" not in tailer.misfiled


def test_blank_lines_are_not_counted_as_unrecognised(live_dir):
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    (live_dir / "auth.log").write_text(SSH[0] + "\n\n\n" + SSH[1] + "\n")
    tailer.poll()
    assert tailer.unrecognised("auth.log") == 0


def test_building_up_reports_progress_towards_a_brute_force_alert(live_dir):
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    live.append_log_lines("auth.log", "\n".join(SSH[:6]))
    assert tailer.poll() == [] and tailer.events == []
    assert tailer.building_up() == ["6 failed SSH logins from 203.0.113.45 so far; a brute-force alert is raised at 10"]
    live.append_log_lines("auth.log", "\n".join(SSH[6:12]))  # now it crosses the threshold and alerts
    assert [e["type"] for e in tailer.poll()][:1] == ["SSH brute force and password spraying"]
    assert tailer.building_up() == []  # nothing left to wait for


def test_recent_lines_keep_the_last_ten_with_their_verdict(live_dir):
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    live.append_log_lines("auth.log", "\n".join(SSH[:12] + [FW[0]]))
    tailer.poll()
    assert len(tailer.recent) == 10 and tailer.recent[-1] == ("auth.log", FW[0], False) and tailer.recent[0][2] is True


# ---- the dashboard: paste box and live panel -------------------------------------------------------------
APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")


@pytest.fixture
def app_live(tmp_path):
    saved = settings.live_dir
    object.__setattr__(settings, "live_dir", tmp_path / "live_logs")
    at = AppTest.from_file(APP, default_timeout=120).run()
    at.toggle(key="live-0").set_value(True).run()
    yield at
    object.__setattr__(settings, "live_dir", saved)


class Messages:
    """What the sidebar showed right after a click. These messages are shown once and gone on the next rerun."""

    def __init__(self, at):
        self.note = " ".join(s.value for s in at.sidebar.success)
        self.warn = " ".join(w.value for w in at.sidebar.warning)


def click(at, key):
    """Press a button, capture what the page shows straight away, then rerun once more so the live panel polls."""
    at.button(key=key).click().run()
    msgs = Messages(at)
    at.run()
    return msgs


def paste(at, target, lines):
    at.selectbox(key="paste-target-0").set_value(target)
    at.text_area(key="paste-text-0").set_value("\n".join(lines))
    return click(at, "paste-go-0")


def page_text(at):
    out = []

    def walk(node):
        for ch in getattr(node, "children", {}).values():
            v = getattr(ch, "value", None)
            if isinstance(v, str):
                out.append(v)
            walk(ch)

    walk(at.main)
    return "\n".join(out)


def test_auto_detect_is_the_default_paste_target(app_live):
    sel = app_live.selectbox(key="paste-target-0")
    assert sel.value.startswith("Auto-detect") and sel.options[0] == sel.value


def test_pasting_everything_with_auto_detect_gives_alerts_like_the_simulation(app_live):
    msgs = paste(app_live, "Auto-detect (recommended)", SSH + WEB + FW)
    assert len(app_live.session_state["live"]["alerts"]) == 14
    assert "16 → auth.log, 8 → nginx_access.log, 14 → firewall.log" in msgs.note


def test_pasting_into_the_wrong_file_warns_in_the_panel_and_the_paste_box(app_live):
    msgs = paste(app_live, "auth.log", FW[:6])
    assert "6 look like firewall.log lines" in msgs.warn
    assert "auth.log: 6 line(s) are ignored. 6 look like firewall.log lines" in page_text(app_live)
    assert app_live.session_state["live"]["alerts"] == []


def test_a_partial_attack_shows_progress_instead_of_silence(app_live):
    paste(app_live, "Auto-detect (recommended)", SSH[:6])
    text = page_text(app_live)
    assert "auth.log: 6 lines, 6 understood" in text
    assert "6 failed SSH logins from 203.0.113.45 so far; a brute-force alert is raised at 10" in text


def test_an_unsupported_format_is_refused_with_the_expected_formats(app_live):
    warn = paste(app_live, "Auto-detect (recommended)", [ISO] * 3).warn
    assert "None of the pasted text looks like log lines" in warn and "Failed password for root" in warn  # and shows real formats
    assert app_live.session_state["live"]["tailer"].lines_read == 0


# ---- ready-made examples, and pasting something that is not log data ---------------------------------------------
def test_example_labels_state_the_real_number_of_lines():
    import re

    for name in live.EXAMPLE_FILES:
        claimed = int(re.search(r"\((\d+) lines\)", name)[1])
        assert len(live.example_text(name).splitlines()) == claimed, name
    claimed = int(re.search(r"\((\d+) lines\)", live.ALL_EXAMPLES)[1])
    assert len(live.example_text(live.ALL_EXAMPLES).splitlines()) == claimed


def test_every_example_line_is_understood_by_some_parser():
    for name in [*live.EXAMPLE_FILES, live.ALL_EXAMPLES]:
        routed, ignored = route_lines(live.example_text(name))
        assert ignored == [] and routed, name


def test_add_example_button_raises_the_alerts(app_live):
    msgs = click(app_live, "example-go-0")
    assert len(app_live.session_state["live"]["alerts"]) == 14  # the default, "all three", is the whole demo
    assert "16 → auth.log, 8 → nginx_access.log, 14 → firewall.log" in msgs.note and "None of the pasted" not in msgs.warn


def test_a_single_example_only_adds_its_own_file(app_live):
    app_live.selectbox(key="example-0").set_value(next(iter(live.EXAMPLE_FILES)))  # the SSH one
    msgs = click(app_live, "example-go-0")
    assert "16 → auth.log" in msgs.note and "nginx" not in msgs.note
    assert len(app_live.session_state["live"]["alerts"]) == 5


def test_pasting_readme_prose_explains_that_it_is_not_log_data(app_live):
    warn = paste(app_live, "Auto-detect (recommended)", ["SSH brute force and password spraying, successful login after brute force, privilege escalation"]).warn
    assert "None of the pasted text looks like log lines" in warn and "Add a ready-made attack" in warn
    assert app_live.session_state["live"]["tailer"].lines_read == 0  # nothing junk reached the log files


# ---- counts are exact, and the live logs can be repaired in place --------------------------------------------------
PROSE_WEB = "SQL injection, path traversal (possibly successful), XSS, command injection, Log4Shell, automated scanner (sqlmap)"
PROSE_FW = "Port scan, large outbound transfer to a suspicious port (reverse shell / exfiltration)"


def test_counts_do_not_drift_after_a_file_is_rewritten(live_dir):
    """The old cumulative counters hid ignored lines once a file had been cleared or rewritten."""
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    f = live_dir / "auth.log"
    f.write_text("\n".join(SSH[:15]) + "\n")
    tailer.poll()
    assert tailer.unrecognised("auth.log") == 0 and tailer.current_by_file["auth.log"] == 15
    f.write_text("\n".join(SSH[:3] + ["some prose that is not a log line"]) + "\n")  # shorter, so the tailer starts over
    tailer.poll()
    assert tailer.current_by_file["auth.log"] == 4 and tailer.recognised_by_file["auth.log"] == 3
    assert tailer.unrecognised("auth.log") == 1  # reported, though 15 good lines were counted earlier
    f.write_text("")
    tailer.poll()
    assert tailer.current_by_file == {} and tailer.unrecognised("auth.log") == 0  # cleared: nothing left to complain about


def test_repair_drops_prose_keeps_good_lines_and_moves_misfiled_ones(live_dir):
    live.live_log_paths()
    (live_dir / "auth.log").write_text("\n".join([SSH[0], PROSE_WEB, FW[0], SSH[1]]) + "\n")  # prose + a firewall line
    (live_dir / "nginx_access.log").write_text(PROSE_WEB + "\n" + WEB[0] + "\n")
    (live_dir / "firewall.log").write_text(PROSE_FW + "\n")
    assert live.repair_live_logs() == {"kept": 3, "moved": 1, "dropped": 3}
    assert (live_dir / "auth.log").read_text().splitlines() == [SSH[0], SSH[1]]
    assert (live_dir / "nginx_access.log").read_text().splitlines() == [WEB[0]]
    assert (live_dir / "firewall.log").read_text().splitlines() == [FW[0]]  # the misplaced line ended up where it belongs
    assert live.repair_live_logs() == {"kept": 4, "moved": 0, "dropped": 0}  # nothing left to fix: idempotent


def test_repair_leaves_the_tailer_consistent_and_still_alerts(live_dir):
    tailer = LogTailer(live.live_log_paths(), baseline=False)
    (live_dir / "auth.log").write_text("\n".join(FW[:12]) + "\n")  # a whole port scan pasted as auth lines: nothing detected
    assert tailer.poll() == [] and tailer.unrecognised("auth.log") == 12
    live.repair_live_logs()
    assert [e["type"] for e in tailer.poll()] == ["Port scan"]  # the moved lines now count
    assert all(tailer.unrecognised(n) == 0 for n in tailer.current_by_file)


def test_fix_button_cleans_the_users_exact_situation(app_live):
    d = settings.live_dir
    (d / "nginx_access.log").write_text(PROSE_WEB + "\n")
    (d / "firewall.log").write_text(PROSE_FW + "\n")
    app_live.run()
    assert "nginx_access.log: 1 line(s) are not in a format" in page_text(app_live)
    assert any(getattr(b, "key", "") == "live-fix" for b in app_live.button)
    msgs = click(app_live, "live-fix")
    assert "removed 2 that no detector can read" in msgs.note
    assert "are not in a format" not in page_text(app_live) and not any(getattr(b, "key", "") == "live-fix" for b in app_live.button)
    assert (d / "nginx_access.log").read_text() == "" and (d / "firewall.log").read_text() == ""


def test_clear_button_shows_only_its_own_message(app_live):
    assert paste(app_live, "Auto-detect (recommended)", ["not a log line at all"]).warn
    msgs = click(app_live, "paste-clear-0")
    assert "Cleared the live logs" in msgs.note and "None of the pasted" not in msgs.warn


def test_a_paste_error_does_not_outlive_the_problem(app_live):
    """Regression: the warning used to stay on screen forever, even after the files were emptied by hand."""
    msgs = paste(app_live, "Auto-detect (recommended)", ["Port scan, large outbound transfer to a suspicious port"])
    assert "None of the pasted text looks like log lines" in msgs.warn  # shown once, right after the paste...
    for f in settings.live_dir.glob("*.log"):
        f.write_text("")  # ...the user empties the files in their editor
    for _ in range(3):
        app_live.run()  # and the page keeps refreshing
        assert "None of the pasted" not in " ".join(w.value for w in app_live.sidebar.warning)
        assert "paste_warn" not in app_live.session_state and "paste_note" not in app_live.session_state


def test_messages_do_not_pile_up_across_actions(app_live):
    paste(app_live, "Auto-detect (recommended)", ["not a log line at all"])
    msgs = click(app_live, "example-go-0")
    assert "Added the example" in msgs.note and "None of the pasted" not in msgs.warn  # the old warning is not carried over
