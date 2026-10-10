from pathlib import Path

from secagents.config import settings
from secagents.live import LogTailer, ReplayFeed

FAIL = "Mar  3 10:00:{s:02d} web01 sshd[10]: Failed password for root from 203.0.113.9 port 22 ssh2\n"


def failures(n: int, start: int = 0) -> str:
    return "".join(FAIL.format(s=(start + i) % 60) for i in range(n))


def types(events) -> list[str]:
    return [e["type"] for e in events]


def test_alerts_once_when_an_attack_appears(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(failures(3))
    tailer = LogTailer([str(log)], baseline=False)
    assert tailer.poll() == []  # below the brute-force threshold

    with log.open("a") as f:
        f.write(failures(12, 3))
    assert types(tailer.poll()) == ["SSH brute force"]

    with log.open("a") as f:
        f.write(failures(30, 15))
    assert tailer.poll() == []  # same attack, already reported
    assert tailer.events[0]["count"] == 45  # but the detection keeps growing


def test_baseline_ignores_existing_content(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(failures(15))
    tailer = LogTailer([str(log)], baseline=True)
    assert tailer.poll() == []
    assert len(tailer.events) == 1  # known, just not alerted

    with log.open("a") as f:  # a new attacker appears
        f.write(failures(12).replace("203.0.113.9", "198.51.100.7"))
    fresh = tailer.poll()
    assert [e["src_ip"] for e in fresh] == ["198.51.100.7"]


def test_partial_line_waits_for_newline(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    tailer = LogTailer([str(log)], baseline=False)
    full = failures(10)
    with log.open("a") as f:
        f.write(full[:-20])  # last line cut off mid-write
    tailer.poll()
    assert tailer.lines_read == 9
    with log.open("a") as f:
        f.write(full[-20:])
    assert types(tailer.poll()) == ["SSH brute force"]
    assert tailer.lines_read == 10


def test_truncated_file_is_reread(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(failures(12))
    tailer = LogTailer([str(log)], baseline=True)
    tailer.poll()
    log.write_text(failures(2))  # rotated: smaller than the saved offset
    tailer.poll()
    assert tailer.lines_read == 14 and tailer.events == []  # buffer reset, only 2 failures now


def test_missing_file_is_tolerated(tmp_path):
    tailer = LogTailer([str(tmp_path / "nope.log")], baseline=False)
    assert tailer.poll() == []


def test_replay_feed_surfaces_the_demo_attacks_gradually():
    sources = sorted(str(p) for p in (settings.samples_dir / "logs").glob("*.log"))
    feed = ReplayFeed(sources, steps=10)
    tailer = LogTailer(feed.paths, baseline=False)
    first_seen: dict[str, int] = {}
    for tick in range(1, 11):
        feed.advance()
        for e in tailer.poll():
            first_seen.setdefault(e["type"], tick)
    assert feed.done
    assert "SSH brute force" in first_seen or any("brute force" in t.lower() for t in first_seen)
    assert len(first_seen) >= 4  # several distinct attack types alerted over the run
    assert len(set(first_seen.values())) > 1  # and not all on the same tick
    assert Path(feed.paths[0]).exists()


def test_brute_force_upgrade_to_spraying_is_not_a_second_alert(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    tailer = LogTailer([str(log)], baseline=False)
    users = ["root", "admin", "test", "oracle", "git", "ubuntu"]
    alerts = []
    with log.open("a") as f:
        for i in range(12):  # one account at first: plain brute force
            f.write(FAIL.format(s=i))
    alerts += tailer.poll()
    with log.open("a") as f:
        for i, u in enumerate(users * 2):  # then many accounts: now password spraying
            f.write(FAIL.format(s=20 + i).replace("root", u))
    alerts += tailer.poll()
    assert types(tailer.events) == ["SSH brute force and password spraying"]
    assert len(alerts) == 1


EXAMPLES = {
    "1_ssh_brute_force_to_compromise.txt": ("auth.log", {
        "SSH brute force and password spraying", "Successful login after brute force",
        "Privilege escalation after suspicious login", "Remote payload download via sudo", "Backdoor account created"}),
    "2_web_attacks.txt": ("nginx_access.log", {
        "Web attack: SQL injection", "Web attack: Path traversal", "Web attack: Cross-site scripting",
        "Web attack: Command injection", "Web attack: Log4Shell (JNDI injection)", "Automated vulnerability scanning"}),
    "3_port_scan_and_c2.txt": ("firewall.log", {"Port scan", "Large outbound transfer to suspicious port"}),
}


def test_copy_paste_examples_trigger_live_alerts(tmp_path, monkeypatch):
    from dataclasses import replace

    from secagents import live

    monkeypatch.setattr(live, "settings", replace(settings, live_dir=tmp_path / "live_logs"))
    tailer = LogTailer(live.live_log_paths(), baseline=True)
    assert tailer.poll() == []
    for name, (target, expected) in EXAMPLES.items():
        text = (settings.samples_dir / "live_examples" / name).read_text()
        assert live.append_log_lines(target, text) == len(text.splitlines())
        assert expected <= set(types(tailer.poll())), name
    assert tailer.poll() == []  # nothing is re-alerted
    live.clear_live_logs()
    tailer.poll()
    assert tailer.events == []  # cleared files are re-read from scratch


def test_append_rejects_unknown_file(tmp_path):
    import pytest

    from secagents.live import append_log_lines

    with pytest.raises(ValueError):
        append_log_lines("../../etc/passwd", "x")


def test_lines_are_counted_per_file(tmp_path):
    a, b = tmp_path / "auth.log", tmp_path / "firewall.log"
    a.write_text(failures(3))
    b.write_text("")
    tailer = LogTailer([str(a), str(b)], baseline=False)
    tailer.poll()
    assert tailer.read_by_file == {"auth.log": 3} and tailer.lines_read == 3
