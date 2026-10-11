"""Live scan: follow growing log files and raise an alert the first time each attack shows up.

``LogTailer`` is a ``tail -f`` for the Log Monitor. It remembers how far it has read in every file
(so only new bytes are read), keeps a rolling buffer of the lines (brute-force and scan rules need
history, not just the latest line) and re-runs the deterministic detectors, so it needs no LLM and
is cheap enough to poll every few seconds. An attack is identified by (type, source) and reported
once, however many more matching lines arrive.

``ReplayFeed`` makes the static demo logs behave like a live system: each call appends the next
slice of the sample logs to a temp copy that a tailer then follows.
"""

from __future__ import annotations

import math
import re
import tempfile
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from typing import Any

from .agents.log_monitor import BRUTE_FORCE_THRESHOLD, detect_named, line_kind, recognised
from .config import settings

MAX_BUFFER_LINES = 20_000  # per file; the oldest lines drop off


def event_key(event: dict[str, Any]) -> tuple[str, str, str]:
    """Identity of an attack for de-duplication.

    The target list grows and "SSH brute force" is renamed "... and password spraying" once enough
    accounts are tried, so neither may count as a new attack.
    """
    return event["source"], event["type"].split(" and ")[0], event.get("src_ip") or event.get("target", "")


class LogTailer:
    def __init__(self, paths: list[str], baseline: bool = True):
        """``baseline=True`` treats what is already in the files as known, so only new activity alerts."""
        self.paths = [Path(p) for p in paths]
        self.baseline = baseline
        self.offsets: dict[Path, int] = {}
        self.buffers: dict[Path, list[str]] = {}
        self.seen: set[tuple[str, str, str]] = set()
        self.events: list[dict[str, Any]] = []  # every detection over the buffered lines
        self.lines_read = 0
        self.read_by_file: dict[str, int] = {}  # cumulative lines per file name, for the live panel
        # What the detectors can make of the lines currently in the files. Lines they cannot read are skipped silently,
        # so the live panel reports them: otherwise "6 lines read, 0 detections" looks like nothing happened. These
        # are recomputed from the buffers whenever those change (never accumulated), so a cleared or rewritten
        # file cannot leave stale totals behind.
        self.current_by_file: dict[str, int] = {}  # non-blank lines now in each file
        self.recognised_by_file: dict[str, int] = {}  # ...of which the file's parser understands
        self.misfiled: dict[str, Counter] = {}  # file -> {kind it really is: count}, e.g. firewall lines in auth.log
        self._ignored: dict[str, int] = {}
        self.recent: deque[tuple[str, str, bool]] = deque(maxlen=10)  # (file, line, understood) for the panel
        self._started = False

    def _read_new(self) -> int:
        """Pull new complete lines into the buffers; returns how many changes (lines or resets) there were."""
        added = 0
        for p in self.paths:
            try:
                size = p.stat().st_size
            except OSError:
                continue  # not created yet, or briefly missing during rotation
            offset = self.offsets.get(p, 0)
            if size < offset:  # truncated or rotated: start over
                offset = self.offsets[p] = 0
                self.buffers[p] = []
                added += 1  # the buffered lines changed even if nothing new was read
            if size == offset:
                continue
            with p.open("rb") as f:
                f.seek(offset)
                data = f.read(size - offset)
            end = data.rfind(b"\n")
            if end == -1:  # a line is still being written; wait for its newline
                continue
            chunk = data[: end + 1]
            self.offsets[p] = offset + len(chunk)
            new = chunk.decode("utf-8", errors="replace").splitlines()
            buf = self.buffers.setdefault(p, [])
            buf.extend(new)
            del buf[:-MAX_BUFFER_LINES]
            added += len(new)
            self.lines_read += len(new)
            self.read_by_file[p.name] = self.read_by_file.get(p.name, 0) + len(new)
            for line in new:
                if line.strip():
                    self.recent.append((p.name, line, recognised(p.name, line)))
        return added

    def _refresh_stats(self) -> None:
        """Recount, from the lines currently buffered, what each file's parser can and cannot read."""
        self.current_by_file, self.recognised_by_file, self.misfiled, self._ignored = {}, {}, {}, {}
        for p, lines in self.buffers.items():
            for line in lines:
                if not line.strip():
                    continue
                name = p.name
                self.current_by_file[name] = self.current_by_file.get(name, 0) + 1
                if recognised(name, line):
                    self.recognised_by_file[name] = self.recognised_by_file.get(name, 0) + 1
                else:
                    self._ignored[name] = self._ignored.get(name, 0) + 1
                    kind = line_kind(line)
                    if kind:  # a valid log line, but for a different parser than this file's
                        self.misfiled.setdefault(name, Counter())[kind] += 1

    def poll(self) -> list[dict[str, Any]]:
        """Read new lines and return the detections that have not been reported before."""
        added = self._read_new()
        if self._started and not added:
            return []
        self._refresh_stats()
        self.events = detect_named([(p.name, lines) for p, lines in self.buffers.items()])
        fresh = []
        for e in self.events:
            key = event_key(e)
            if key not in self.seen:
                self.seen.add(key)
                fresh.append(e)
        if not self._started:
            self._started = True
            if self.baseline:
                return []
        return fresh


    def unrecognised(self, name: str) -> int:
        """Non-blank lines now in this file that its parser cannot understand."""
        return self._ignored.get(name, 0)

    def building_up(self) -> list[str]:
        """Attacks in progress that have not reached their alert threshold yet (so the panel is not silent)."""
        out = []
        fails: Counter = Counter()
        for p, lines in self.buffers.items():
            if "auth" in p.name.lower() or "secure" in p.name.lower():
                for ln in lines:
                    m = re.search(r"Failed password for (?:invalid user )?\S+ from (\S+)", ln)
                    if m:
                        fails[m[1]] += 1
        already = {e.get("src_ip") for e in self.events if "brute force" in e["type"].lower()}
        for ip, n in fails.most_common(3):
            if n < BRUTE_FORCE_THRESHOLD and ip not in already:
                out.append(f"{n} failed SSH logins from {ip} so far; a brute-force alert is raised at {BRUTE_FORCE_THRESHOLD}")
        return out


def to_alert(event: dict[str, Any], number: int) -> dict[str, Any]:
    keep = ("type", "severity", "src_ip", "target", "source", "count", "description", "mitre", "evidence")
    return {"id": f"ALERT-{number:03d}", "detected_at": datetime.now().strftime("%H:%M:%S"),
            **{k: event[k] for k in keep if k in event}}


LIVE_LOG_FILES = ("auth.log", "nginx_access.log", "firewall.log")  # names the Log Monitor routes to a parser


def live_log_paths() -> list[str]:
    """The writable folder Live scan follows by default; paste or append attack lines into these files."""
    settings.live_dir.mkdir(parents=True, exist_ok=True)
    paths = [settings.live_dir / n for n in LIVE_LOG_FILES]
    for p in paths:
        p.touch(exist_ok=True)
    return [str(p) for p in paths]


KIND_FILE = {"auth": "auth.log", "web": "nginx_access.log", "firewall": "firewall.log"}
FORMAT_EXAMPLES = {
    "auth.log": "Oct 10 11:20:01 web-01 sshd[7101]: Failed password for root from 203.0.113.45 port 40211 ssh2",
    "nginx_access.log": '192.0.2.88 - - [10/Oct/2026:11:30:01 +0000] "GET /search?q=<script> HTTP/1.1" 200 840 "-" "Mozilla/5.0"',
    "firewall.log": "Oct 10 11:40:01 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46001 DPT=22 SYN",
}


# Ready-made attacks shipped in samples/live_examples/, so nobody has to find and copy them by hand.
EXAMPLE_FILES = {
    "SSH brute force → compromise (16 lines)": "1_ssh_brute_force_to_compromise.txt",
    "Web attacks: SQLi, XSS, Log4Shell… (8 lines)": "2_web_attacks.txt",
    "Port scan + C2 traffic (14 lines)": "3_port_scan_and_c2.txt",
}
ALL_EXAMPLES = "All three examples (38 lines)"


def example_text(name: str) -> str:
    """The log lines of a ready-made example ('All three' joins them)."""
    files = list(EXAMPLE_FILES.values()) if name == ALL_EXAMPLES else [EXAMPLE_FILES[name]]
    return "\n".join((settings.samples_dir / "live_examples" / f).read_text(encoding="utf-8").strip() for f in files)


def route_lines(text: str) -> tuple[dict[str, list[str]], list[str]]:
    """Sort pasted lines into the log file each one belongs in, by what the line looks like.

    Returns ({file name: lines}, lines no parser understands). Lets people paste attack lines without choosing the
    right file: a firewall line pasted as an auth line would otherwise be ignored without a word.
    """
    routed: dict[str, list[str]] = {}
    ignored: list[str] = []
    for line in (ln.rstrip() for ln in text.replace("\r\n", "\n").splitlines()):
        if not line.strip():
            continue
        kind = line_kind(line)
        if kind:
            routed.setdefault(KIND_FILE[kind], []).append(line)
        else:
            ignored.append(line)
    return routed, ignored


def append_routed(text: str) -> tuple[dict[str, int], list[str]]:
    """Append pasted lines to the right live log files. Returns ({file: lines written}, lines not understood)."""
    routed, ignored = route_lines(text)
    return {name: append_log_lines(name, "\n".join(lines)) for name, lines in routed.items()}, ignored


def append_log_lines(filename: str, text: str) -> int:
    """Append pasted text to one of the live log files; returns the number of lines written."""
    if filename not in LIVE_LOG_FILES:
        raise ValueError(f"unknown live log: {filename}")
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").splitlines() if ln.strip()]
    if lines:
        live_log_paths()
        with (settings.live_dir / filename).open("a", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
    return len(lines)


def repair_live_logs() -> dict[str, int]:
    """Clean the live logs without wiping them: keep the lines their parser reads, move lines that belong in
    another log to it, and drop the rest (prose, unsupported formats). Returns {"kept", "moved", "dropped"}.

    Only ever called for the live_logs/ folder, which is test data owned by this app; a real log is never rewritten.
    """
    kept = dropped = 0
    moves: dict[str, list[str]] = {}
    for path in live_log_paths():
        p = Path(path)
        good: list[str] = []
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            if recognised(p.name, line):
                good.append(line)
                kept += 1
                continue
            kind = line_kind(line)
            if kind and KIND_FILE[kind] != p.name:
                moves.setdefault(KIND_FILE[kind], []).append(line)
            else:
                dropped += 1
        with p.open("w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(good) + ("\n" if good else ""))
    moved = sum(append_log_lines(name, "\n".join(lines)) for name, lines in moves.items())
    return {"kept": kept, "moved": moved, "dropped": dropped}


def clear_live_logs() -> None:
    for p in live_log_paths():
        Path(p).write_text("")


class ReplayFeed:
    """Plays existing log files back gradually into a temp directory, to simulate a live system."""

    def __init__(self, sources: list[str], steps: int = 15):
        self.dir = Path(tempfile.mkdtemp(prefix="secagents_live_"))
        self.lines = {Path(s).name: Path(s).read_text(errors="replace").splitlines() for s in sources if Path(s).exists()}
        self.pos = dict.fromkeys(self.lines, 0)
        self.steps = max(1, steps)
        self.paths = [str(self.dir / n) for n in self.lines]
        for p in self.paths:
            Path(p).touch()

    def advance(self) -> None:
        for name, lines in self.lines.items():
            step = max(1, math.ceil(len(lines) / self.steps))
            chunk = lines[self.pos[name]: self.pos[name] + step]
            if chunk:
                with (self.dir / name).open("a", encoding="utf-8", newline="\n") as f:
                    f.write("\n".join(chunk) + "\n")
                self.pos[name] += len(chunk)

    @property
    def progress(self) -> float:
        total = sum(len(v) for v in self.lines.values())
        return sum(self.pos.values()) / total if total else 1.0

    @property
    def done(self) -> bool:
        return self.progress >= 1.0
