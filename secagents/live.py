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
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .agents.log_monitor import detect_named
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
        return added

    def poll(self) -> list[dict[str, Any]]:
        """Read new lines and return the detections that have not been reported before."""
        added = self._read_new()
        if self._started and not added:
            return []
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
