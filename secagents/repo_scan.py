"""Turn a repository folder into agent inputs, honouring ignore files and user exclusions.

The agents take one code directory plus single requirements / Dockerfile / config paths, and
their scanners walk that directory recursively. To keep ignored folders (``.venv``,
``node_modules``, ...) out of the scan, the allowed source files are copied into a temp
directory and that copy is handed to the agents. Log files are referenced in place.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

IGNORE_FILES = (".gitignore", ".ignore")
ALWAYS_SKIP = {".git"}
CODE_SUFFIXES = {".py", ".env", ".yaml", ".yml", ".json", ".cfg", ".ini"}  # what the scanners read


class IgnoreRules:
    """Gitignore-style rules (comments, ``!`` negation, ``dir/``, anchored ``/path``, globs)."""

    def __init__(self, patterns: list[str], extra_dirs: list[str] | None = None):
        self.rules: list[tuple[bool, bool, bool, str]] = []  # (negated, dir_only, anchored, pattern)
        for raw in patterns:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            line = line.lstrip("!")
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            anchored = "/" in line
            line = line.lstrip("/")
            if line:
                self.rules.append((negated, dir_only, anchored, line))
        self.extra_dirs = [d.strip().strip("/\\").replace("\\", "/") for d in (extra_dirs or []) if d.strip()]

    def is_ignored(self, rel: str, is_dir: bool) -> bool:
        name = rel.rsplit("/", 1)[-1]
        if is_dir and any(fnmatch.fnmatch(name, d) or fnmatch.fnmatch(rel, d) for d in self.extra_dirs):
            return True
        ignored = False
        for negated, dir_only, anchored, pat in self.rules:
            if dir_only and not is_dir:
                continue
            if fnmatch.fnmatch(rel if anchored else name, pat):
                ignored = not negated
        return ignored


def load_ignore_rules(root: Path, extra_dirs: list[str] | None = None) -> IgnoreRules:
    patterns: list[str] = []
    for name in IGNORE_FILES:
        f = root / name
        if f.is_file():
            patterns += f.read_text(encoding="utf-8", errors="ignore").splitlines()
    return IgnoreRules(patterns, extra_dirs)


_PICKER = (
    "import tkinter as tk; from tkinter import filedialog; r = tk.Tk(); r.withdraw(); "
    "r.attributes('-topmost', True); print(filedialog.askdirectory(title='Select folder to scan', mustexist=True))"
)


def browse_folder() -> str:
    """Open the native folder dialog on this machine (a subprocess keeps Tk off Streamlit's threads).

    Returns the chosen path, or "" if cancelled or no display/tkinter is available.
    """
    try:
        out = subprocess.run([sys.executable, "-c", _PICKER], capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError):
        return ""
    return os.path.normpath(out.stdout.strip()) if out.returncode == 0 and out.stdout.strip() else ""


def parse_excludes(text: str) -> list[str]:
    return [p.strip() for p in text.split(",") if p.strip()]


def walk_repo(root: Path, rules: IgnoreRules):
    """Yield (relative posix path, absolute path) for every non-ignored file."""
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = sorted(
            d for d in dirnames if d not in ALWAYS_SKIP and not rules.is_ignored(prefix + d, True)
        )
        for fn in sorted(filenames):
            if not rules.is_ignored(prefix + fn, False):
                yield prefix + fn, here / fn


def _shallowest(candidates: list[str]) -> str | None:
    return min(candidates, key=lambda r: (r.count("/"), r)) if candidates else None


def collect_repo_inputs(folder: str, exclude_text: str = "") -> tuple[dict[str, Any], dict[str, int]]:
    """Build agent inputs from a repository folder. Returns (inputs, summary counts)."""
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Not a folder: {folder}")
    rules = load_ignore_rules(root, parse_excludes(exclude_text))

    logs: list[str] = []
    code_files: list[str] = []
    reqs: list[str] = []
    dockerfiles: list[str] = []
    configs: list[str] = []
    for rel, _ in walk_repo(root, rules):
        name, suffix = rel.rsplit("/", 1)[-1], Path(rel).suffix.lower()
        if suffix == ".log":
            logs.append(rel)
        if suffix in CODE_SUFFIXES:
            code_files.append(rel)
        if name.lower().startswith("requirements") and suffix == ".txt":
            reqs.append(rel)
        if name.lower().startswith("dockerfile"):
            dockerfiles.append(rel)
        if suffix in {".yaml", ".yml"} and "config" in name.lower():
            configs.append(rel)

    stage = Path(tempfile.mkdtemp(prefix="secagents_repo_"))
    code_dir = stage / "code"
    code_dir.mkdir()
    for rel in code_files:
        dest = code_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / rel, dest)

    def pick(candidates: list[str]) -> str:
        best = _shallowest(candidates)
        return str(root / best) if best else ""

    inputs = {
        "log_paths": [str(root / r) for r in logs],
        "code_path": str(code_dir) if any(r.endswith(".py") for r in code_files) else "",
        "requirements_path": pick(reqs),
        "dockerfile_path": pick(dockerfiles),
        "config_path": pick(configs),
    }
    summary = {
        "logs": len(logs),
        "python": sum(r.endswith(".py") for r in code_files),
        "requirements": len(reqs),
        "dockerfiles": len(dockerfiles),
        "configs": len(configs),
    }
    return inputs, summary
