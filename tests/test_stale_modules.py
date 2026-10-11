"""After a code update the dashboard must not fail with 'cannot import name ... from secagents.live'.

Streamlit re-runs the app script after a push but keeps imported modules in memory, so a new app can meet an old
module. The app guards against it in two ways: it reloads the package when the source files changed since the last
run, and if an import still fails it drops every secagents module and imports everything again. This runs in a
separate Python process because reloading replaces the module objects that the rest of the test suite holds on to.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCRIPT = r"""
import importlib, json, os, sys
from pathlib import Path
from streamlit.testing.v1 import AppTest

live_py = Path("secagents/live.py")
original = live_py.stat().st_mtime_ns
out = {}

def run(app="app/streamlit_app.py"):
    at = AppTest.from_file(app, default_timeout=120)
    at.run()
    return at

def error(at):
    return at.exception[0].message if at.exception else None

def make_stale():
    # the process holds an OLDER secagents.live: it lacks names the current app imports
    live = importlib.import_module("secagents.live")
    for name in ("repair_live_logs", "example_text", "ALL_EXAMPLES"):
        if hasattr(live, name):
            delattr(live, name)

# a) the process was started by an OLDER version of the app: nothing recorded a source fingerprint (the Streamlit Cloud case)
importlib.import_module("secagents.live")
make_stale()
assert not hasattr(sys, "_secagents_source_fingerprint")
out["a_old_process_no_fingerprint"] = error(run())

# b) an older module is in memory, a fingerprint exists, and the files are unchanged
make_stale()
out["b_stale_module_files_unchanged"] = error(run())

# c) the source files change on disk, as when a push is pulled
make_stale()
bump = original + 5_000_000_000
os.utime(live_py, ns=(bump, bump))
out["c_stale_module_files_changed"] = error(run())
os.utime(live_py, ns=(original, original))
out["c2_after_restore"] = error(run())

# d) a genuine problem must still surface: an app that imports a name which exists nowhere
src = Path("app/streamlit_app.py").read_text(encoding="utf-8").replace("ALL_EXAMPLES, EXAMPLE_FILES,", "ALL_EXAMPLES, NO_SUCH_NAME_ANYWHERE, EXAMPLE_FILES,", 1)
tmp = Path(os.environ["BAD_APP_DIR"]); tmp.mkdir(parents=True, exist_ok=True)
(tmp / "streamlit_app.py").write_text(src, encoding="utf-8")
out["d_genuine_error"] = error(run(str(tmp / "streamlit_app.py")))
print("RESULT:" + json.dumps(out))
"""


def test_the_app_heals_itself_from_stale_modules_but_still_reports_real_errors():
    env = {**os.environ, "SECAGENTS_OFFLINE": "1", "PYTHONUTF8": "1", "CHROMA_DIR": tempfile.mkdtemp(),
           "HISTORY_DIR": tempfile.mkdtemp(), "LIVE_LOGS_DIR": tempfile.mkdtemp(), "PYTHONPATH": str(ROOT),
           "BAD_APP_DIR": tempfile.mkdtemp()}
    # the child prints UTF-8 (tracebacks use box-drawing characters), so do not decode with the Windows code page
    proc = subprocess.run([sys.executable, "-c", SCRIPT], cwd=ROOT, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=400)
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT:")), None)
    assert line, f"no result.\nstdout: {proc.stdout[-800:]}\nstderr: {proc.stderr[-800:]}"
    out = json.loads(line[len("RESULT:"):])
    assert out["a_old_process_no_fingerprint"] is None  # the exact situation on Streamlit Cloud: heals on the first run
    assert out["b_stale_module_files_unchanged"] is None
    assert out["c_stale_module_files_changed"] is None and out["c2_after_restore"] is None
    assert out["d_genuine_error"] and "NO_SUCH_NAME_ANYWHERE" in out["d_genuine_error"]  # not swallowed, no endless retry
