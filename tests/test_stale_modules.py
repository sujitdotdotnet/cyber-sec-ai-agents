"""After a code update the dashboard must not fail with 'cannot import name ... from secagents.live'.

Streamlit re-runs the app script after a push but keeps imported modules in memory, so a new app can meet an old
module. The app now notices that the source files changed and reloads the package. This runs in a separate Python
process because reloading replaces the module objects that the rest of the test suite holds on to.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCRIPT = r"""
import json, os
from pathlib import Path
from streamlit.testing.v1 import AppTest
import secagents.live as live

live_py = Path("secagents/live.py")
original = live_py.stat().st_mtime_ns
out = {}

def run():
    at.run()
    return at.exception[0].message if at.exception else None

at = AppTest.from_file("app/streamlit_app.py", default_timeout=120)
out["first_run"] = run()

# the running process still holds an OLDER secagents.live (missing the names the new app imports)
del live.repair_live_logs, live.example_text
out["old_module_source_unchanged"] = run()      # nothing on disk changed, so there is nothing to detect: it must still fail

bump = original + 5_000_000_000                 # the files change on disk, as they do when a push is pulled
os.utime(live_py, ns=(bump, bump))
out["old_module_source_changed"] = run()        # the app reloads the package and recovers
os.utime(live_py, ns=(original, original))
out["after_restore"] = run()
print("RESULT:" + json.dumps(out))
"""


def test_the_app_reloads_secagents_when_its_source_changed():
    env = {**os.environ, "SECAGENTS_OFFLINE": "1", "PYTHONUTF8": "1", "CHROMA_DIR": tempfile.mkdtemp(),
           "HISTORY_DIR": tempfile.mkdtemp(), "LIVE_LOGS_DIR": tempfile.mkdtemp(), "PYTHONPATH": str(ROOT)}
    proc = subprocess.run([sys.executable, "-c", SCRIPT], cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT:")), None)
    assert line, f"no result.\nstdout: {proc.stdout[-800:]}\nstderr: {proc.stderr[-800:]}"
    out = json.loads(line[len("RESULT:"):])
    assert out["first_run"] is None
    # the control: with an old module and unchanged files the error you saw on Streamlit Cloud is reproduced exactly...
    assert out["old_module_source_unchanged"] and "cannot import name 'example_text' from 'secagents.live'" in out["old_module_source_unchanged"]
    # ...and once the files change on disk (a git pull) the app heals itself instead of staying broken until a reboot
    assert out["old_module_source_changed"] is None
    assert out["after_restore"] is None
