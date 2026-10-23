"""SecAgents dashboard: run the five-agent assessment and explore the results.

    streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import html
import json
import logging
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# After a code update (a push to Streamlit Cloud, or a save while running locally) Streamlit re-runs this script but
# keeps already-imported modules in memory. A new app can then meet an old copy of a secagents module and fail with
# "ImportError: cannot import name ... from 'secagents.live'" until the whole process is restarted. Two guards below
# make the app load the current files by itself.
def _drop_secagents_modules() -> None:
    for name in [m for m in sys.modules if m == "secagents" or m.startswith("secagents.")]:
        del sys.modules[name]


def _drop_stale_secagents_modules() -> None:
    """Guard 1: reload the package when its source files changed since the previous run (handles silent changes too).

    Compares a fingerprint of the source with the one from the last run; nothing happens while the code is unchanged,
    so state is kept between reruns. It cannot help a process that was started by an older version of this app,
    because that version recorded no fingerprint: guard 2 covers that case.
    """
    files = (Path(__file__).resolve().parent.parent / "secagents").rglob("*.py")
    fingerprint = hash(tuple(sorted((str(f), f.stat().st_mtime_ns, f.stat().st_size) for f in files)))
    previous = getattr(sys, "_secagents_source_fingerprint", None)
    sys._secagents_source_fingerprint = fingerprint
    if previous is not None and previous != fingerprint:
        _drop_secagents_modules()


def _import_secagents() -> dict:
    """Every import from the secagents package, together, so they can be retried as one unit."""
    from secagents import agent_ui, gate, history, review_ui
    from secagents.config import settings
    from secagents.exporters import MIME as EXPORT_MIME, export
    from secagents.graph import default_inputs, stream
    from secagents.agents.log_monitor import detect_named
    from secagents.live import (
        ALL_EXAMPLES, EXAMPLE_FILES, FORMAT_EXAMPLES, KIND_FILE, LIVE_LOG_FILES, LogTailer, ReplayFeed, append_log_lines,
        append_routed, clear_live_logs, event_key, example_text, live_log_paths, repair_live_logs, route_lines, to_alert,
    )
    from secagents.llm import LLMRouter, get_router
    from secagents.qa import ask
    from secagents.rag import embedding_backend, set_embedding_key
    from secagents.repo_scan import browse_folder, collect_repo_inputs, find_logs, ignore_entries
    from secagents.knowledge import footer_text as knowledge_text
    from secagents.version import app_title
    from secagents.session import activate as activate_session, live_dir as current_live_dir, new_session
    from secagents.sources import SourceError, classify as classify_source, resolve as resolve_source

    return dict(locals())


_drop_stale_secagents_modules()
try:
    globals().update(_import_secagents())
except ImportError:
    # Guard 2: the process still holds an older secagents module than this app expects (it was started by an earlier
    # version of the app). Drop every secagents module and import everything again, so old and new modules are never
    # mixed. A genuine error (a name that exists nowhere) fails the second attempt too and is raised as usual.
    _drop_secagents_modules()
    globals().update(_import_secagents())

st.set_page_config(page_title=app_title(), page_icon="🛡️", layout="wide")

# Public deployment: visitors sign in or continue as guests, and each gets their own router (typed API keys), live-log
# folder, scan history and spending limits, because all visitors share one Python process. Locally nothing changes:
# no gate, one shared router and the configured folders.
if settings.public:
    who = gate.resolve()  # shows the sign-in / guest page and stops until the visitor chooses
    visitor = st.session_state.get("visitor")
    if visitor is None or visitor.identity != who:  # first visit, or signed in / out: start clean for the new identity
        for stale in ("agent_obj", "agent_sig", "agent_thread", "agent_memory", "result", "scan", "chat", "live"):
            st.session_state.pop(stale, None)
        st.session_state["visitor"] = new_session(LLMRouter(), identity=who)
    activate_session(st.session_state["visitor"])


class _IgnoreBrowserDisconnect(logging.Filter):
    """Drop asyncio's 'ConnectionResetError [WinError 10054]' noise: the browser closed or reloaded the page."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not (record.exc_info and isinstance(record.exc_info[1], ConnectionResetError))


if not any(isinstance(f, _IgnoreBrowserDisconnect) for f in logging.getLogger("asyncio").filters):
    logging.getLogger("asyncio").addFilter(_IgnoreBrowserDisconnect())

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
STATUS_ICON = {"PASS": "✅", "PARTIAL": "🟡", "FAIL": "❌"}
AGENT_LABEL = {
    "supervisor": "🧭 Supervisor",
    "log_monitor": "📜 Log Monitor",
    "vuln_scanner": "🔍 Vulnerability Scanner",
    "threat_intel": "🌐 Threat Intelligence",
    "incident_response": "🚨 Incident Response",
    "policy_checker": "📋 Policy Checker",
    "correlator": "🔗 Correlator",
    "critic": "🧪 Uncertainty Critic",
    "human_gate": "🧑‍⚖️ Human gate",
    "reporter": "📝 Reporter",
}
BAR_COLOR = "#2a78d6"
HISTORY_BOX_PX, HISTORY_SCROLL_AFTER = 320, 4  # Scan history: height of the scrolling list, and how many scans before it scrolls
LIVE_ASSESS_GAP = 20  # minimum seconds between automatic dashboard refreshes in Live scan
BANNER_STILL = Path(__file__).resolve().parent / "assets" / "banner_still.png"  # shown when idle
BANNER_SCAN = Path(__file__).resolve().parent / "assets" / "banner_scan.gif"  # shown while scanning
# Page-wide CSS, injected once from the sidebar so no stray element sits above the banner in the main area.
APP_CSS = """
<style>
/* banner flush under the toolbar: Streamlit's default top padding (6rem) leaves a blank band above it */
[data-testid="stMainBlockContainer"], .block-container{padding-top:3.75rem}
/* wider sidebar so the title fits on one line (only while open, so collapsing still works) */
[data-testid="stSidebar"][aria-expanded="true"]{min-width:420px;max-width:420px}
/* status dot: red and still when idle, green and pulsing while any scan is running */
.sa-dot{display:inline-block;width:12px;height:12px;border-radius:50%;background:#d64545;margin-right:8px;vertical-align:middle}
.sa-dot.on{background:#2ecc71;animation:sa-greenpulse 1.2s ease-in-out infinite}
.sa-knowledge{font-size:.85rem;font-weight:400;color:#fff !important;letter-spacing:0}
.sa-tagline{font-size:1.35rem;font-weight:600;letter-spacing:.2px;line-height:1.35;margin:-.25rem 0 .75rem}
/* fade in and out (1.6 s per cycle) for the call-to-action; off for people who prefer reduced motion */
.sa-pulse-text{animation:sa-textpulse 1.6s ease-in-out infinite}
@keyframes sa-textpulse{0%,100%{opacity:1}50%{opacity:.3}}
@media (prefers-reduced-motion: reduce){.sa-pulse-text{animation:none}}
.sa-live{display:inline-flex;align-items:center;font-weight:700;color:#2ecc71;margin-bottom:6px}
@keyframes sa-greenpulse{0%,100%{box-shadow:0 0 0 0 rgba(46,204,113,.65)}50%{box-shadow:0 0 0 8px rgba(46,204,113,0)}}
</style>
"""


def tagline_color() -> str:
    """Green with enough contrast on the current page theme: bright on dark, deeper on light."""
    try:
        return "#0f8a43" if st.context.theme.type == "light" else "#3ddc84"
    except Exception:  # noqa: BLE001 - theme unknown (older Streamlit / embedded): the bright green suits the default dark theme
        return "#3ddc84"


def cta_color() -> str:
    """Orange for the pulsing call to action: bright on a dark page, deeper on a light one (same idea as the tagline)."""
    try:
        return "#d9480f" if st.context.theme.type == "light" else "#ff9f43"
    except Exception:  # noqa: BLE001 - theme unknown: the bright orange suits the default dark theme
        return "#ff9f43"


def scan_status_html(scanning: bool, detail: str) -> str:
    return (f'<div><span class="sa-dot{" on" if scanning else ""}"></span>'
            f'<b>{"Scanning" if scanning else "Idle"}</b> <span style="opacity:.7">· {detail}</span></div>')


PIPELINE = ["log_monitor", "vuln_scanner", "threat_intel", "incident_response", "policy_checker", "correlator", "critic", "human_gate", "reporter"]
AFTER = {"correlator": "critic", "critic": "human_gate", "human_gate": "reporter"}  # what starts when each review step finishes
PIPELINE_CSS = """
<style>
.sa-pipe{display:flex;flex-wrap:wrap;gap:8px;margin:4px 0 10px}
.sa-chip{padding:6px 12px;border-radius:999px;border:1px solid rgba(128,128,128,.35);font-size:.85rem;opacity:.55}
.sa-chip.done{opacity:1;border-color:#2e9e5b;color:#2e9e5b}
.sa-chip.active{opacity:1;border-color:#2a78d6;background:rgba(42,120,214,.14);font-weight:600;
  animation:sa-pulse 1.2s ease-in-out infinite}
.sa-dots span{animation:sa-blink 1.4s infinite both;font-weight:700}
.sa-dots span:nth-child(2){animation-delay:.2s}
.sa-dots span:nth-child(3){animation-delay:.4s}
.sa-spin{display:inline-block;animation:sa-rot 1s linear infinite}
@keyframes sa-pulse{0%,100%{box-shadow:0 0 0 0 rgba(42,120,214,.55)}50%{box-shadow:0 0 0 8px rgba(42,120,214,0)}}
@keyframes sa-blink{0%,80%,100%{opacity:.2}40%{opacity:1}}
@keyframes sa-rot{to{transform:rotate(360deg)}}
</style>
"""


def pipeline_html(active: str | set[str] | None, done: set[str]) -> str:
    """The progress chips. ``active`` can be several agents: independent specialists run at the same time."""
    working = {active} if isinstance(active, str) else set(active or ())
    chips = []
    for name in PIPELINE:
        state = "active" if name in working else "done" if name in done else ""
        label = AGENT_LABEL.get(name, name)
        spin = '<span class="sa-spin">⚙️</span> ' if state == "active" else ("✓ " if state == "done" else "")
        dots = '<span class="sa-dots"><span>.</span><span>.</span><span>.</span></span>' if state == "active" else ""
        chips.append(f'<div class="sa-chip {state}">{spin}{label}{dots}</div>')
    return PIPELINE_CSS + f'<div class="sa-pipe">{"".join(chips)}</div>'


def sev(s: str) -> str:
    return f"{SEV_ICON.get(s, '')} {s}"


def show_footer() -> None:
    """The bottom of every page: the collapsed About panel, then the app's name and version (from the VERSION file)."""
    gate.footer()


def reset_app() -> None:
    """Back to a clean start: no result, no chat, fresh widgets. Saved history is kept."""
    nonce = st.session_state.get("nonce", 0) + 1
    st.session_state.clear()
    st.session_state["nonce"] = nonce


def open_scan(scan_id: str) -> None:
    rec = history.load(scan_id)
    st.session_state["result"] = rec["result"]
    st.session_state["scan"] = {k: v for k, v in rec.items() if k != "result"}
    st.session_state.pop("chat", None)


def delete_scan(scan_id: str) -> None:
    history.delete(scan_id)
    if st.session_state.get("scan", {}).get("id") == scan_id:
        st.session_state.pop("scan", None)


def reset_live() -> None:
    """Toggling Live scan starts from scratch: forget read positions, seen attacks and alerts."""
    st.session_state.pop("live", None)


PASTE_AUTO = "Auto-detect (recommended)"


def queue_test_batch(routed: dict[str, list[str]]) -> None:
    """Remember lines the user just added by hand (a paste or an example) for the live panel.

    The tailer reports an attack once, so adding the same attack again (the same example twice, a paste after the
    example, or lines identical to ones already in the folder when Live scan started) would raise no alert and look
    broken. The live panel checks this batch on its own and alerts again for attacks that were already reported.
    """
    st.session_state["live_batch"] = [(name, lines) for name, lines in routed.items() if lines]


def clear_live_logs_ui() -> None:
    """Button callback: empty the live logs, start the live scan over, and forget the old paste messages."""
    clear_live_logs()
    st.session_state.pop("live", None)  # alerts, counters and the "already reported" memory all restart
    st.session_state["skip_baseline"] = True  # ...but without a fresh full assessment: that is for starting Live scan
    st.session_state.pop("live_batch", None)
    st.session_state["paste_note"], st.session_state["paste_warn"] = "Cleared the live logs.", ""


def fix_live_logs() -> None:
    """Button callback: clean the live_logs files in place (see secagents.live.repair_live_logs)."""
    r = repair_live_logs()
    st.session_state["paste_note"] = (f"Fixed the live logs: kept {r['kept']} line(s), moved {r['moved']} to the right file, "
                                      f"removed {r['dropped']} that no detector can read.")
    st.session_state["paste_warn"] = ""


def append_example(example_key: str) -> None:
    """Button callback: write a ready-made attack (from samples/live_examples) into the live logs."""
    name = st.session_state.get(example_key, ALL_EXAMPLES)
    text = example_text(name)
    written, _ = append_routed(text)
    queue_test_batch(route_lines(text)[0])
    st.session_state["paste_note"] = (f"Added the example '{name.split(' (')[0]}': "
                                      + ", ".join(f"{n} → {f}" for f, n in written.items()) + ".")
    st.session_state["paste_warn"] = ""


def format_help(files: list[str]) -> str:
    return " ".join(f"{f}: `{FORMAT_EXAMPLES[f]}`" for f in files)


def append_pasted(text_key: str, target_key: str) -> None:
    """Button callback: write the pasted lines to the live log(s), then empty the box.

    Auto-detect sends each line to the log it belongs in. With a fixed file, lines that look like a different log
    are still written (it is the user's choice) but flagged, because that file's parser would silently skip them.
    """
    text, target = st.session_state.get(text_key, ""), st.session_state.get(target_key, PASTE_AUTO)
    st.session_state[text_key] = ""
    note, warn = "", ""
    if target == PASTE_AUTO:
        written, ignored = append_routed(text)
        queue_test_batch(route_lines(text)[0])
        if written:
            note = f"Appended {sum(written.values())} line(s): " + ", ".join(f"{n} → {f}" for f, n in written.items()) + "."
        if ignored and not written:
            warn = (f"None of the pasted text looks like log lines (first: `{ignored[0][:90]}`). If you copied it from a README, "
                    "that describes what the examples detect and is not log data: use **Add a ready-made attack** below. "
                    "Real lines look like: " + format_help(list(FORMAT_EXAMPLES)))
        elif ignored:
            warn = (f"{len(ignored)} line(s) were not added: no parser understands their format (first: `{ignored[0][:90]}`). "
                    "Expected formats: " + format_help(list(FORMAT_EXAMPLES)))
        if not written and not ignored:
            note = "Nothing to append: paste some log lines first."
    else:
        n = append_log_lines(target, text)
        note = f"Appended {n} line(s) to {target}." if n else "Nothing to append: paste some log lines first."
        queue_test_batch({target: [ln.rstrip() for ln in text.replace("\r\n", "\n").splitlines() if ln.strip()]})
        routed, ignored = route_lines(text)
        elsewhere = {f: len(ls) for f, ls in routed.items() if f != target}
        if elsewhere or ignored:
            parts = [f"{c} look like {f} lines" for f, c in elsewhere.items()] + ([f"{len(ignored)} are in no known format"] if ignored else [])
            warn = (f"Of the lines added to {target}, " + " and ".join(parts) + ", so its parser will ignore them. "
                    "Use Auto-detect to send each line to the right file.")
    st.session_state["paste_note"], st.session_state["paste_warn"] = note, warn


def pick_folder(key: str) -> None:
    """Button callback: fill the path box from a native folder dialog (runs before the widget redraws)."""
    chosen = browse_folder()
    if chosen:
        st.session_state[key] = chosen
    else:
        st.session_state["browse_failed"] = True


def save_uploads(files, folder: Path) -> list[str]:
    paths = []
    for f in files or []:
        p = folder / Path(f.name).name
        p.write_bytes(f.getvalue())
        paths.append(str(p))
    return paths


# ---- sidebar: providers and inputs ------------------------------------------------
nonce = st.session_state.setdefault("nonce", 0)

with st.sidebar:
    st.title(f"🛡️ {app_title()}")
    st.button("↺ Reset", on_click=reset_app, use_container_width=True,
              help="Clear the current results, chat and inputs. Scan history is kept.")
    st.caption("Five AI agents for detection, intel, scanning, response and compliance. Scan your GitHub Repositories, own logs, code and config files now.")
    if settings.public:
        gate.sidebar_box(st.session_state["visitor"])
    router = get_router()
    options = list(settings.provider_order)
    router.preferred = st.selectbox(
        "LLM provider", options, index=options.index("openrouter") if "openrouter" in options else 0,
        key=f"provider-{nonce}", help="Tried first; the others are used as fallbacks if it fails.",
    )
    # API key box for the selected provider; a key typed here beats the .env key, which stays the fallback.
    # Each provider keeps its own box value, so switching the dropdown never sends one provider's key to another.
    chosen = router.preferred
    key_box = f"apikey-{chosen}-{nonce}"
    typed = st.text_input(
        f"API key for {chosen}", type="password", key=key_box,
        placeholder="Leave empty to use the key from .env",
        help="Used first for this provider. If empty, the key in .env is used. Kept in this session only: it is "
             "never saved to disk or to Scan history.",
    )
    router.key_overrides = {
        p: (typed if p == chosen else st.session_state.get(f"apikey-{p}-{nonce}", "")).strip() for p in options
    }
    # No key for the selected provider (neither typed nor in .env): say so loudly, once as a toast, always as an error,
    # and outline the box. Offline mode is a deliberate choice to run without a model, so it is not an error.
    key_missing = router.key_source(chosen) == "none" and not settings.offline
    key_box_css = ""
    if key_missing:
        fallbacks = [p for p in router.ordered_providers() if p != chosen and router.key_source(p) != "none"]
        what_happens = (f"Falling back to {fallbacks[0]}." if fallbacks
                        else "No provider has a key, so the agents run in rule-based mode (no LLM).")
        st.error(f"No API key found for {chosen}. Add one in the box above or in .env. {what_happens}", icon="🔑")
        if st.session_state.get("key_toast") != chosen:  # toast once per provider, not on every rerun
            st.toast(f"No API key found for {chosen}", icon="🚨")
            st.session_state["key_toast"] = chosen
        key_box_css = (f".st-key-{key_box} div[data-baseweb='input']{{border:2px solid #e74c3c !important;"
                       f"box-shadow:0 0 0 4px rgba(231,76,60,.28);background:rgba(231,76,60,.08)}}")
    else:
        st.session_state.pop("key_toast", None)
        source_note = {"typed": "🔑 using the key you entered", ".env": "using the key from .env"}[router.key_source(chosen)] \
            if router.key_source(chosen) != "none" else "rule-based mode (offline)"
        st.caption(f"{chosen}: {source_note}")
    if not settings.public:  # the knowledge base is shared by every visitor, so a visitor's key must not drive it
        set_embedding_key(router.key_overrides.get("openai", ""))  # an OpenAI key typed here also drives RAG embeddings
    providers = router.available_providers()
    st.markdown("**Active providers:** " + (", ".join(providers) if providers else "none (rule-based mode)"))
    st.caption(f"Model: `{router.model_for(router.preferred)}` ({router.preferred})")
    st.caption("Fallback order: " + " → ".join(f"{p} (`{router.model_for(p)}`)" for p in router.ordered_providers()))
    st.caption(f"RAG embeddings: {'OpenAI (`' + settings.embedding_model + '`)' if embedding_backend() == 'openai' else 'local, no OpenAI key'}")

    source = st.radio("Data to analyze", ["Demo attack scenario", "Upload my own files"], key=f"source-{nonce}")
    inputs = default_inputs()
    repo_folder = repo_excludes = repo_path = ""  # repo_folder: what was typed; repo_path: the local folder it resolves to
    repo_info = None
    if source == "Upload my own files":
        st.markdown("**Scan a GitHub Repository or Shared Folder**")
        repo_key = f"repo-{nonce}"
        repo_folder = st.text_input(
            "Repository folder path or link", key=repo_key,
            placeholder=r"C:\code\app · \\server\share\app · https://github.com/owner/repo · Drive folder link",
            help=r"Any of: a folder on the machine running this app (Browse works locally only); a Windows network share "
                 r"(\\server\share\folder); a GitHub repository or folder link (https://github.com/owner/repo or "
                 ".../tree/<branch>/<folder>); a public Google Drive folder link (shared as 'Anyone with the link'). "
                 "Links are downloaded. Logs, Python code, requirements, Dockerfile and config are found automatically; "
                 "files matched by the .gitignore / .ignore are skipped.",
        )
        source_kind = ""
        if repo_folder.strip():
            try:
                source_kind = classify_source(repo_folder)
            except SourceError as exc:
                st.error(str(exc))
            if settings.public and source_kind in ("local", "network"):
                st.error("Folders on the server and network shares are disabled on this public site. "
                         "Use a GitHub or Google Drive link, or upload files.")
                source_kind = ""
            if settings.public and source_kind in ("github", "gdrive"):  # each fetch costs bandwidth and disk: limited per day
                if note := st.session_state["visitor"].allowance.download(repo_folder.strip()):
                    st.error(note)
                    source_kind = ""
        gh_token = ""
        if source_kind == "github":
            gh_token = st.text_input("GitHub token (private repositories only)", type="password", key=f"ghtoken-{nonce}",
                                     placeholder="Optional. Or set GITHUB_TOKEN on the server",
                                     help="Only sent to api.github.com, kept in this session, never saved.")
        if not settings.public:
            st.button("📂 Browse...(Works Locally only)", key=f"browse-{nonce}", on_click=pick_folder, args=(repo_key,),
                      use_container_width=True, help="Open a folder chooser on this machine")
        if st.session_state.pop("browse_failed", False):
            st.warning("Couldn't open a folder dialog here (no display?). Type the path instead.")
        if source_kind:  # turn the path / link into a local folder (downloads are cached for a few minutes)
            wait = {"github": "Downloading from GitHub...",
                    "gdrive": "Fetching the Google Drive folder (the first fetch can take a minute)...",
                    "network": "Reaching the network share...", "local": "Reading the folder..."}[source_kind]
            try:
                with st.spinner(wait):
                    repo_info = resolve_source(repo_folder, gh_token)
                repo_path = str(repo_info.path)
                st.caption(f"✅ {repo_info.label}")
                if repo_info.note:
                    st.caption(repo_info.note)
            except SourceError as exc:
                st.error(str(exc))
        st.session_state["repo_remote"] = bool(repo_info and repo_info.remote)
        # pre-fill with the folder's .gitignore / .ignore entries when the source changes or first resolves
        exclude_key = f"exclude-{nonce}"
        fingerprint = (repo_folder.strip(), bool(repo_path))
        if st.session_state.get(f"prefilled-{nonce}") != fingerprint:
            st.session_state[f"prefilled-{nonce}"] = fingerprint
            st.session_state[exclude_key] = ", ".join(ignore_entries(repo_path)) if repo_path else ""
        repo_excludes = st.text_area(
            "Exclude folders (comma-separated) · .gitignore / .ignore items are excluded by default",
            key=exclude_key, height=110, placeholder="e.g. tests, docs, build",
            help="Pre-filled from the folder's .gitignore and .ignore files, so everything listed is skipped. "
                 "Add your own folders (names, relative paths or wildcards) or remove entries to scan them.",
        )
        tmp = Path(tempfile.mkdtemp(prefix="secagents_"))
        with st.expander("Upload Custom Files", expanded=False):
            logs = st.file_uploader("Log files (auth.log, access.log, firewall.log)", accept_multiple_files=True, key=f"logs-{nonce}")
            code = st.file_uploader("Python source files", type=["py"], accept_multiple_files=True, key=f"code-{nonce}")
            reqs = st.file_uploader("requirements.txt", type=["txt"], key=f"reqs-{nonce}")
            docker = st.file_uploader("Dockerfile", key=f"docker-{nonce}")
            cfg = st.file_uploader("System config (YAML)", type=["yaml", "yml"], key=f"cfg-{nonce}")
        (tmp / "code").mkdir()
        inputs = {
            "log_paths": save_uploads(logs, tmp),
            "code_path": str(tmp / "code") if code else "",
            "requirements_path": save_uploads([reqs], tmp)[0] if reqs else "",
            "dockerfile_path": save_uploads([docker], tmp)[0] if docker else "",
            "config_path": save_uploads([cfg], tmp)[0] if cfg else "",
        }
        save_uploads(code, tmp / "code")
    scan_name = st.text_input("Scan name (optional)", key=f"name-{nonce}",
                              placeholder="e.g. Prod web server, weekly check")
    run = st.button("▶ Run assessment", type="primary", use_container_width=True)
    live_on = st.toggle(
        "Live scan", key=f"live-{nonce}", on_change=reset_live,
        help="Keep watching the logs and alert the moment a new attack appears. Turn on Simulation mode to replay "
             "the demo logs as a simulated live feed; for your own data use a folder path or the live_logs/ folder.",
    )
    scanning = bool(run or live_on)
    st.markdown(scan_status_html(scanning, "assessment running" if run else "live scan on" if live_on else "no scan running"),
                unsafe_allow_html=True)
    live_interval, live_auto, live_llm, sim_on = 5, True, False, False
    if live_on:
        sim_on = st.toggle(
            "🎬 Simulation mode", key=f"sim-{nonce}", on_change=reset_live,
            help="Replay the existing demo logs gradually as a simulated live feed. Switch it off to follow real "
                 "log files: your folder path, or the live_logs/ folder you can paste attack lines into.",
        )
        with st.expander("Live scan settings"):
            live_interval = st.slider("Check every (seconds)", 2, 30, 5, key=f"live-interval-{nonce}")
            live_auto = st.checkbox("Refresh the dashboard on new alerts (full assessment)", value=True,
                                    key=f"live-auto-{nonce}",
                                    help="Runs all five agents so Incidents, Log detections, Code findings and CVEs "
                                         f"update. Also runs once when Live scan starts. At most every {LIVE_ASSESS_GAP} "
                                         "seconds; each run is saved to Scan history.")
            live_llm = st.checkbox("Use the LLM for these refreshes (slower, uses tokens)", value=False,
                                   key=f"live-llm-{nonce}", disabled=not live_auto,
                                   help="Off: the agents use their rule-based output, so counters update in seconds with "
                                        "no model calls. Press Run assessment for a full LLM-written report.")
        # Messages about the last paste / example / fix are shown once, on the rerun the click causes, then dropped. They
        # describe one action, not the current state, so keeping them would leave a stale error on screen after the
        # files are fixed. (The per-file warnings in the live panel are recomputed from the files and clear by themselves.)
        paste_note, paste_warn = st.session_state.pop("paste_note", ""), st.session_state.pop("paste_warn", "")
        if not sim_on and not repo_path:
            # default target: a writable folder the tailer follows, so attacks can be pasted in
            with st.expander("🧪 Test it: paste log lines", expanded=True):
                st.caption(f"Live scan is following `{current_live_dir()}`. Add a ready-made attack in one click, or paste "
                           "your own log lines below.")
                example_key = f"example-{nonce}"
                st.selectbox("Add a ready-made attack", [ALL_EXAMPLES, *EXAMPLE_FILES], key=example_key,
                             help="Real log lines from samples/live_examples/, routed to the right files. No copying needed.")
                st.button("⚡ Add example", key=f"example-go-{nonce}", on_click=append_example, args=(example_key,),
                          use_container_width=True, type="primary")
                st.markdown("**Or paste your own log lines**")
                st.selectbox("Append to", [PASTE_AUTO, *LIVE_LOG_FILES], key=f"paste-target-{nonce}",
                             help="Auto-detect looks at each line and writes it to auth.log, nginx_access.log or firewall.log "
                                  "as appropriate. A line in the wrong file is read but ignored by that file's parser.")
                st.text_area("Log lines", key=f"paste-text-{nonce}", height=130,
                             placeholder='Oct 10 11:20:01 web-01 sshd[7101]: Failed password for root from 203.0.113.45 port 40211 ssh2')
                cols = st.columns(2)
                cols[0].button("➕ Append to log", key=f"paste-go-{nonce}", on_click=append_pasted,
                               args=(f"paste-text-{nonce}", f"paste-target-{nonce}"), use_container_width=True)
                cols[1].button("🧹 Clear live logs", key=f"paste-clear-{nonce}", on_click=clear_live_logs_ui,
                               use_container_width=True, help="Empty all three files and start again")
                if paste_note:
                    st.success(paste_note)
                if paste_warn:
                    st.warning(paste_warn)

    scans = history.list_scans()
    active = st.session_state.get("scan", {}).get("id")
    with st.expander(f"🕘 Scan history ({len(scans)})", expanded=False):
        if not scans:
            st.caption("No saved scans yet. Each assessment you run is saved here.")
        # a long history scrolls inside a fixed-height box instead of stretching the sidebar
        with st.container(height=HISTORY_BOX_PX if len(scans) > HISTORY_SCROLL_AFTER else "content"):
            for sc in scans:
                when = sc["created_at"].replace("T", " ")[:16]
                st.button(
                    f"{SEV_ICON.get(sc['risk'], '')} {sc['name']}",
                    key=f"open-{sc['id']}", on_click=open_scan, args=(sc["id"],), use_container_width=True,
                    type="primary" if sc["id"] == active else "secondary", help=f"{sc['source']} · open this scan",
                )
                st.caption(f"{when} UTC · {sc['incidents']} incidents")
        if active:
            st.button("Delete the open scan", key="del-active", on_click=delete_scan, args=(active,),
                      use_container_width=True)
    st.markdown(APP_CSS + (f"<style>{key_box_css}</style>" if key_box_css else ""), unsafe_allow_html=True)

# ---- header: title, then the banner (a still when idle, an animated GIF while any scan is running) ----
st.title(f"🛡️ {app_title()}")
st.markdown(
    f'<div class="sa-tagline" style="color:{tagline_color()}">Five AI agents for detection, intel, scanning, '
    f"response and compliance. <span class='sa-pulse-text' style='color:{cta_color()}'>"
    "(Scan your GitHub Repositories, own logs, code and config files now)</span>"
    f"<br><span class='sa-knowledge'>📚 {html.escape(knowledge_text())}</span></div>",
    unsafe_allow_html=True,
)
if scanning:
    st.image(str(BANNER_SCAN), width="stretch")  # untouched, so the GIF keeps animating
else:
    st.image(str(BANNER_STILL), width="stretch", output_format="PNG")  # PNG: no JPEG blur


# ---- run the graph with a live agent trace ----------------------------------------
def with_repo(base: dict, folder: str, excludes: str) -> tuple[dict, dict]:
    """Fill the input slots from a scanned folder; logs from the base inputs and the folder are both kept."""
    repo_inputs, found = collect_repo_inputs(folder.strip(), excludes, use_ignore_files=False)
    merged = {**base, **{k: v for k, v in repo_inputs.items() if v and k != "log_paths"},
              "log_paths": base["log_paths"] + repo_inputs["log_paths"]}
    return merged, found


@contextmanager
def llm_enabled(on: bool):
    router = get_router()
    previous, router.enabled = router.enabled, on
    try:
        yield
    finally:
        router.enabled = previous


def run_assessment(inputs: dict, name: str, source_label: str, use_llm: bool = True) -> None:
    """Stream the five agents with the animated trace, then save the result and make it the open scan.

    ``use_llm=False`` keeps every agent on its rule-based output: same detections and counters, no model calls.
    """
    state: dict = {}
    trace: list = []
    get_router().calls.clear()
    get_router().redactions.clear()
    done: set[str] = set()
    with llm_enabled(use_llm), st.status("Agents working...", expanded=True) as status:
        banner = st.empty()
        banner.markdown(pipeline_html(None, done), unsafe_allow_html=True)
        for node, update in stream(inputs):
            if node in PIPELINE:
                done.add(node)
            working: set[str] = set()
            if node == "supervisor" and update.get("next_agent"):
                # the supervisor just dispatched a wave: every agent in it is working now, at the same time
                working = set(update.get("next_agents") or [update["next_agent"]])
            elif node in AFTER:
                working = {AFTER[node]}  # a review step finished, the next one starts
            if working:
                banner.markdown(pipeline_html(working, done), unsafe_allow_html=True)
                names = " + ".join(AGENT_LABEL.get(n, n) for n in sorted(working))
                status.update(label=f"{names} working{' in parallel' if len(working) > 1 else ''}...", expanded=True)
            for t in update.get("trace", []):
                trace.append(t)
                st.write(f"**{AGENT_LABEL.get(t['agent'], t['agent'])}**: {t['message']}")
            state.update({k: v for k, v in update.items() if k not in ("trace", "completed")})
        banner.markdown(pipeline_html(None, done), unsafe_allow_html=True)
        status.update(label="Assessment complete", state="complete", expanded=True)
    state["trace"] = trace
    state["llm_calls"] = list(get_router().calls)
    state["redactions"] = get_router().redaction_total  # secrets / personal data removed from what the models were sent
    scan_id = history.save(state, name, source_label)
    st.session_state["result"] = state
    st.session_state["scan"] = {k: v for k, v in history.load(scan_id).items() if k != "result"}
    st.session_state.pop("chat", None)


if run:
    if key_missing:
        st.toast(f"No API key found for {chosen}: running without it", icon="🚨")
    if repo_folder.strip() and not repo_path:
        st.error("The folder path or link in the sidebar could not be opened. Fix it, or clear it to scan the other inputs.")
        st.stop()
    if live_on and not sim_on and not repo_path:
        inputs = {**inputs, "log_paths": live_log_paths()}  # analyse what Live scan is following, not the demo logs
    if repo_path:
        try:
            inputs, found = with_repo(inputs, repo_path, repo_excludes)
        except OSError as exc:
            st.error(str(exc))
            st.stop()
        st.info(f"📁 Scanning {repo_info.label}: {found['logs']} log file(s), {found['python']} Python file(s), "
                f"{found['requirements']} requirements, {found['dockerfiles']} Dockerfile(s), {found['configs']} config file(s).")
    run_assessment(inputs, scan_name, source)
    st.rerun()  # refresh the sidebar history with the new scan


# ---- live scan: follow the logs and alert on new attacks --------------------------
def start_live(mode: str, folder: str, excludes: str, sig: tuple) -> dict | None:
    feed = None
    try:
        if mode == "demo":
            feed = ReplayFeed(default_inputs()["log_paths"])
            tailer = LogTailer(feed.paths, baseline=False)
        elif mode == "files":
            tailer = LogTailer(live_log_paths(), baseline=True)
        else:
            paths = find_logs(folder.strip(), excludes)
            if not paths:
                st.warning("No .log files found in that folder (check the exclude list).")
                return None
            tailer = LogTailer(paths, baseline=True)  # what is already in the files is not an alert
    except OSError as exc:
        st.error(str(exc))
        return None
    # real files: take a baseline assessment right away so the counters exist, except when only restarting after Clear
    baseline = mode != "demo" and not st.session_state.pop("skip_baseline", False)
    live = {"sig": sig, "feed": feed, "tailer": tailer, "alerts": [], "n": 0, "last_run": 0.0, "last_run_at": "",
            "pending": baseline}
    st.session_state["live"] = live
    return live


def live_panel(mode: str, folder: str, excludes: str, base_inputs: dict, source_label: str,
               interval: int, auto_assess: bool, use_llm: bool) -> None:
    live = st.session_state.get("live")
    if not live or live["sig"] != (mode, folder, excludes):
        live = start_live(mode, folder, excludes, (mode, folder, excludes))
        if live is None:
            return
    feed, tailer = live["feed"], live["tailer"]
    if feed:
        feed.advance()
    # Lines the user just added by hand are checked on their own first: an attack the tailer has already reported would
    # otherwise stay silent (it alerts once), which makes a second paste or a second example look like it did nothing.
    batch = st.session_state.pop("live_batch", None)
    repeats = [e for e in detect_named(batch) if event_key(e) in tailer.seen] if batch else []
    fresh = tailer.poll()  # new attacks, found by the tailer as usual (disjoint from `repeats`: those were already seen)
    for e in [*repeats, *fresh]:
        live["n"] += 1
        alert = to_alert(e, live["n"])
        alert["repeat"] = e in repeats
        live["alerts"].insert(0, alert)
        st.toast(f"{alert['severity']}: {alert['type']}" + (" (repeat)" if alert["repeat"] else ""),
                 icon=SEV_ICON.get(alert["severity"], "⚠️"))
    if fresh or repeats:
        live["pending"] = True  # any new attack refreshes the dashboard counters

    with st.container(border=True):
        st.markdown(f'<span class="sa-live"><span class="sa-dot on"></span>LIVE SCAN · checking every {interval}s</span>',
                    unsafe_allow_html=True)
        c = st.columns(4)
        c[0].metric("Files watched", len(tailer.paths))
        c[1].metric("Lines read", f"{tailer.lines_read:,}")
        c[2].metric("Detections", len(tailer.events))
        c[3].metric("New alerts", len(live["alerts"]))
        if feed:
            st.progress(feed.progress, text="Simulation: replaying the demo logs" + (" (finished)" if feed.done else ""))
        elif mode == "files":
            st.caption(f"Following `{current_live_dir()}`. Paste attack lines in the sidebar's **Test it** box.")
        elif st.session_state.get("repo_remote"):
            st.caption("This is a downloaded snapshot, so it does not change and Live scan only shows what it already holds. "
                       "To monitor logs as they grow, use a local folder or a network share.")
        else:
            st.caption(f"Following the log files in `{folder.strip()}`.")
        per_file = " · ".join(f"{n}: {c} lines, {tailer.recognised_by_file.get(n, 0)} understood"
                              for n, c in tailer.current_by_file.items()) or "no lines yet"
        st.caption(f"{per_file}. Last checked {datetime.now():%H:%M:%S}.")
        # Lines no parser understands are skipped silently, so say so (and where they belong) instead of looking idle.
        file_for = {kind: name for kind, name in KIND_FILE.items()}
        ignored_somewhere = False
        for name in tailer.current_by_file:
            bad = tailer.unrecognised(name)
            if not bad:
                continue
            ignored_somewhere = True
            wrong = tailer.misfiled.get(name)
            if wrong:
                belongs = ", ".join(f"{n} look like {file_for[k]} lines" for k, n in wrong.items())
                st.warning(f"{name}: {bad} line(s) are ignored. {belongs}, which this file's parser cannot read. "
                           f"Move them to the right file, or paste with Auto-detect.")
            else:
                st.warning(f"{name}: {bad} line(s) are not in a format the detectors understand, so they are ignored. "
                           f"Expected: `{FORMAT_EXAMPLES.get(name, 'a syslog, nginx access or UFW line')}`")
        if ignored_somewhere and mode == "files":  # only the app's own test folder is ever rewritten, never a real log
            st.button("🧹 Fix the live logs", key="live-fix", on_click=fix_live_logs, type="primary",
                      help="Keeps the lines the detectors read, moves lines that belong in another log to it, and removes "
                           "the rest (for example text copied from a README). Only touches the live_logs folder.")
        for msg in tailer.building_up():
            st.info(f"⏳ {msg}.")
        if tailer.lines_read and not live["alerts"] and not tailer.building_up() and not ignored_somewhere:
            st.caption("The lines were understood but match no attack pattern yet. The rules look for patterns, e.g. a "
                       "web request carrying SQL injection or Log4Shell, a root-level account being created, a port scan "
                       "across 10+ ports, or 10+ failed SSH logins from one IP. Samples: `samples/live_examples/`.")
        if tailer.recent:
            with st.expander(f"Latest lines read ({len(tailer.recent)})"):
                for name, line, ok in reversed(tailer.recent):
                    st.markdown(f"{'✅' if ok else '⚠️'} `{name}` · `{line[:140]}`")
        res = st.session_state.get("result")
        if res:  # the same counters as the Overview tab, refreshed after every live assessment
            k = st.columns(4)
            k[0].metric("Incidents", len(res.get("incident_plan", {}).get("incidents", [])))
            k[1].metric("Log detections", len(res.get("log_findings", {}).get("events", [])))
            k[2].metric("Code & config findings", len(res.get("vuln_findings", {}).get("findings", [])))
            k[3].metric("CVEs affecting us", len(res.get("threat_intel", {}).get("cve_matches", [])))
            st.caption("Dashboard counters" + (f" as of the last assessment at {live['last_run_at']}." if live["last_run_at"]
                                               else " from the open scan."))
        elif auto_assess:
            st.caption("Dashboard counters appear after the first assessment, which starts automatically.")
        for a in live["alerts"][:15]:
            box = st.error if a["severity"] == "CRITICAL" else st.warning if a["severity"] == "HIGH" else st.info
            who = a.get("src_ip") or a.get("target", "")
            head = (f"**{a['id']} · {a['severity']} · {a['type']}** · {who} · {a['detected_at']}"
                    + (" · ↻ added again" if a.get("repeat") else ""))
            box(head + "\n\n" + a["description"],
                icon=SEV_ICON.get(a["severity"], "⚠️"))
        if live["pending"] and auto_assess:
            wait = LIVE_ASSESS_GAP - (time.time() - live["last_run"])
            if wait > 0:
                st.caption(f"Dashboard refresh queued, starts in {int(wait)}s.")

    if auto_assess and live["pending"] and time.time() - live["last_run"] >= LIVE_ASSESS_GAP:
        live["pending"], live["last_run"] = False, time.time()
        live["last_run_at"] = f"{datetime.now():%H:%M:%S}"
        if mode == "folder":
            run_inputs = with_repo(base_inputs, folder, excludes)[0]
        else:  # simulation temp copy or live_logs/: analyse exactly the files being followed
            run_inputs = {**base_inputs, "log_paths": [str(p) for p in tailer.paths]}
        run_assessment(run_inputs, f"🔴 Live alert · {datetime.now():%d %b %H:%M:%S}", f"Live scan ({source_label})", use_llm)
        st.rerun(scope="app")


if live_on:
    # simulation replays the demo logs; else follow a folder's real logs; else follow live_logs/ (paste target)
    live_mode = "demo" if sim_on else "folder" if repo_path else "files"
    st.fragment(run_every=live_interval)(live_panel)(
        live_mode, repo_path, repo_excludes, inputs, source, live_interval, live_auto, live_llm)

result = st.session_state.get("result")
if not result:
    welcome, agent_tab = st.tabs(["Welcome", "🤖 Agent"])  # the agent works before any assessment: knowledge, log analysis
    with welcome:
        st.header("AI-powered security operations")
        st.markdown(
            "Press **Run assessment** to have the agents analyze the demo environment: a web server that was "
            "scanned, probed with SQL injection and Log4Shell, brute-forced over SSH and backdoored.\n\n"
            "| Agent | Job |\n|---|---|\n"
            "| 📜 Log Monitor | Detects attacks and anomalies in auth, web and firewall logs |\n"
            "| 🔍 Vulnerability Scanner | Scans code (Bandit), secrets, Dockerfile and dependencies |\n"
            "| 🌐 Threat Intelligence | Matches CVEs, IOCs and ATT&CK via agentic RAG; answers *are we affected?* |\n"
            "| 🚨 Incident Response | Declares incidents and writes a NIST 800-61 playbook |\n"
            "| 📋 Policy Checker | Scores NIST 800-53, NIST CSF 2.0, ISO 27001 and SOC 2 |"
        )
    with agent_tab:
        agent_ui.render({}, nonce)
    show_footer()
    st.stop()

scan = st.session_state.get("scan")
if scan:
    st.caption(f"🕘 **{scan['name']}** · {scan['source']} · {scan['created_at'].replace('T', ' ')[:16]} UTC")

logs, vulns = result.get("log_findings", {}), result.get("vuln_findings", {})
intel, ir, comp = result.get("threat_intel", {}), result.get("incident_plan", {}), result.get("compliance", {})

tabs = st.tabs(["Overview", "📜 Logs", "🌐 Threat Intel", "🔍 Vulnerabilities", "🚨 Response", "📋 Compliance", "💬 Ask", "📝 Report", "🤖 Agent"])

with tabs[0]:
    c = st.columns([1.5, 1, 1, 1.2, 1.2])
    c[0].metric("Overall risk", sev(intel.get("overall_risk", "n/a")))
    c[1].metric("Incidents", len(ir.get("incidents", [])), help=f"Highest priority {ir.get('highest_priority')}")
    c[2].metric("Log detections", len(logs.get("events", [])))
    c[3].metric("Code & config findings", len(vulns.get("findings", [])))
    c[4].metric("CVEs affecting us", len(intel.get("cve_matches", [])))
    if review_ui.confidence_line(result):
        st.caption(review_ui.confidence_line(result)
                   + (f" · 🛡️ {result['redactions']} secret/personal-data value(s) removed before the models" if result.get("redactions") else ""))
    review_ui.critic_panel(result)
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Incident briefing")
        st.markdown(ir.get("briefing", ""))
    with right:
        st.subheader("Compliance score")
        df = pd.DataFrame(comp.get("frameworks", []))
        if not df.empty:
            bars = alt.Chart(df).mark_bar(color=BAR_COLOR, cornerRadiusEnd=4, height=18).encode(
                x=alt.X("score:Q", scale=alt.Scale(domain=[0, 100]), title="Score (%)"),
                y=alt.Y("framework:N", sort="-x", title=None),
                tooltip=["framework", "score", "pass", "partial", "fail"],
            )
            labels = bars.mark_text(align="left", dx=4).encode(text=alt.Text("score:Q", format=".0f"))
            st.altair_chart((bars + labels).properties(height=180), use_container_width=True)
        st.subheader("Attacker IPs")
        st.write(", ".join(f"`{ip}`" for ip in logs.get("attackers", [])) or "None")
    with st.expander("Agent trace"):
        for t in result.get("trace", []):
            st.write(f"`{t['ts']}` **{AGENT_LABEL.get(t['agent'], t['agent'])}**: {t['message']}")
        if result.get("llm_calls"):
            st.dataframe(pd.DataFrame(result["llm_calls"]), hide_index=True, use_container_width=True)

with tabs[1]:
    st.markdown(logs.get("narrative", ""))
    if logs.get("techniques"):
        st.caption("MITRE ATT&CK: " + " · ".join(f"{t['id']} {t['name']}" for t in logs["techniques"]))
    for e in logs.get("events", []):
        with st.expander(f"{SEV_ICON.get(e['severity'], '')} {e['id']} · {e['type']} · {e.get('src_ip', '')}"):
            st.write(e["description"])
            st.caption(f"{e.get('first_seen', '')} → {e.get('last_seen', '')} · source {e['source']} · ATT&CK {', '.join(e.get('mitre', []))}")
            st.code("\n".join(e.get("evidence", [])), language="log")

with tabs[2]:
    st.markdown(intel.get("summary", ""))
    st.subheader("Attacks that hit real weaknesses")
    st.dataframe(pd.DataFrame(intel.get("correlations", [])), hide_index=True, use_container_width=True)
    st.subheader("CVEs affecting deployed components")
    st.dataframe(review_ui.cve_frame(intel), hide_index=True, use_container_width=True)
    a, b = st.columns(2)
    a.subheader("Exploit attempts")
    a.dataframe(pd.DataFrame(intel.get("exploit_attempts", [])), hide_index=True, use_container_width=True)
    b.subheader("Known-bad indicators")
    b.dataframe(pd.DataFrame(intel.get("ioc_hits", [])), hide_index=True, use_container_width=True)
    with st.expander("Agentic RAG trace"):
        st.write(intel.get("rag_trace", []))

with tabs[3]:
    df = pd.DataFrame(vulns.get("findings", []))
    if not df.empty:
        cats = st.multiselect("Category", sorted(df["category"].unique()), default=sorted(df["category"].unique()))
        df = df[df["category"].isin(cats)]
        df["severity"] = df["severity"].map(sev)
        cols = [c for c in ["id", "severity", "category", "title", "file", "line", "cwe", "tool", "snippet"] if c in df]
        st.dataframe(df[cols], hide_index=True, use_container_width=True)
    st.subheader("Suggested fixes")
    st.markdown(vulns.get("remediation", ""))
    with st.expander("Software inventory"):
        st.dataframe(pd.DataFrame(vulns.get("inventory", [])), hide_index=True, use_container_width=True)

with tabs[4]:
    for inc in ir.get("incidents", []):
        st.markdown(f"**{sev(inc['severity'])} {inc['id']} [{inc['priority']}] {inc['title']}**  \n{inc['summary']}")
        review_ui.similar_past(inc)
    review_ui.correlation_panel(result)
    st.divider()
    review_ui.gate_panel(result, scan, (st.session_state["visitor"].identity.label if settings.public else "local user"), nonce)
    st.divider()
    phase = None
    for s in ir.get("steps", []):
        if s["phase"] != phase:
            phase = s["phase"]
            st.subheader(phase)
        label = f"**{s['priority']}** {s['action']} · _{s['owner']}_" + (" · 🤖 suggested" if s.get("source") == "llm" else "")
        st.checkbox(label, key=f"step-{(scan or {}).get('id', '')}-{s['step']}")
        if s.get("command"):
            st.code(s["command"], language="bash")

with tabs[5]:
    st.markdown(comp.get("roadmap", ""))
    frameworks = ["All"] + [f["framework"] for f in comp.get("frameworks", [])]
    pick = st.selectbox("Framework", frameworks)
    rows = [c for c in comp.get("controls", []) if pick == "All" or c["framework"] == pick]
    st.dataframe(
        pd.DataFrame([{"Status": f"{STATUS_ICON[c['status']]} {c['status']}", "Framework": c["framework"], "Control": c["id"],
                       "Title": c["title"], "Evidence": c["evidence"]} for c in rows]),
        hide_index=True, use_container_width=True,
    )
    with st.expander("Technical checks"):
        st.dataframe(pd.DataFrame(comp.get("checks", [])), hide_index=True, use_container_width=True)

with tabs[6]:
    st.caption("Ask a question; it is routed to the relevant agents' results and grounded with RAG.")
    chat = st.session_state.setdefault("chat", [])
    for role, text in chat:
        st.chat_message(role).markdown(text)
    q = st.chat_input("e.g. Are we affected by Log4Shell? What should we do in the next hour?")
    if q:
        st.chat_message("user").markdown(q)
        with st.spinner("Agents thinking..."):
            ans = ask(q, result)
        reply = ans["answer"] + f"\n\n_Agents: {', '.join(ans['agents'])} · sources: {', '.join(ans['sources'])}_"
        st.chat_message("assistant").markdown(reply)
        chat += [("user", q), ("assistant", reply)]

with tabs[7]:
    report = result.get("report_md", "")
    meta = scan or {}
    st.caption("Download the report as Word, Excel (one sheet per table), PDF or Markdown, or the raw results as JSON.")
    cols = st.columns(5)
    cols[0].download_button("⬇ Word (.docx)", data=lambda: export("docx", result, meta), file_name="security_report.docx",
                            mime=EXPORT_MIME["docx"], on_click="ignore", use_container_width=True)
    cols[1].download_button("⬇ Excel (.xlsx)", data=lambda: export("xlsx", result, meta), file_name="security_report.xlsx",
                            mime=EXPORT_MIME["xlsx"], on_click="ignore", use_container_width=True)
    cols[2].download_button("⬇ PDF", data=lambda: export("pdf", result, meta), file_name="security_report.pdf",
                            mime=EXPORT_MIME["pdf"], on_click="ignore", use_container_width=True)  # built only when clicked
    cols[3].download_button("⬇ Markdown", report, "security_report.md", on_click="ignore", use_container_width=True)
    cols[4].download_button("⬇ JSON", json.dumps(result, indent=2, default=str), "security_results.json",
                            on_click="ignore", use_container_width=True)
    st.markdown(report)

with tabs[8]:
    agent_ui.render(result, nonce)

show_footer()
