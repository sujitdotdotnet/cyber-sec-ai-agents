"""Web API for the five agents: the ASGI entrypoint for Vercel (and any ASGI host).

    uvicorn secagents.web:app          # local
    pyproject.toml: [tool.vercel] entrypoint = "secagents.web:app"

Streamlit cannot run on serverless platforms (it needs a long-lived server and a WebSocket), so this API is
the part that can: send log / code / config text, get the assessment back as JSON or as a Word, Excel, PDF or
Markdown report. It takes file *contents* only, never server paths, so nothing on the host can be read.

Safe defaults for a public URL: the LLM is off unless the operator allows it (a stranger must not spend your
credits), request size and file counts are capped, and ``SECAGENTS_API_TOKEN`` (if set) is required as a
bearer token.
"""

from __future__ import annotations

import hmac
import json
import os
import tempfile
import threading
from pathlib import Path, PurePosixPath

# Serverless filesystems are read-only except /tmp, so point the writable stores there before the config loads.
if os.getenv("VERCEL"):
    os.environ.setdefault("CHROMA_DIR", "/tmp/secagents-chroma")
    os.environ.setdefault("HISTORY_DIR", "/tmp/secagents-history")
    os.environ.setdefault("LIVE_LOGS_DIR", "/tmp/secagents-live-logs")

from fastapi import Depends, FastAPI, Header, HTTPException, Response  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from . import __version__  # noqa: E402
from .exporters import MIME, export  # noqa: E402
from .graph import default_inputs, run  # noqa: E402
from .llm import get_router  # noqa: E402

MAX_TOTAL_CHARS = 2_000_000  # all submitted text together
MAX_FILES = 50
LOG_NAMES_HINT = "auth.log, nginx_access.log (or access.log), firewall.log (or ufw.log)"

app = FastAPI(
    title="SecAgents API", version=__version__,
    description="Five cooperating security agents: Log Monitor, Threat Intelligence, Vulnerability Scanner, "
                "Incident Response and Policy Checker.",
)
_run_lock = threading.Lock()  # the agents share one router and knowledge base per instance: run one assessment at a time


class AssessRequest(BaseModel):
    demo: bool = Field(False, description="Analyse the built-in attack scenario instead of your own data.")
    logs: dict[str, str] = Field(default_factory=dict, description=f"File name -> log text. The name picks the parser: {LOG_NAMES_HINT}.")
    code: dict[str, str] = Field(default_factory=dict, description="Relative path -> Python source to scan.")
    requirements: str = Field("", description="requirements.txt contents (software inventory and CVE matching).")
    dockerfile: str = Field("", description="Dockerfile contents.")
    config_yaml: str = Field("", description="System configuration YAML for the compliance checks.")
    use_llm: bool = Field(False, description="Use the LLM for narratives. Ignored unless the server allows it (SECAGENTS_API_ALLOW_LLM=1).")


def require_token(authorization: str | None = Header(default=None)) -> None:
    expected = os.getenv("SECAGENTS_API_TOKEN", "")
    if not expected:
        return
    given = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(given.encode(), expected.encode()):
        raise HTTPException(401, "Missing or wrong bearer token.", headers={"WWW-Authenticate": "Bearer"})


def _safe_relative(name: str) -> str:
    """A file name from the request, confined to the temp folder: no absolute paths, no '..', no empty names."""
    p = PurePosixPath(name.replace("\\", "/"))
    if not name.strip() or p.is_absolute() or ".." in p.parts or p.parts[0].endswith(":"):
        raise HTTPException(422, f"Invalid file name: {name!r}")
    return str(p)


def _stage(req: AssessRequest, root: Path) -> dict:
    texts = [*req.logs.values(), *req.code.values(), req.requirements, req.dockerfile, req.config_yaml]
    if sum(len(t) for t in texts) > MAX_TOTAL_CHARS:
        raise HTTPException(413, f"Too much text: the limit is {MAX_TOTAL_CHARS:,} characters in total.")
    if len(req.logs) + len(req.code) > MAX_FILES:
        raise HTTPException(413, f"Too many files: the limit is {MAX_FILES}.")

    inputs: dict = {"log_paths": [], "code_path": "", "requirements_path": "", "dockerfile_path": "", "config_path": ""}
    for name, content in req.logs.items():
        rel = _safe_relative(name)
        if "/" in rel:
            raise HTTPException(422, f"Log names must be plain file names, got {name!r}.")
        (root / rel).write_text(content, encoding="utf-8")
        inputs["log_paths"].append(str(root / rel))
    if req.code:
        for name, content in req.code.items():
            dest = root / "code" / _safe_relative(name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
        inputs["code_path"] = str(root / "code")
    for field_, filename, key in ((req.requirements, "requirements.txt", "requirements_path"),
                                  (req.dockerfile, "Dockerfile", "dockerfile_path"),
                                  (req.config_yaml, "system_config.yaml", "config_path")):
        if field_.strip():
            (root / filename).write_text(field_, encoding="utf-8")
            inputs[key] = str(root / filename)
    return inputs


def _assess(req: AssessRequest) -> dict:
    llm_allowed = os.getenv("SECAGENTS_API_ALLOW_LLM") == "1"
    with tempfile.TemporaryDirectory(prefix="secagents-api-") as tmp:
        if req.demo:
            inputs = default_inputs()
        else:
            inputs = _stage(req, Path(tmp))
            if not any(inputs.values()):
                raise HTTPException(422, "Nothing to analyse: send logs, code, requirements, dockerfile or config_yaml, or set demo=true.")
        router = get_router()
        with _run_lock:
            previous, router.enabled = router.enabled, bool(req.use_llm and llm_allowed)
            try:
                state = run(inputs)
            finally:
                router.enabled = previous
    return json.loads(json.dumps(state, default=str))


def _summary(state: dict) -> dict:
    ir, intel = state.get("incident_plan", {}), state.get("threat_intel", {})
    return {
        "overall_risk": intel.get("overall_risk", "n/a"),
        "incidents": len(ir.get("incidents", [])),
        "highest_priority": ir.get("highest_priority", "n/a"),
        "log_detections": len(state.get("log_findings", {}).get("events", [])),
        "code_config_findings": len(state.get("vuln_findings", {}).get("findings", [])),
        "cves_affecting_us": len(intel.get("cve_matches", [])),
        "compliance": {f["framework"]: f["score"] for f in state.get("compliance", {}).get("frameworks", [])},
    }


@app.get("/health")
def health() -> dict:
    return {"ok": True, "version": __version__, "llm_enabled_on_server": os.getenv("SECAGENTS_API_ALLOW_LLM") == "1",
            "auth_required": bool(os.getenv("SECAGENTS_API_TOKEN"))}


@app.post("/api/assess", dependencies=[Depends(require_token)])
def assess(req: AssessRequest) -> dict:
    """Run all five agents and return a summary plus the full results."""
    state = _assess(req)
    return {"summary": _summary(state), "result": state}


@app.post("/api/export/{fmt}", dependencies=[Depends(require_token)])
def export_report(fmt: str, req: AssessRequest) -> Response:
    """Run the assessment and return the report as docx, xlsx, pdf or md."""
    if fmt not in (*MIME, "md"):
        raise HTTPException(404, "Format must be one of: docx, xlsx, pdf, md.")
    state = _assess(req)
    body = state.get("report_md", "").encode("utf-8") if fmt == "md" else export(fmt, state, {})
    return Response(body, media_type="text/markdown" if fmt == "md" else MIME[fmt],
                    headers={"Content-Disposition": f'attachment; filename="security_report.{fmt}"'})


_LANDING = """<!doctype html><meta charset="utf-8"><title>SecAgents API</title>
<style>body{font:16px/1.5 system-ui;max-width:46rem;margin:3rem auto;padding:0 1rem;color:#1f2937}
code,pre{background:#f3f4f6;border-radius:6px}code{padding:.1rem .3rem}pre{padding:.8rem;overflow:auto}h1{color:#1f3a5f}</style>
<h1>🛡️ SecAgents API</h1>
<p>Five cooperating security agents (Log Monitor, Threat Intelligence, Vulnerability Scanner, Incident Response,
Policy Checker). Interactive docs: <a href="/docs">/docs</a>. Health: <a href="/health">/health</a>.</p>
<p>Try the built-in attack scenario:</p>
<pre>curl -X POST $URL/api/assess -H "content-type: application/json" -d '{"demo": true}'</pre>
<p>Your own data, as a PDF report:</p>
<pre>curl -X POST $URL/api/export/pdf -H "content-type: application/json" -o report.pdf \\
  -d '{"logs": {"auth.log": "Oct  9 10:05:04 web-01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"}}'</pre>
<p>Formats: <code>docx</code>, <code>xlsx</code>, <code>pdf</code>, <code>md</code>. The interactive dashboard with Live scan is the Streamlit app
(<code>streamlit run app/streamlit_app.py</code>); it needs a host that runs a long-lived server.</p>"""


@app.get("/", response_class=HTMLResponse)
def landing() -> str:
    return _LANDING
