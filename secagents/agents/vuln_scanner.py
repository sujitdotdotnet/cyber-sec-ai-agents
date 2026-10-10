"""Vulnerability Scanner Agent: static analysis of code, secrets, Dockerfile and dependency inventory.

Uses Bandit for Python SAST when available (regex rules otherwise), its own secret and Dockerfile
checks, and Trivy if it is installed. It builds the software inventory that the Threat
Intelligence Agent matches against CVE data, and asks the LLM for concrete fixes.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from ..llm import get_router
from .base import severity_counts, sort_by_severity, trace_event

AGENT = "vuln_scanner"

FALLBACK_SAST = [
    ("B608", "SQL built by string concatenation", "HIGH", "CWE-89", re.compile(r"execute\(\s*[\"'].*(SELECT|INSERT|UPDATE|DELETE).*[\"']\s*\+", re.I)),
    ("B602", "subprocess call with shell=True", "HIGH", "CWE-78", re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True")),
    ("B506", "yaml.load with unsafe Loader", "HIGH", "CWE-502", re.compile(r"yaml\.load\((?!.*SafeLoader)")),
    ("B324", "Weak hash (MD5/SHA1) for security", "MEDIUM", "CWE-327", re.compile(r"hashlib\.(md5|sha1)\(")),
    ("B201", "Flask app run with debug=True", "HIGH", "CWE-94", re.compile(r"\.run\(.*debug\s*=\s*True")),
    ("B501", "TLS verification disabled", "HIGH", "CWE-295", re.compile(r"verify\s*=\s*False")),
    ("B104", "Binding to all interfaces", "MEDIUM", "CWE-605", re.compile(r"host\s*=\s*[\"']0\.0\.0\.0")),
]
SECRET_RULES = [
    ("AWS secret access key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})")),
    ("AWS access key id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("Hardcoded password", re.compile(r"(?i)\b\w*(password|passwd|pwd)\w*\s*[=:]\s*[\"']?([^\s\"']{4,})")),
    ("Hardcoded secret key", re.compile(r"(?i)\b(secret_key|api_key|token)\b[\"']?\s*\]?\s*[=:]\s*[\"']([^\"']{8,})")),
    ("Private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
# Patterns Bandit does not cover; always run alongside it.
EXTRA_SAST = [
    ("PATH-TRAVERSAL", "File path built from request input (path traversal)", "HIGH", "CWE-22",
     re.compile(r"(send_file|open)\(\s*os\.path\.join\(")),
]
# Bandit rates some directly exploitable classes MEDIUM; raise them for triage.
SEVERITY_FLOOR = {"B506": "HIGH", "CWE-89": "HIGH", "CWE-78": "HIGH", "CWE-502": "HIGH", "CWE-22": "HIGH"}
EOL_IMAGES = {"python:2": "2020-01-01", "python:3.6": "2021-12-23", "python:3.7": "2023-06-27", "python:3.8": "2024-10-07", "node:14": "2023-04-30", "node:16": "2023-09-11", "ubuntu:18.04": "2023-05-31", "debian:buster": "2024-06-30"}


def _finding(**kw: Any) -> dict[str, Any]:
    kw.setdefault("severity", "MEDIUM")
    return kw


# ---- SAST ----------------------------------------------------------------------
def run_bandit(code_path: Path) -> list[dict[str, Any]] | None:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", str(code_path), "-f", "json", "-q"],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    if "results" not in data:
        return None
    out = []
    for r in data["results"]:
        out.append(_finding(
            category="code", tool="bandit", rule=r["test_id"], title=r["issue_text"],
            severity=r["issue_severity"], confidence=r["issue_confidence"],
            cwe=f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else "",
            file=Path(r["filename"]).name, line=r["line_number"], snippet=r["code"].strip()[:300],
        ))
    return out


def regex_sast(code_path: Path, rules=FALLBACK_SAST) -> list[dict[str, Any]]:
    out = []
    for f in code_path.rglob("*.py"):
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            for rule, title, sev, cwe, rx in rules:
                if rx.search(line):
                    out.append(_finding(category="code", tool="regex", rule=rule, title=title, severity=sev, cwe=cwe, file=f.name, line=n, snippet=line.strip()))
    return out


def _is_literal_secret(title: str, m: re.Match[str], suffix: str) -> bool:
    """Reject password 'matches' whose value is code (f-string braces, calls, indexing, ...) rather than a literal."""
    if title != "Hardcoded password":
        return True
    value = m.group(2)
    if any(c in value for c in "{}()[]$<>,"):
        return False
    if suffix == ".py":  # in Python source a real literal is quoted; a bare name is just a variable
        return m.string[m.start(2) - 1] in "\"'"
    return True


def scan_secrets(root: Path) -> list[dict[str, Any]]:
    out, seen = [], set()
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and p.suffix in {".py", ".env", ".yaml", ".yml", ".json", ".cfg", ".ini", ""}]
    for f in files:
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            for title, rx in SECRET_RULES:
                m = rx.search(line)
                if m and _is_literal_secret(title, m, f.suffix) and (f.name, n) not in seen:
                    seen.add((f.name, n))
                    redacted = re.sub(r"([\"'=:]\s*[\"']?)([^\s\"']{4})[^\s\"']*", r"\1\2****", line.strip())
                    out.append(_finding(category="secret", tool="secret-scan", rule="SECRET", title=f"{title} committed to source",
                                        severity="HIGH", cwe="CWE-798", file=f.name, line=n, snippet=redacted[:200]))
    return out


# ---- Dockerfile ----------------------------------------------------------------
def scan_dockerfile(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    text = path.read_text()
    lines = text.splitlines()
    findings: list[dict[str, Any]] = []
    image = ""

    def add(rule: str, title: str, sev: str, n: int, fix: str) -> None:
        findings.append(_finding(category="container", tool="dockerfile-lint", rule=rule, title=title, severity=sev,
                                 file=path.name, line=n, snippet=lines[n - 1].strip() if n else "", fix=fix))

    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        upper = line.upper()
        if upper.startswith("FROM "):
            image = line.split()[1]
            if ":" not in image or image.endswith(":latest"):
                add("DL3007", "Base image uses an unpinned or :latest tag", "MEDIUM", n, "Pin a specific version and digest.")
            for eol, date in EOL_IMAGES.items():
                if image == eol or image.startswith(eol + "-") or image.startswith(eol + "."):
                    add("EOL-IMAGE", f"Base image {image} is end-of-life since {date} (no security patches)", "HIGH", n, "Move to a supported slim image, e.g. python:3.12-slim.")
        elif upper.startswith("ENV ") and re.search(r"(PASSWORD|SECRET|TOKEN|KEY)\w*\s*=", line, re.I):
            add("SECRET-ENV", "Secret baked into image via ENV", "HIGH", n, "Inject secrets at runtime (secrets manager / orchestrator secrets).")
        elif upper.startswith("ADD "):
            add("DL3020", "ADD used instead of COPY", "LOW", n, "Use COPY for local files.")
        elif upper.startswith("EXPOSE ") and re.search(r"\b22\b", line):
            add("SSH-EXPOSED", "SSH port 22 exposed from container", "MEDIUM", n, "Do not run sshd in containers; use docker exec / kubectl exec.")
        elif upper.startswith("RUN ") and "apt-get install" in line and "--no-install-recommends" not in line:
            add("DL3015", "apt-get install without --no-install-recommends", "LOW", n, "Add --no-install-recommends and clean apt lists.")
        elif upper.startswith("CMD ") and not line[4:].strip().startswith("["):
            add("DL3025", "CMD uses shell form", "LOW", n, "Use JSON exec form so signals reach the app.")
    if not any(l.strip().upper().startswith("USER ") for l in lines):
        add("DS002", "Container runs as root (no USER instruction)", "HIGH", 0, "Create an unprivileged user and add USER app.")
    if not any(l.strip().upper().startswith("HEALTHCHECK") for l in lines):
        add("DS026", "No HEALTHCHECK defined", "LOW", 0, "Add a HEALTHCHECK instruction.")
    return findings, {"base_image": image}


def run_trivy(target: Path) -> list[dict[str, Any]]:
    if not shutil.which("trivy"):
        return []
    try:
        proc = subprocess.run(["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig", str(target)],
                              capture_output=True, text=True, timeout=300)
        data = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    out = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            out.append(_finding(category="dependency", tool="trivy", rule=v["VulnerabilityID"], title=v.get("Title", v["VulnerabilityID"]),
                                severity=v.get("Severity", "MEDIUM"), file=res.get("Target", ""), snippet=f"{v['PkgName']} {v.get('InstalledVersion', '')}"))
    return out


# ---- inventory -----------------------------------------------------------------
def parse_requirements(path: Path) -> list[dict[str, str]]:
    pkgs = []
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-]+)", line)
        if m:
            pkgs.append({"name": m[1].lower(), "version": m[2], "ecosystem": "pypi", "source": path.name})
        elif line:
            pkgs.append({"name": re.split(r"[<>=!~\[ ]", line)[0].lower(), "version": "unpinned", "ecosystem": "pypi", "source": path.name})
    return pkgs


def os_inventory(config_path: Path) -> list[dict[str, str]]:
    try:
        cfg = yaml.safe_load(config_path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return []
    pkgs = (cfg.get("os") or {}).get("packages") or {}
    return [{"name": k.lower(), "version": str(v), "ecosystem": "os", "source": config_path.name} for k, v in pkgs.items()]


FIX_SYSTEM = "You are an application security engineer. Explain vulnerabilities briefly and give concrete, minimal code fixes."


def run_vuln_scanner(state: dict[str, Any]) -> dict[str, Any]:
    inp = state.get("inputs", {})
    findings: list[dict[str, Any]] = []
    inventory: list[dict[str, str]] = []
    notes: list[str] = []
    container: dict[str, Any] = {}

    code = Path(inp["code_path"]) if inp.get("code_path") else None
    if code and code.exists():
        bandit = run_bandit(code)
        findings += bandit if bandit is not None else regex_sast(code)
        findings += regex_sast(code, EXTRA_SAST)
        notes.append("SAST: bandit" if bandit is not None else "SAST: regex rules (bandit unavailable)")
        findings += scan_secrets(code)
        findings += run_trivy(code)
    if inp.get("dockerfile_path") and Path(inp["dockerfile_path"]).exists():
        df, container = scan_dockerfile(Path(inp["dockerfile_path"]))
        findings += df
        if container.get("base_image"):
            inventory.append({"name": "base-image", "version": container["base_image"], "ecosystem": "container", "source": "Dockerfile"})
    if inp.get("requirements_path") and Path(inp["requirements_path"]).exists():
        reqs = parse_requirements(Path(inp["requirements_path"]))
        inventory += reqs
        for p in reqs:
            if p["version"] == "unpinned":
                findings.append(_finding(category="dependency", tool="inventory", rule="UNPINNED", title=f"Dependency {p['name']} is not pinned", severity="LOW", file=p["source"]))
    if inp.get("config_path") and Path(inp["config_path"]).exists():
        inventory += os_inventory(Path(inp["config_path"]))

    for f in findings:
        floor = SEVERITY_FLOOR.get(f.get("rule", "")) or SEVERITY_FLOOR.get(f.get("cwe", ""))
        if floor and f["severity"] == "MEDIUM":
            f["severity"] = floor
    findings = sort_by_severity(findings)
    for i, f in enumerate(findings, 1):
        f["id"] = f"VULN-{i:03d}"

    router = get_router()
    top = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")][:10]
    remediation = None
    if top:
        listing = "\n".join(f"- {f['id']} {f['title']} ({f.get('cwe', '')}) in {f.get('file')}:{f.get('line', '')}: `{f.get('snippet', '')}`" for f in top)
        result = router.complete(
            FIX_SYSTEM,
            f"Findings from static analysis:\n{listing}\n\nFor each finding give one line on the risk and a corrected code snippet. "
            "Group related findings. Markdown, under 450 words.",
            agent=AGENT, max_tokens=6000,
        )
        remediation = result.text if result else None
    if not remediation:
        remediation = "\n".join(f"- **{f['id']} {f['title']}**: {f.get('fix') or _default_fix(f)}" for f in top) or "No high-severity code findings."

    out = {
        "findings": findings,
        "counts": severity_counts(findings),
        "inventory": inventory,
        "container": container,
        "remediation": remediation,
        "notes": notes,
    }
    msg = f"{len(findings)} findings ({', '.join(f'{k}: {v}' for k, v in out['counts'].items())}); inventory of {len(inventory)} components"
    return {"vuln_findings": out, "completed": [AGENT], "trace": [trace_event(AGENT, msg)]}


def _default_fix(f: dict[str, Any]) -> str:
    cwe = f.get("cwe", "")
    return {
        "CWE-89": "Use parameterized queries: cur.execute('... WHERE id = ?', (product_id,)).",
        "CWE-78": "Pass an argument list and drop shell=True; validate the host against an allowlist.",
        "CWE-502": "Use yaml.safe_load().",
        "CWE-327": "Hash passwords with bcrypt/argon2, never MD5/SHA1.",
        "CWE-94": "Never enable debug in production; read it from config.",
        "CWE-295": "Keep TLS verification on (verify=True).",
        "CWE-798": "Move secrets to environment variables or a secrets manager and rotate them.",
        "CWE-22": "Resolve the path and ensure it stays inside the allowed directory (werkzeug.utils.safe_join).",
    }.get(cwe, "Review and remediate per the rule guidance.")
