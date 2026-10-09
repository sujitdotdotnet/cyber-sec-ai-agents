"""Log Monitor Agent: parses auth, web and firewall logs and detects attacks and anomalies.

Detection is rule-based and deterministic (so it is explainable and testable); the LLM then
correlates the detections into an attack narrative and timeline.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

from ..llm import get_router
from ..rag import get_kb
from .base import severity_counts, sort_by_severity, trace_event

AGENT = "log_monitor"
YEAR = 2026

SYSLOG_RE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-]+)(?:\[\d+\])?: (?P<msg>.*)$")
NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<bytes>\d+) "[^"]*" "(?P<ua>[^"]*)"'
)
UFW_RE = re.compile(r"\[UFW (?P<action>\w+)\].*?SRC=(?P<src>\S+) DST=(?P<dst>\S+).*?DPT=(?P<dpt>\d+)(?:.*?BYTES=(?P<bytes>\d+))?")

WEB_ATTACKS = [
    ("SQL injection", "T1190", "HIGH", re.compile(r"(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|;\s*drop\s+table|sleep\(\d+\)|--\s*$)", re.I)),
    ("Path traversal", "T1083", "HIGH", re.compile(r"(\.\./|\.\.%2f|/etc/(passwd|shadow))", re.I)),
    ("Cross-site scripting", "T1190", "MEDIUM", re.compile(r"(<script|javascript:|onerror=)", re.I)),
    ("Command injection", "T1059.004", "HIGH", re.compile(r"(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", re.I)),
    ("Log4Shell (JNDI injection)", "T1190", "CRITICAL", re.compile(r"\$\{jndi:", re.I)),
]
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|nuclei|masscan|dirbuster|gobuster|wpscan|zgrab)", re.I)
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 1389, 9001}

INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
PORT_SCAN_THRESHOLD = 10


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS)


def _syslog_time(ts: str) -> datetime:
    return datetime.strptime(f"{YEAR} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def _event(**kw: Any) -> dict[str, Any]:
    kw.setdefault("evidence", [])
    kw["evidence"] = kw["evidence"][:4]
    return kw


# ---- parsers -----------------------------------------------------------------
def analyze_auth(lines: list[str], source: str) -> list[dict[str, Any]]:
    failures: dict[str, list[tuple[datetime, str, str]]] = defaultdict(list)
    events: list[dict[str, Any]] = []
    suspicious_logins: dict[str, datetime] = {}

    for line in lines:
        m = SYSLOG_RE.match(line)
        if not m:
            continue
        t, msg, proc = _syslog_time(m["ts"]), m["msg"], m["proc"]
        if proc == "sshd":
            f = re.search(r"Failed password for (invalid user )?(\S+) from (\S+)", msg)
            if f:
                failures[f[3]].append((t, f[2], line))
                continue
            a = re.search(r"Accepted (\w+) for (\S+) from (\S+)", msg)
            if a:
                method, user, ip = a[1], a[2], a[3]
                prior = [x for x in failures.get(ip, []) if t - x[0] <= timedelta(minutes=30)]
                if len(prior) >= BRUTE_FORCE_THRESHOLD:
                    suspicious_logins[user] = t
                    events.append(_event(
                        type="Successful login after brute force", severity="CRITICAL", source=source,
                        src_ip=ip, target=user, count=len(prior) + 1, first_seen=prior[0][0].isoformat(),
                        last_seen=t.isoformat(), mitre=["T1110.001", "T1078", "T1021.004"],
                        description=f"{ip} logged in as '{user}' via {method} after {len(prior)} failed attempts: account likely compromised.",
                        evidence=[prior[-1][2], line],
                    ))
        elif proc == "sudo" and "COMMAND=" in msg:
            user = msg.split(":")[0].strip()
            cmd = msg.split("COMMAND=", 1)[1]
            if user in suspicious_logins and t - suspicious_logins[user] <= timedelta(hours=2):
                downloader = re.search(r"\b(curl|wget)\b.*https?://", cmd)
                events.append(_event(
                    type="Remote payload download via sudo" if downloader else "Privilege escalation after suspicious login",
                    severity="CRITICAL" if downloader else "HIGH", source=source, target=user, count=1,
                    first_seen=t.isoformat(), last_seen=t.isoformat(),
                    mitre=["T1059.004", "T1105"] if downloader else ["T1548.003"],
                    description=f"Compromised account '{user}' ran as root: {cmd}", evidence=[line],
                ))
        elif proc == "useradd":
            u = re.search(r"name=(\S+?),.*UID=(\d+)", msg)
            if u:
                root = u[2] == "0"
                events.append(_event(
                    type="Backdoor account created" if root else "New local account", severity="CRITICAL" if root else "MEDIUM",
                    source=source, target=u[1], count=1, first_seen=t.isoformat(), last_seen=t.isoformat(),
                    mitre=["T1136.001"],
                    description=f"Account '{u[1]}' created with UID {u[2]}" + (" (root-equivalent)" if root else ""),
                    evidence=[line],
                ))

    for ip, attempts in failures.items():
        attempts.sort()
        window = [a for a in attempts if a[0] - attempts[0][0] <= BRUTE_FORCE_WINDOW] if attempts else []
        if len(attempts) < BRUTE_FORCE_THRESHOLD or len(window) < BRUTE_FORCE_THRESHOLD // 2:
            continue
        users = sorted({a[1] for a in attempts})
        events.append(_event(
            type="SSH brute force" + (" and password spraying" if len(users) >= 5 else ""), severity="HIGH",
            source=source, src_ip=ip, target=", ".join(users[:6]) + ("..." if len(users) > 6 else ""),
            count=len(attempts), first_seen=attempts[0][0].isoformat(), last_seen=attempts[-1][0].isoformat(),
            mitre=["T1110.001"] + (["T1110.003"] if len(users) >= 5 else []),
            description=f"{len(attempts)} failed SSH logins from {ip} against {len(users)} account(s).",
            evidence=[a[2] for a in attempts[:2]] + [attempts[-1][2]],
        ))
    return events


def analyze_web(lines: list[str], source: str) -> list[dict[str, Any]]:
    by_ip: dict[str, dict[str, Any]] = defaultdict(lambda: {"total": 0, "404": 0, "scanner": set(), "lines": [], "times": []})
    attack_hits: dict[tuple[str, str], list[tuple[datetime, str, int]]] = defaultdict(list)
    meta: dict[str, tuple[str, str]] = {}

    for line in lines:
        m = NGINX_RE.match(line)
        if not m:
            continue
        ip, status = m["ip"], int(m["status"])
        t = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        payload = unquote_plus(m["path"]) + " " + m["ua"]
        stats = by_ip[ip]
        stats["total"] += 1
        stats["times"].append(t)
        stats["404"] += status == 404
        if SCANNER_UA.search(m["ua"]):
            stats["scanner"].add(SCANNER_UA.search(m["ua"])[1].lower())
            stats["lines"].append(line)
        for name, technique, sev, rx in WEB_ATTACKS:
            if rx.search(payload):
                attack_hits[(ip, name)].append((t, line, status))
                meta[name] = (technique, sev)

    events: list[dict[str, Any]] = []
    for (ip, name), hits in attack_hits.items():
        technique, sev = meta[name]
        succeeded = [h for h in hits if 200 <= h[2] < 300]
        events.append(_event(
            type=f"Web attack: {name}", severity=sev, source=source, src_ip=ip, target="web application",
            count=len(hits), first_seen=hits[0][0].isoformat(), last_seen=hits[-1][0].isoformat(), mitre=[technique],
            description=f"{len(hits)} {name} attempt(s) from {ip}; {len(succeeded)} returned HTTP 2xx and may have succeeded.",
            possibly_successful=bool(succeeded), evidence=[h[1] for h in (succeeded or hits)[:3]],
        ))
    for ip, stats in by_ip.items():
        if stats["scanner"] or (stats["404"] >= 15 and stats["404"] / max(stats["total"], 1) > 0.5):
            events.append(_event(
                type="Automated vulnerability scanning", severity="MEDIUM", source=source, src_ip=ip,
                target="web application", count=stats["total"], mitre=["T1595.002"],
                first_seen=min(stats["times"]).isoformat(), last_seen=max(stats["times"]).isoformat(),
                description=f"{ip} made {stats['total']} requests ({stats['404']} x 404) using {', '.join(sorted(stats['scanner'])) or 'unknown tooling'}.",
                evidence=stats["lines"][:3],
            ))
    return events


def analyze_firewall(lines: list[str], source: str) -> list[dict[str, Any]]:
    ports: dict[str, set[int]] = defaultdict(set)
    first_last: dict[str, list[datetime]] = {}
    sample: dict[str, list[str]] = defaultdict(list)
    events: list[dict[str, Any]] = []

    for line in lines:
        m, s = UFW_RE.search(line), SYSLOG_RE.match(line)
        if not m or not s:
            continue
        t = _syslog_time(s["ts"])
        src, dst, dpt = m["src"], m["dst"], int(m["dpt"])
        outbound = "OUT=eth0" in line and "IN= " in line
        if outbound and dpt in SUSPICIOUS_PORTS:
            size = int(m["bytes"] or 0)
            events.append(_event(
                type="Large outbound transfer to suspicious port" if size > 10_000_000 else "Outbound connection to suspicious port",
                severity="CRITICAL" if size > 10_000_000 else "HIGH", source=source, src_ip=src, target=f"{dst}:{dpt}",
                count=1, first_seen=t.isoformat(), last_seen=t.isoformat(),
                mitre=["T1048"] if size > 10_000_000 else ["T1071", "T1571"], bytes=size,
                description=f"{src} connected out to {dst}:{dpt}" + (f" and sent {size / 1e6:.1f} MB" if size else "") + ": typical of a reverse shell or exfiltration.",
                evidence=[line],
            ))
            continue
        if not outbound:
            ports[src].add(dpt)
            first_last.setdefault(src, [t, t])[1] = t
            if len(sample[src]) < 3:
                sample[src].append(line)

    for src, seen in ports.items():
        if len(seen) >= PORT_SCAN_THRESHOLD:
            fl = first_last[src]
            events.append(_event(
                type="Port scan", severity="MEDIUM", source=source, src_ip=src, target="10.0.0.0/24",
                count=len(seen), first_seen=fl[0].isoformat(), last_seen=fl[1].isoformat(), mitre=["T1046"],
                description=f"{src} probed {len(seen)} distinct ports in {(fl[1] - fl[0]).seconds}s.", evidence=sample[src],
            ))
    return events


def detect(paths: list[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        lines = path.read_text(errors="replace").splitlines()
        name = path.name.lower()
        if "auth" in name or "secure" in name:
            events += analyze_auth(lines, path.name)
        elif "access" in name or "nginx" in name or "apache" in name:
            events += analyze_web(lines, path.name)
        elif "firewall" in name or "ufw" in name or "iptables" in name:
            events += analyze_firewall(lines, path.name)
        else:  # unknown file: try every parser
            events += analyze_auth(lines, path.name) + analyze_web(lines, path.name) + analyze_firewall(lines, path.name)
    events = sort_by_severity(events)
    for i, e in enumerate(events, 1):
        e["id"] = f"LOG-{i:03d}"
    return events


NARRATIVE_SYSTEM = (
    "You are a senior SOC analyst. You receive security detections produced by log parsers and "
    "MITRE ATT&CK context. Correlate them into one coherent picture for a defender."
)


def run_log_monitor(state: dict[str, Any]) -> dict[str, Any]:
    paths = state.get("inputs", {}).get("log_paths", [])
    events = detect(paths)
    kb, router = get_kb(), get_router()

    techniques = sorted({t for e in events for t in e.get("mitre", [])})
    attack_ctx = {t: kb.get("attack", t) for t in techniques if kb.get("attack", t)}
    attackers = sorted({e["src_ip"] for e in events if e.get("src_ip") and not is_internal(e["src_ip"]) and e["severity"] in ("HIGH", "CRITICAL")})

    narrative = None
    if events:
        brief = "\n".join(
            f"- {e['id']} [{e['severity']}] {e['type']} | src={e.get('src_ip', '-')} target={e.get('target', '-')} "
            f"| {e.get('first_seen', '')} -> {e.get('last_seen', '')} | {e['description']}"
            for e in events
        )
        ctx = "\n".join(f"- {k}: {v['name']} ({v['tactic']})" for k, v in attack_ctx.items())
        result = router.complete(
            NARRATIVE_SYSTEM,
            f"Detections:\n{brief}\n\nATT&CK context:\n{ctx}\n\n"
            "Write: (1) a 3-5 sentence attack narrative in chronological order naming the kill-chain stages, "
            "(2) which detections are linked to the same actor, (3) the single most urgent concern. Use markdown, under 250 words.",
            agent=AGENT,
            max_tokens=4000,
        )
        narrative = result.text if result else None
    if not narrative:
        narrative = _fallback_narrative(events)

    findings = {
        "events": events,
        "counts": severity_counts(events),
        "attackers": attackers,
        "techniques": [{"id": k, "name": v["name"], "tactic": v["tactic"]} for k, v in attack_ctx.items()],
        "narrative": narrative,
        "files_analyzed": [Path(p).name for p in paths if Path(p).exists()],
    }
    msg = f"Analyzed {len(findings['files_analyzed'])} log file(s): {len(events)} detections, attackers: {', '.join(attackers) or 'none'}"
    return {"log_findings": findings, "completed": [AGENT], "trace": [trace_event(AGENT, msg)]}


def _fallback_narrative(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No suspicious activity detected in the supplied logs."
    ordered = sorted(events, key=lambda e: e.get("first_seen") or "")
    lines = [f"- **{e.get('first_seen', '')[11:19] or '--:--'}** {e['type']} ({e.get('src_ip', 'n/a')}): {e['description']}" for e in ordered]
    crit = [e for e in events if e["severity"] == "CRITICAL"]
    head = (
        f"**{len(crit)} critical detection(s)** indicate an active compromise." if crit
        else "Suspicious activity detected; no evidence of successful compromise."
    )
    return head + "\n\nTimeline:\n" + "\n".join(lines)
