"""Helpers shared by the agents."""

from __future__ import annotations

import time
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "").upper(), 0)


def sort_by_severity(items: list[dict[str, Any]], key: str = "severity") -> list[dict[str, Any]]:
    return sorted(items, key=lambda i: sev_rank(i.get(key, "")), reverse=True)


def trace_event(agent: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"agent": agent, "message": message, "ts": time.strftime("%H:%M:%S"), **extra}


def severity_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for i in items:
        counts[(i.get("severity") or "INFO").upper()] = counts.get((i.get("severity") or "INFO").upper(), 0) + 1
    return {k: v for k, v in counts.items() if v}
