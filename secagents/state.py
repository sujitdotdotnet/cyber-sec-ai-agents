"""Shared LangGraph state passed between the agents."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class Inputs(TypedDict, total=False):
    log_paths: list[str]
    code_path: str
    requirements_path: str
    dockerfile_path: str
    config_path: str


class SecState(TypedDict, total=False):
    inputs: Inputs
    log_findings: dict[str, Any]
    vuln_findings: dict[str, Any]
    threat_intel: dict[str, Any]
    incident_plan: dict[str, Any]
    compliance: dict[str, Any]
    completed: Annotated[list[str], operator.add]
    trace: Annotated[list[dict[str, Any]], operator.add]
    next_agent: str
    report_md: str
