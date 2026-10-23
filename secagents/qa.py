"""Ask-the-agents: answer free-text questions grounded in the latest results and the knowledge base."""

from __future__ import annotations

import json
from typing import Any

from .llm import get_router
from .rag import agentic_retrieve, get_kb

ROUTES = {
    "log_monitor": ("log", "attack", "login", "brute", "ip", "scan", "traffic", "timeline", "happened"),
    "threat_intel": ("cve", "affected", "exploit", "ioc", "threat", "log4", "intel"),
    "vuln_scanner": ("code", "docker", "image", "secret", "dependency", "bandit", "vulnerab", "fix"),
    "incident_response": ("incident", "contain", "respond", "playbook", "step", "next", "do now"),
    "policy_checker": ("nist", "iso", "soc", "complian", "control", "policy", "audit", "gap"),
}
STATE_KEYS = {
    "log_monitor": "log_findings", "threat_intel": "threat_intel", "vuln_scanner": "vuln_findings",
    "incident_response": "incident_plan", "policy_checker": "compliance",
}


def route(question: str) -> list[str]:
    q = question.lower()
    hits = [agent for agent, words in ROUTES.items() if any(w in q for w in words)]
    return hits or ["threat_intel", "incident_response"]


def _compact(obj: Any, limit: int = 6000) -> str:
    text = json.dumps(obj, default=str)
    return text[:limit] + ("..." if len(text) > limit else "")


def _no_answer_note(router) -> str:
    """Why there is no model-written answer: no key at all, or a key whose calls failed (with the provider's reason)."""
    if not router.available_providers():
        budget = getattr(router, "budget", None)
        blocked = budget.blocked() if budget is not None else None
        if blocked:
            return blocked + " Here is the most relevant knowledge instead:"
        return "No LLM is configured (no API key, or offline mode), so here is the most relevant knowledge:"
    why = getattr(router, "last_errors", [])
    detail = "\n\nWhat the providers said:" + "".join(f"\n- {e}" for e in why) if why else ""
    return "A language model is configured, but the call failed, so here is the most relevant knowledge instead." + detail


def ask(question: str, state: dict[str, Any]) -> dict[str, Any]:
    kb, router = get_kb(), get_router()
    agents = route(question)
    context = {a: state.get(STATE_KEYS[a], {}) for a in agents}
    kind = "controls" if "policy_checker" in agents else ("attack" if agents == ["log_monitor"] else "cves")
    rag = agentic_retrieve(kb, router, kind, question, k=3, agent="qa")
    knowledge = [h["text"] for h in rag["hits"]]

    result = router.complete(
        "You are the coordinator of a team of security agents. Answer the analyst's question using only the "
        "agents' results and knowledge snippets provided. Cite finding IDs (LOG-, VULN-, INC-, CVE-) where relevant. Be concise.",
        f"Question: {question}\n\nAgent results ({', '.join(agents)}):\n{_compact(context)}\n\nKnowledge:\n" + "\n".join(f"- {k}" for k in knowledge),
        agent="qa", max_tokens=4000,
    )
    if result:
        answer = result.text
    else:
        answer = _no_answer_note(router) + "\n\n" + "\n\n".join(f"- {k}" for k in knowledge)
    return {"answer": answer, "agents": agents, "sources": [h["id"] for h in rag["hits"]], "trace": rag["trace"]}
