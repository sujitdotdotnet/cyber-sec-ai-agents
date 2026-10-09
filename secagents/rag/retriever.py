"""Agentic retrieval: retrieve, let the LLM grade relevance, rewrite the query and retry once.

With no LLM configured this degrades to plain vector search.
"""

from __future__ import annotations

from typing import Any

from ..llm import LLMRouter
from .store import KnowledgeBase

GRADER_SYSTEM = (
    "You are a retrieval grader for a security operations assistant. Given a question and "
    "numbered knowledge snippets, decide which snippets are relevant to answering the question."
)


def agentic_retrieve(
    kb: KnowledgeBase,
    router: LLMRouter | None,
    kind: str,
    question: str,
    *,
    k: int = 4,
    min_relevant: int = 1,
    agent: str = "",
) -> dict[str, Any]:
    trace: list[str] = [f"search[{kind}]: {question}"]
    hits = kb.search(kind, question, k=k)
    if router is None or not router.available_providers():
        return {"hits": hits, "trace": trace, "graded": False}

    for attempt in range(2):
        listing = "\n".join(f"[{i}] {h['text'][:600]}" for i, h in enumerate(hits))
        verdict = router.complete_json(
            GRADER_SYSTEM,
            f"Question: {question}\n\nSnippets:\n{listing}\n\n"
            'Return {"relevant": [indices], "rewrite": "better search query if fewer than '
            f'{min_relevant} are relevant, else empty"}}',
            agent=f"{agent}:rag-grader",
            max_tokens=2000,
        )
        if not isinstance(verdict, dict):
            break
        relevant = [hits[i] for i in verdict.get("relevant", []) if isinstance(i, int) and 0 <= i < len(hits)]
        trace.append(f"graded {len(relevant)}/{len(hits)} relevant")
        rewrite = (verdict.get("rewrite") or "").strip()
        if len(relevant) >= min_relevant or not rewrite or attempt == 1:
            return {"hits": relevant or hits, "trace": trace, "graded": True}
        question = rewrite
        trace.append(f"rewrite -> search[{kind}]: {question}")
        hits = kb.search(kind, question, k=k)
    return {"hits": hits, "trace": trace, "graded": False}
