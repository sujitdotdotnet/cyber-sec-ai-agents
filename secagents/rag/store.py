"""Chroma-backed knowledge base for CVEs, MITRE ATT&CK techniques and compliance controls.

Embeddings come from OpenAI when a key is set; otherwise a local hashed bag-of-words embedding
is used so the demo (and tests) run fully offline. Each backend gets its own collections so
vectors of different dimensions never mix.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

import chromadb

from ..config import Settings, settings as default_settings

COLLECTIONS = {
    "cves": "cves.jsonl",
    "attack": "attack.jsonl",
    "controls": "controls.jsonl",
}

_TOKEN = re.compile(r"[a-z0-9][a-z0-9.\-]+")
HASH_DIM = 512


def hash_embed(text: str, dim: int = HASH_DIM) -> list[float]:
    vec = [0.0] * dim
    tokens = _TOKEN.findall(text.lower())
    grams = tokens + [f"{a} {b}" for a, b in zip(tokens, tokens[1:])]
    for tok in grams:
        h = int(hashlib.md5(tok.encode(), usedforsecurity=False).hexdigest(), 16)
        vec[h % dim] += 1.0 if (h >> 8) & 1 else -1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def doc_text(kind: str, rec: dict[str, Any]) -> str:
    if kind == "cves":
        return (
            f"{rec['id']} {rec['title']}. Package {rec['package']} ({rec['ecosystem']}) "
            f"affected {rec['affected']}, fixed in {rec['fixed']}. CVSS {rec['cvss']} {rec['severity']}. "
            f"{rec['description']}"
        )
    if kind == "attack":
        return (
            f"{rec['id']} {rec['name']} (tactic: {rec['tactic']}). {rec['description']} "
            f"Detection: {rec['detection']} Mitigation: {rec['mitigation']}"
        )
    return f"{rec['framework']} {rec['id']} {rec['title']}. {rec['description']}"


class KnowledgeBase:
    def __init__(self, cfg: Settings | None = None, persist: bool = True):
        self.cfg = cfg or default_settings
        self.backend = "openai" if (self.cfg.openai_api_key and not self.cfg.offline) else "hash"
        if persist:
            self.cfg.chroma_dir.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(path=str(self.cfg.chroma_dir))
        else:
            self.client = chromadb.EphemeralClient()
        self.records: dict[str, dict[str, dict[str, Any]]] = {}
        self._openai = None
        if self.backend == "openai":
            self.embed(["probe"])  # switches to local embeddings if OpenAI is unreachable
        self.ingest()

    # ---- embeddings --------------------------------------------------------
    def embed(self, texts: list[str]) -> list[list[float]]:
        if self.backend == "openai":
            try:
                if self._openai is None:
                    from openai import OpenAI

                    self._openai = OpenAI(api_key=self.cfg.openai_api_key)
                resp = self._openai.embeddings.create(model=self.cfg.embedding_model, input=texts)
                return [d.embedding for d in resp.data]
            except Exception:  # noqa: BLE001 - fall back to local embeddings for the whole session
                self.backend = "hash"
        return [hash_embed(t) for t in texts]

    def _collection(self, kind: str):
        return self.client.get_or_create_collection(
            name=f"{kind}_{self.backend}", metadata={"hnsw:space": "cosine"}
        )

    # ---- ingestion ---------------------------------------------------------
    def load_records(self, kind: str) -> list[dict[str, Any]]:
        path = Path(self.cfg.knowledge_dir) / COLLECTIONS[kind]
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def ingest(self) -> None:
        for kind in COLLECTIONS:
            recs = self.load_records(kind)
            self.records[kind] = {r["id"]: r for r in recs}
            col = self._collection(kind)
            existing = set(col.get(ids=[r["id"] for r in recs])["ids"])
            new = [r for r in recs if r["id"] not in existing]
            if not new:
                continue
            texts = [doc_text(kind, r) for r in new]
            col.add(
                ids=[r["id"] for r in new],
                documents=texts,
                embeddings=self.embed(texts),
                metadatas=[{"kind": kind} for _ in new],
            )

    # ---- search ------------------------------------------------------------
    def search(self, kind: str, query: str, k: int = 4) -> list[dict[str, Any]]:
        col = self._collection(kind)
        res = col.query(query_embeddings=self.embed([query]), n_results=k)
        hits = []
        for doc_id, dist, doc in zip(res["ids"][0], res["distances"][0], res["documents"][0]):
            hits.append({"id": doc_id, "score": round(1 - dist, 3), "text": doc, "record": self.records[kind][doc_id]})
        return hits

    def get(self, kind: str, doc_id: str) -> dict[str, Any] | None:
        return self.records.get(kind, {}).get(doc_id)

    def all(self, kind: str) -> list[dict[str, Any]]:
        return list(self.records[kind].values())


_kb: KnowledgeBase | None = None


def get_kb() -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb
