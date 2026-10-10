"""Chroma-backed knowledge base for CVEs, MITRE ATT&CK techniques and compliance controls.

Embeddings come from OpenAI when an OpenAI key is available (typed in the dashboard, else from
.env); otherwise a local hashed bag-of-words embedding is used so the demo (and tests) run fully
offline. Each backend gets its own collections so vectors of different dimensions never mix, which
also makes switching keys cheap: the OpenAI collections persist and are only topped up.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
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
    def __init__(self, cfg: Settings | None = None, persist: bool = True, api_key: str = ""):
        self.cfg = cfg or default_settings
        self.api_key = api_key.strip() or self.cfg.openai_api_key  # embeddings key; a typed one beats .env
        self.backend = "openai" if (self.api_key and not self.cfg.offline) else "hash"
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

    def use_key(self, key: str) -> bool:
        """Switch the embeddings key (blank = the .env key). Returns True if the knowledge base was rebuilt.

        Does nothing while the key is unchanged, so calling it on every dashboard rerun is free, and a key that
        already failed is not retried until it changes. A rebuild re-selects the backend (OpenAI with a key,
        local without) and tops up that backend's collections with any records they are missing.
        """
        key = key.strip() or self.cfg.openai_api_key
        if key == self.api_key:
            return False
        self.api_key, self._openai = key, None
        self.backend = "openai" if (key and not self.cfg.offline) else "hash"
        if self.backend == "openai":
            self.embed(["probe"])  # falls back to local embeddings if this key does not work
        self.ingest()
        return True

    # ---- embeddings --------------------------------------------------------
    def embed(self, texts: list[str]) -> list[list[float]]:
        if self.backend == "openai":
            try:
                if self._openai is None:
                    from openai import OpenAI

                    self._openai = OpenAI(api_key=self.api_key)
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
        q = self.embed([query])  # may switch the backend (bad key), so fetch the collection afterwards
        col = self._collection(kind)
        ids, dists, docs = self._query(col, q, k)
        return [
            {"id": i, "score": round(1 - d, 3), "text": t, "record": self.records[kind][i]}
            for i, d, t in zip(ids, dists, docs)
        ]

    @staticmethod
    def _query(col, query_embedding: list[list[float]], k: int, attempts: int = 4) -> tuple[list, list, list]:
        """Chroma query, tolerant of its background index build.

        Right after a collection is created Chroma can raise "Error creating hnsw segment reader: Nothing found
        on disk" until the index has been written, and it depends on timing and threads (LangGraph runs each agent
        in a worker thread). Retry briefly, then rank the stored vectors exactly: the knowledge base is a few dozen
        records, so the answer is the same and an agent run never fails on it.
        """
        for attempt in range(attempts):
            try:
                res = col.query(query_embeddings=query_embedding, n_results=k)
                return res["ids"][0], res["distances"][0], res["documents"][0]
            except Exception:  # noqa: BLE001 - chromadb raises its own InternalError types
                if attempt < attempts - 1:
                    time.sleep(0.15 * (attempt + 1))
        data = col.get(include=["embeddings", "documents"])
        q = query_embedding[0]
        qn = math.sqrt(sum(x * x for x in q)) or 1.0
        scored = []
        for doc_id, vec, doc in zip(data["ids"], data["embeddings"], data["documents"]):
            vn = math.sqrt(sum(float(x) * float(x) for x in vec)) or 1.0
            cos = sum(a * float(b) for a, b in zip(q, vec)) / (qn * vn)
            scored.append((1 - cos, doc_id, doc))  # cosine distance, like the index
        scored.sort(key=lambda t: t[0])
        top = scored[:k]
        return [t[1] for t in top], [t[0] for t in top], [t[2] for t in top]

    def get(self, kind: str, doc_id: str) -> dict[str, Any] | None:
        return self.records.get(kind, {}).get(doc_id)

    def all(self, kind: str) -> list[dict[str, Any]]:
        return list(self.records[kind].values())


_kb: KnowledgeBase | None = None
_typed_key = ""  # OpenAI key typed in the dashboard; blank = use the one from .env


def set_embedding_key(key: str) -> None:
    """Remember the dashboard key. Applied lazily by get_kb(), so setting it never builds the knowledge base."""
    global _typed_key
    _typed_key = key.strip()


def get_kb() -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase(api_key=_typed_key)
    else:
        _kb.use_key(_typed_key)
    return _kb


def embedding_backend() -> str:
    """"openai" or "hash" (local): what embeddings are in use, or will be once the knowledge base is built."""
    key = _typed_key or default_settings.openai_api_key
    if _kb is not None and key == _kb.api_key:
        return _kb.backend  # actual, including a fallback to local after a failed key
    return "openai" if (key and not default_settings.offline) else "hash"  # what the next get_kb() will switch to
