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
import os
import re
import time
from pathlib import Path
from typing import Any

try:  # optional: the serverless web API runs without it (see MemoryClient) to stay under size limits
    import chromadb
except ImportError:  # pragma: no cover - exercised by tests through the SECAGENTS_KB switch
    chromadb = None

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


class MemoryCollection:
    """The slice of the Chroma collection API this module uses, held in plain lists.

    The knowledge base is a few dozen records, so an exact cosine ranking is instant and equals what the index
    returns. It lets the web API skip chromadb (about 280 MB with its dependencies) on size-limited hosts.
    """

    def __init__(self, name: str):
        self.name = name
        self._rows: dict[str, tuple[list[float], str]] = {}

    def add(self, ids: list[str], documents: list[str], embeddings: list[list[float]], metadatas: list[dict] | None = None) -> None:
        for i, doc, vec in zip(ids, documents, embeddings):
            self._rows[i] = ([float(x) for x in vec], doc)

    def get(self, ids: list[str] | None = None, include: list[str] | None = None) -> dict[str, list]:
        keep = [i for i in (ids if ids is not None else self._rows) if i in self._rows]
        return {"ids": keep, "embeddings": [self._rows[i][0] for i in keep], "documents": [self._rows[i][1] for i in keep]}

    def query(self, query_embeddings: list[list[float]], n_results: int = 4) -> dict[str, list]:
        q = query_embeddings[0]
        qn = math.sqrt(sum(x * x for x in q)) or 1.0
        scored = []
        for doc_id, (vec, doc) in self._rows.items():
            vn = math.sqrt(sum(x * x for x in vec)) or 1.0
            scored.append((1 - sum(a * b for a, b in zip(q, vec)) / (qn * vn), doc_id, doc))  # cosine distance
        top = sorted(scored, key=lambda t: t[0])[:n_results]
        return {"ids": [[t[1] for t in top]], "distances": [[t[0] for t in top]], "documents": [[t[2] for t in top]]}


class MemoryClient:
    def __init__(self) -> None:
        self._collections: dict[str, MemoryCollection] = {}

    def get_or_create_collection(self, name: str, **_: Any) -> MemoryCollection:
        return self._collections.setdefault(name, MemoryCollection(name))

    def list_collections(self) -> list[MemoryCollection]:
        return list(self._collections.values())


def use_memory_store() -> bool:
    """In-memory store when chromadb is not installed or SECAGENTS_KB=memory (nothing persists between runs)."""
    return chromadb is None or os.getenv("SECAGENTS_KB", "").lower() == "memory"


class KnowledgeBase:
    def __init__(self, cfg: Settings | None = None, persist: bool = True, api_key: str = ""):
        self.cfg = cfg or default_settings
        self.api_key = api_key.strip() or self.cfg.openai_api_key  # embeddings key; a typed one beats .env
        self.backend = "openai" if (self.api_key and not self.cfg.offline) else "hash"
        if use_memory_store():
            self.client = MemoryClient()
        elif persist:
            self.cfg.chroma_dir.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(path=str(self.cfg.chroma_dir))
        else:
            self.client = chromadb.EphemeralClient()
        # An in-memory copy of every vector, kept as records are ingested. Chroma's on-disk index can lag behind a
        # new collection, so a failing query falls back to this copy instead of reading the index back again.
        self._mirror = self.client if isinstance(self.client, MemoryClient) else MemoryClient()
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

    def _mirror_collection(self, kind: str) -> MemoryCollection:
        return self._mirror.get_or_create_collection(f"{kind}_{self.backend}")

    # ---- ingestion ---------------------------------------------------------
    def load_records(self, kind: str) -> list[dict[str, Any]]:
        path = Path(self.cfg.knowledge_dir) / COLLECTIONS[kind]
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def ingest(self) -> None:
        for kind in COLLECTIONS:
            recs = self.load_records(kind)
            self.records[kind] = {r["id"]: r for r in recs}
            col, mirror = self._collection(kind), self._mirror_collection(kind)
            existing = set(col.get(ids=[r["id"] for r in recs])["ids"])
            new = [r for r in recs if r["id"] not in existing]
            if new:
                texts = [doc_text(kind, r) for r in new]
                vectors = self.embed(texts)
                col.add(ids=[r["id"] for r in new], documents=texts, embeddings=vectors, metadatas=[{"kind": kind} for _ in new])
                mirror.add(ids=[r["id"] for r in new], documents=texts, embeddings=vectors)
            if col is not mirror:  # records stored by an earlier run: copy their vectors across once
                have = set(mirror.get(ids=[r["id"] for r in recs])["ids"])
                missing = [r for r in recs if r["id"] not in have]
                if missing:
                    self._copy_to_mirror(kind, col, mirror, missing)

    def _copy_to_mirror(self, kind: str, col, mirror: MemoryCollection, recs: list[dict[str, Any]]) -> None:
        ids = [r["id"] for r in recs]
        try:
            data = col.get(ids=ids, include=["embeddings", "documents"])
            mirror.add(ids=data["ids"], documents=list(data["documents"]), embeddings=[list(v) for v in data["embeddings"]])
        except Exception:  # noqa: BLE001 - the stored vectors are unreadable right now: recompute them instead
            texts = [doc_text(kind, r) for r in recs]
            mirror.add(ids=ids, documents=texts, embeddings=self.embed(texts))

    # ---- search ------------------------------------------------------------
    def search(self, kind: str, query: str, k: int = 4) -> list[dict[str, Any]]:
        q = self.embed([query])  # may switch the backend (bad key), so fetch the collections afterwards
        ids, dists, docs = self._query(self._collection(kind), self._mirror_collection(kind), q, k)
        return [
            {"id": i, "score": round(1 - d, 3), "text": t, "record": self.records[kind][i]}
            for i, d, t in zip(ids, dists, docs)
        ]

    @staticmethod
    def _query(col, mirror: MemoryCollection, query_embedding: list[list[float]], k: int, attempts: int = 4) -> tuple[list, list, list]:
        """Chroma query, tolerant of its background index build.

        Right after a collection is created Chroma can raise "Error creating hnsw segment reader: Nothing found
        on disk" until the index has been written; it depends on timing, not on the data. Retry with a growing
        pause, then answer from the in-memory copy of the vectors: the knowledge base is a few dozen records, so
        the exact ranking equals the index's and an agent run never fails on it. (Reading the vectors back from
        Chroma would hit the same index, which is why the copy is kept separately.)
        """
        for attempt in range(attempts):
            try:
                res = col.query(query_embeddings=query_embedding, n_results=k)
                return res["ids"][0], res["distances"][0], res["documents"][0]
            except Exception:  # noqa: BLE001 - chromadb raises its own InternalError types
                if attempt < attempts - 1:
                    time.sleep(0.25 * (attempt + 1))
        res = mirror.query(query_embedding, n_results=k)
        return res["ids"][0], res["distances"][0], res["documents"][0]

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
