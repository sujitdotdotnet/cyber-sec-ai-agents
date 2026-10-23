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
from ..redact import scrub

COLLECTIONS = {
    "cves": "cves.jsonl",
    "attack": "attack.jsonl",
    "controls": "controls.jsonl",
}

# Regenerated daily by secagents.knowledge_sync. The hand-written files above always win for a shared id, so what you
# pin by hand (or the demo scenario depends on) is never overwritten.
SYNCED = {
    "cves": "cves_synced.jsonl",
    "attack": "attack_synced.jsonl",
}
# Matching by package scans every CVE record, but only the most important synced ones are embedded for semantic search
# (thousands of advisories would slow every cold start for little retrieval benefit).
INDEX_SYNCED_CVES = 300
# Hand-written records are the vetted, demo-critical ones. When a synced record is about as close a match, they come first.
PINNED_BONUS = 0.05
PINNED_POOL = 6  # extra candidates fetched so a pinned record just outside the top k can still be promoted

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
        self.backend = "openai" if (self.api_key and not self.cfg.offline and not self.cfg.self_hosted_only) else "hash"
        if persist:
            self.cfg.chroma_dir.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(path=str(self.cfg.chroma_dir))
        else:
            self.client = chromadb.EphemeralClient()
        self.records: dict[str, dict[str, dict[str, Any]]] = {}
        self.pinned: dict[str, set[str]] = {}  # ids of the hand-written records, which rank slightly above synced ones
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
        self.backend = "openai" if (key and not self.cfg.offline and not self.cfg.self_hosted_only) else "hash"
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
    def _read(self, name: str) -> list[dict[str, Any]]:
        path = Path(self.cfg.knowledge_dir) / name
        if not path.exists():
            return []
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:  # a half-written synced file must not break the app
                    continue
        return out

    def load_records(self, kind: str) -> list[dict[str, Any]]:
        """Hand-written records, then synced ones whose id is not already taken."""
        base = self._read(COLLECTIONS[kind])
        taken = {r["id"] for r in base}
        synced = [r for r in self._read(SYNCED[kind]) if r["id"] not in taken] if kind in SYNCED else []
        return base + synced

    def _to_index(self, kind: str, recs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if kind != "cves":
            return recs
        pinned = {r["id"] for r in self._read(COLLECTIONS[kind])}
        extra = sorted((r for r in recs if r["id"] not in pinned), key=lambda r: (bool(r.get("kev")), r.get("cvss", 0)), reverse=True)
        return [r for r in recs if r["id"] in pinned] + extra[:INDEX_SYNCED_CVES]

    def ingest(self) -> None:
        """Make the vector index match the files: add new records, refresh changed ones, drop ones that disappeared."""
        for kind in COLLECTIONS:
            recs = self.load_records(kind)
            self.records[kind] = {r["id"]: r for r in recs}
            self.pinned[kind] = {r["id"] for r in self._read(COLLECTIONS[kind])}
            indexed = self._to_index(kind, recs)
            col = self._collection(kind)
            texts = {r["id"]: doc_text(kind, r) for r in indexed}
            stamp = {i: hashlib.sha1(t.encode()).hexdigest()[:12] for i, t in texts.items()}
            have = col.get(ids=list(texts), include=["metadatas"])
            current = {i: (m or {}).get("h") for i, m in zip(have["ids"], have["metadatas"])}
            stale = [i for i in col.get(include=[])["ids"] if i not in texts]
            if stale:
                col.delete(ids=stale)
            todo = [i for i in texts if current.get(i) != stamp[i]]
            for start in range(0, len(todo), 200):
                batch = todo[start:start + 200]
                col.upsert(
                    ids=batch,
                    documents=[texts[i] for i in batch],
                    embeddings=self.embed([texts[i] for i in batch]),
                    metadatas=[{"kind": kind, "h": stamp[i]} for i in batch],
                )
            if todo:
                self._wait_ready(col)  # a freshly built or changed index answers queries only once Chroma has written it

    # ---- past incidents (memory of this team's own history, one owner at a time) ----------------------
    def _incident_collection(self):
        return self.client.get_or_create_collection(name=f"incidents_{self.backend}", metadata={"hnsw:space": "cosine"})

    def add_incidents(self, owner: str, scan_id: str, incidents: list[dict[str, Any]]) -> int:
        """Remember a scan's incidents under ``owner``. Safe to repeat: the same incident is overwritten, not duplicated."""
        rows = [i for i in incidents if i.get("id")]
        if not rows:
            return 0
        texts = [scrub(f"{i.get('title', '')}. {i.get('summary', '')}")[0] for i in rows]
        self._incident_collection().upsert(
            ids=[f"{owner}|{scan_id}|{i['id']}" for i in rows], documents=texts, embeddings=self.embed(texts),
            metadatas=[{"owner": owner, "scan": scan_id, "incident": i["id"], "title": str(i.get("title", ""))[:200],
                        "priority": str(i.get("priority", "")), "summary": texts[n][:400]} for n, i in enumerate(rows)],
        )
        return len(rows)

    def similar_incidents(self, owner: str, query: str, k: int = 3) -> list[dict[str, Any]]:
        """The ``owner``'s own past incidents closest to ``query``. Nobody else's are ever returned."""
        col = self._incident_collection()
        if not col.get(where={"owner": owner}, limit=1, include=[])["ids"]:
            return []
        q = self.embed([scrub(query)[0]])
        res = col.query(query_embeddings=q, n_results=k, where={"owner": owner})
        return [{"scan": m["scan"], "incident": m["incident"], "title": m["title"], "priority": m["priority"], "summary": m["summary"], "score": round(1 - d, 3)}
                for m, d in zip(res["metadatas"][0], res["distances"][0])]

    # ---- search ------------------------------------------------------------
    def search(self, kind: str, query: str, k: int = 4) -> list[dict[str, Any]]:
        col = self._collection(kind)
        if self.cfg.redact_before_model:  # a query built from log evidence goes to the embedding service: no secrets in it
            query = scrub(query)[0]
        q = self.embed([query])  # may switch the backend (bad key), so fetch the collection afterwards
        col = self._collection(kind)
        ids, dists, docs = self._query(col, q, k + PINNED_POOL, query_text=query)
        hits = [
            {"id": i, "score": round(1 - d + (PINNED_BONUS if i in self.pinned.get(kind, ()) else 0), 3), "text": t, "record": self.records[kind][i]}
            for i, d, t in zip(ids, dists, docs)
        ]
        return sorted(hits, key=lambda h: -h["score"])[:k]

    @staticmethod
    def _query(col, query_embedding: list[list[float]], k: int, attempts: int = 8, query_text: str = "") -> tuple[list, list, list]:
        """Chroma query, tolerant of its background index build.

        Right after a collection is created or changed Chroma can raise "Error creating hnsw segment reader: Nothing
        found on disk" until the index has been written, and it depends on timing and threads (LangGraph runs
        agents in worker threads). Retry for a few seconds; then rank the stored vectors exactly; and if even
        reading them fails, rank by word overlap with the stored text (which needs no vector index). A search
        therefore always answers, and an agent run never fails on it.
        """
        for attempt in range(attempts):
            try:
                res = col.query(query_embeddings=query_embedding, n_results=k)
                return res["ids"][0], res["distances"][0], res["documents"][0]
            except Exception:  # noqa: BLE001 - chromadb raises its own InternalError types
                if attempt < attempts - 1:
                    time.sleep(min(0.15 * (attempt + 1), 0.6))
        try:
            data = col.get(include=["embeddings", "documents"])
            q = query_embedding[0]
            qn = math.sqrt(sum(x * x for x in q)) or 1.0
            scored = []
            for doc_id, vec, doc in zip(data["ids"], data["embeddings"], data["documents"]):
                vn = math.sqrt(sum(float(x) * float(x) for x in vec)) or 1.0
                cos = sum(a * float(b) for a, b in zip(q, vec)) / (qn * vn)
                scored.append((1 - cos, doc_id, doc))  # cosine distance, like the index
        except Exception:  # noqa: BLE001 - the vector segment is not readable yet: use the text alone
            data = col.get(include=["documents"])
            wanted = set(_TOKEN.findall(query_text.lower()))
            scored = []
            for doc_id, doc in zip(data["ids"], data["documents"]):
                words = set(_TOKEN.findall(doc.lower()))
                scored.append((1 - len(wanted & words) / (len(wanted) or 1), doc_id, doc))
        scored.sort(key=lambda t: t[0])
        top = scored[:k]
        return [t[1] for t in top], [t[0] for t in top], [t[2] for t in top]

    def _wait_ready(self, col, tries: int = 40, delay: float = 0.25) -> None:
        """After the index changed, wait (up to ~10 s) until Chroma can actually answer a query."""
        probe = self.embed(["readiness probe"])
        for _ in range(tries):
            try:
                col.query(query_embeddings=probe, n_results=1)
                return
            except Exception:  # noqa: BLE001
                time.sleep(delay)

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
    return "openai" if (key and not default_settings.offline and not default_settings.self_hosted_only) else "hash"  # what the next get_kb() will switch to
