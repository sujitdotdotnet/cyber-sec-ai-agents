"""One small database layer for memory, scan history and usage counters: SQLite by default, Postgres when configured.

``Db("postgresql://user:pass@host/db?sslmode=require")`` (a Neon, Supabase or any Postgres URL) keeps data across
restarts of a host with a temporary disk. Anything else is a SQLite file (or ``":memory:"``). Callers write SQL with
``?`` placeholders and portable types only; the layer translates for Postgres and returns rows as dicts either way.
"""

from __future__ import annotations

import re
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, unquote

_instances: dict[str, "Db"] = {}
_instances_lock = threading.Lock()


def is_postgres(target: str | Path) -> bool:
    return str(target).lower().startswith(("postgres://", "postgresql://"))


def open_db(target: str | Path) -> "Db":
    """The shared Db for a target (one connection per process, reused across Streamlit reruns and sessions)."""
    key = str(target)
    with _instances_lock:
        if key not in _instances or key == ":memory:":
            _instances[key] = Db(target)
        return _instances[key]


class Cursor:
    """What callers get back from execute(): dict rows and a row count."""

    def __init__(self, rows: list[dict[str, Any]], rowcount: int):
        self._rows, self.rowcount = rows, rowcount

    def fetchone(self) -> dict[str, Any] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._rows)


class Db:
    def __init__(self, target: str | Path):
        self.target = str(target)
        self.postgres = is_postgres(self.target)
        self._lock = threading.RLock()  # one shared connection: serialise use (the load is a handful of small queries)
        self._conn: Any = None
        if not self.postgres and self.target != ":memory:":
            Path(self.target).parent.mkdir(parents=True, exist_ok=True)

    # ---- connections -----------------------------------------------------------------------------------------
    def _connect(self) -> Any:
        if self.postgres:
            import ssl

            import pg8000.dbapi

            p = parse_pg_url(self.target)
            conn = pg8000.dbapi.connect(
                user=p["user"], password=p["password"], host=p["host"], port=p["port"], database=p["database"],
                ssl_context=ssl.create_default_context() if p["ssl"] else None, timeout=15,
            )
            return conn
        conn = sqlite3.connect(self.target, check_same_thread=False, timeout=10)
        return conn

    def _translate(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.postgres else sql

    def _run(self, sql: str, params: tuple | list = ()) -> Cursor:
        if self._conn is None:
            self._conn = self._connect()
        cur = self._conn.cursor()
        cur.execute(self._translate(sql), tuple(params))
        rows: list[dict[str, Any]] = []
        if cur.description:
            names = [d[0] for d in cur.description]
            rows = [dict(zip(names, r)) for r in cur.fetchall()]
        return Cursor(rows, cur.rowcount if cur.rowcount is not None else -1)

    @contextmanager
    def transaction(self) -> Iterator["Tx"]:
        """Everything inside commits together, or rolls back if anything raises.

        A connection that died (Neon closes idle ones) is dropped, so the next transaction opens a fresh one.
        """
        with self._lock:
            tx = Tx(self)
            try:
                yield tx
                if self._conn is not None:
                    self._conn.commit()
            except BaseException as exc:
                try:
                    if self._conn is not None:
                        self._conn.rollback()
                except Exception:  # noqa: BLE001 - the connection is gone
                    self._conn = None
                if self.postgres and _is_connection_error(exc):
                    self._conn = None
                raise

    def script(self, ddl: str) -> None:
        with self.transaction() as tx:
            for stmt in (s.strip() for s in ddl.split(";")):
                if stmt:
                    tx.execute(stmt)

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None


def _is_connection_error(exc: Exception) -> bool:
    name = type(exc).__name__
    return name in {"InterfaceError", "OperationalError", "ConnectionResetError", "BrokenPipeError"} or "connection" in str(exc).lower()


class Tx:
    def __init__(self, db: Db):
        self.db, self.statements = db, 0

    def execute(self, sql: str, params: tuple | list = ()) -> Cursor:
        self.statements += 1
        return self.db._run(sql, params)

    def executemany(self, sql: str, rows: list[tuple]) -> None:
        for r in rows:
            self.execute(sql, r)


_PG_URL = re.compile(r"^postgres(?:ql)?://(?P<user>[^:@/]*)(?::(?P<password>.*))?@(?P<host>[^:/?@]+)(?::(?P<port>\d+))?(?:/(?P<db>[^?]*))?(?:\?(?P<query>.*))?$", re.S)


def parse_pg_url(url: str) -> dict[str, Any]:
    """Split a Postgres URL into connection parts. More forgiving than urlparse: the password may contain ``@``, ``[`` or
    ``]`` (a copied-in placeholder like ``[YOUR-PASSWORD]`` must produce a login error, not a parser crash)."""
    m = _PG_URL.match(url.strip())
    if not m:
        raise ValueError("DATABASE_URL is not a valid postgresql://user:password@host:port/database URL")
    query = parse_qs(m["query"] or "")
    return {"user": unquote(m["user"] or ""), "password": unquote(m["password"] or ""), "host": m["host"],
            "port": int(m["port"] or 5432), "database": (m["db"] or "") or None,
            "ssl": query.get("sslmode", ["require"])[0] not in ("disable", "allow", "prefer")}


def redact_url(url: str) -> str:
    """A database URL with the password hidden, safe to show in an error or caption."""
    return re.sub(r"(://[^:/]*:).*@", r"\1***@", url)
