"""The database layer: SQLite behaviour, and the Postgres path through a fake DB-API driver (no server needed)."""

import sys
import types

import pytest

from secagents.db import Db, is_postgres, open_db, redact_url
from secagents.memory import Memory


def test_dict_rows_commit_and_rollback(tmp_path):
    db = Db(tmp_path / "t.db")
    db.script("CREATE TABLE t (id TEXT PRIMARY KEY, n INTEGER); CREATE INDEX IF NOT EXISTS t_n ON t (n)")
    with db.transaction() as tx:
        tx.execute("INSERT INTO t VALUES (?,?)", ("a", 1))
        tx.executemany("INSERT INTO t VALUES (?,?)", [("b", 2), ("c", 3)])
    with db.transaction() as tx:
        assert tx.execute("SELECT id, n FROM t ORDER BY n").fetchall() == [{"id": "a", "n": 1}, {"id": "b", "n": 2}, {"id": "c", "n": 3}]
        assert tx.execute("SELECT n FROM t WHERE id=?", ("zz",)).fetchone() is None
        assert tx.execute("DELETE FROM t WHERE n>?", (1,)).rowcount == 2
    with pytest.raises(RuntimeError):
        with db.transaction() as tx:
            tx.execute("INSERT INTO t VALUES (?,?)", ("d", 4))
            raise RuntimeError("boom")
    with db.transaction() as tx:
        assert [r["id"] for r in tx.execute("SELECT id FROM t").fetchall()] == ["a"]  # the failed transaction left nothing behind


def test_open_db_shares_one_connection_per_file_but_memory_is_private(tmp_path):
    assert open_db(tmp_path / "x.db") is open_db(tmp_path / "x.db")
    assert open_db(":memory:") is not open_db(":memory:")


def test_two_memories_on_one_database_see_the_same_facts(tmp_path):
    a, b = Memory(tmp_path / "m.db"), Memory(tmp_path / "m.db")
    a.remember("shared fact one", "ws")
    assert [f["text"] for f in b.facts("ws")] == ["shared fact one"]


def test_url_detection_and_password_hiding():
    assert is_postgres("postgresql://u:p@h/db") and is_postgres("POSTGRES://u@h/db") and not is_postgres("C:/x/memory.db")
    assert redact_url("postgresql://neon:s3cret@ep-1.neon.tech/db?sslmode=require") == "postgresql://neon:***@ep-1.neon.tech/db?sslmode=require"


class FakePg:
    """A stand-in for pg8000.dbapi that records what it was asked and answers like a driver would."""

    def __init__(self):
        self.connects, self.executed, self.commits, self.rollbacks = [], [], 0, 0
        self.fail_next = None

    def module(self):
        pg = self
        mod = types.ModuleType("pg8000.dbapi")

        class Cur:
            description = [("n",)]
            rowcount = 1

            def execute(self, sql, params=()):
                if pg.fail_next:
                    err, pg.fail_next = pg.fail_next, None
                    raise err
                pg.executed.append((sql, params))

            def fetchall(self):
                return [(7,)]

        class Conn:
            def cursor(self):
                return Cur()

            def commit(self):
                pg.commits += 1

            def rollback(self):
                pg.rollbacks += 1

            def close(self):
                pass

        mod.connect = lambda **kw: (pg.connects.append(kw), Conn())[1]
        pkg = types.ModuleType("pg8000")
        pkg.dbapi = mod
        return pkg, mod


@pytest.fixture
def fake_pg(monkeypatch):
    fake = FakePg()
    pkg, mod = fake.module()
    monkeypatch.setitem(sys.modules, "pg8000", pkg)
    monkeypatch.setitem(sys.modules, "pg8000.dbapi", mod)
    return fake


def test_postgres_connection_uses_the_url_parts_and_requires_tls_by_default(fake_pg):
    db = Db("postgresql://neon_user:p%40ss@ep-cool.neon.tech:5433/appdb?sslmode=require")
    with db.transaction() as tx:
        assert tx.execute("SELECT 7 AS n").fetchone() == {"n": 7}
    kw = fake_pg.connects[0]
    assert (kw["user"], kw["password"], kw["host"], kw["port"], kw["database"]) == ("neon_user", "p@ss", "ep-cool.neon.tech", 5433, "appdb")
    assert kw["ssl_context"] is not None
    plain = Db("postgresql://u:p@localhost/db?sslmode=disable")
    with plain.transaction() as tx:
        tx.execute("SELECT 1")
    assert fake_pg.connects[1]["ssl_context"] is None


def test_postgres_placeholders_are_translated_and_commits_happen(fake_pg):
    db = Db("postgresql://u:p@h/db")
    with db.transaction() as tx:
        tx.execute("SELECT * FROM t WHERE a=? AND b=?", ("x", 2))
    assert fake_pg.executed[-1] == ("SELECT * FROM t WHERE a=%s AND b=%s", ("x", 2)) and fake_pg.commits == 1


def test_postgres_connection_is_reused_and_replaced_after_it_dies(fake_pg):
    db = Db("postgresql://u:p@h/db")
    for _ in range(3):
        with db.transaction() as tx:
            tx.execute("SELECT 1")
    assert len(fake_pg.connects) == 1  # one connection serves every call
    fake_pg.fail_next = ConnectionResetError("server closed the connection")
    with pytest.raises(ConnectionResetError):
        with db.transaction() as tx:
            tx.execute("SELECT 1")
    with db.transaction() as tx:  # the next call opens a fresh connection instead of failing forever
        tx.execute("SELECT 1")
    assert len(fake_pg.connects) == 2


def test_urls_with_placeholder_brackets_or_at_signs_in_the_password_parse_instead_of_crashing():
    from secagents.db import parse_pg_url

    p = parse_pg_url("postgresql://postgres:[YOUR-PASSWORD]@db.abc.supabase.co:5432/postgres")
    assert (p["user"], p["password"], p["host"], p["port"], p["database"]) == ("postgres", "[YOUR-PASSWORD]", "db.abc.supabase.co", 5432, "postgres")
    q = parse_pg_url("postgresql://u:p@ss@h.neon.tech/db?sslmode=require")
    assert (q["password"], q["host"], q["ssl"]) == ("p@ss", "h.neon.tech", True)
    assert parse_pg_url("postgres://u:p@h/db?sslmode=disable")["ssl"] is False
    with pytest.raises(ValueError, match="not a valid"):
        parse_pg_url("postgresql://no-at-sign-here")


def test_redacting_hides_the_whole_password_even_with_an_at_sign():
    assert "ss" not in redact_url("postgresql://u:p@ss@h.neon.tech/db").split("@")[0]
    assert redact_url("postgresql://u:p@ss@h.neon.tech/db") == "postgresql://u:***@h.neon.tech/db"


def test_a_broken_database_url_falls_back_to_local_storage_and_says_why(tmp_path, monkeypatch):
    from dataclasses import replace

    from secagents import session
    from secagents.config import settings

    monkeypatch.setattr(session, "_shared", {"db": None, "error": "", "at": 0.0})
    monkeypatch.setattr(session, "settings", replace(settings, database_url="postgresql://u:[PASSWORD]@no-such-host.invalid/db",
                                                     memory_db=tmp_path / "local.db"))
    db = session.shared_db()
    assert not db.postgres and db.target == str(tmp_path / "local.db")  # the site still works
    assert session.db_error() and "PASSWORD" not in session.db_error()  # and the reason is available, without the password
    assert session.shared_db() is db  # not retried on every call


def test_without_a_database_url_there_is_no_error(tmp_path, monkeypatch):
    from dataclasses import replace

    from secagents import session
    from secagents.config import settings

    monkeypatch.setattr(session, "_shared", {"db": None, "error": "", "at": 0.0})
    monkeypatch.setattr(session, "settings", replace(settings, database_url="", memory_db=tmp_path / "local.db"))
    assert not session.shared_db().postgres and session.db_error() == ""
