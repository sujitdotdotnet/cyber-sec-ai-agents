"""SQLite memory: threads, remembered facts, workspace isolation, secret redaction, export/import."""

import json

import pytest

from secagents.memory import Memory, looks_secret, redact


@pytest.fixture
def mem(tmp_path):
    return Memory(tmp_path / "m.db")


def test_thread_round_trip_and_title_from_first_question(mem):
    tid = mem.create_thread("ws")
    msgs = [{"role": "user", "content": "What is Log4Shell?"}, {"role": "assistant", "content": "A JNDI RCE."}]
    mem.save_messages(tid, "ws", msgs)
    assert mem.messages(tid, "ws") == msgs
    assert mem.threads("ws")[0]["title"] == "What is Log4Shell?"
    mem.save_messages(tid, "ws", msgs + [{"role": "user", "content": "and the fix?"}])
    assert len(mem.messages(tid, "ws")) == 3  # replaced, not duplicated


def test_workspaces_are_isolated(mem):
    tid = mem.create_thread("alice")
    mem.save_messages(tid, "alice", [{"role": "user", "content": "private"}])
    fid = mem.remember("alice runs nginx", "alice")
    assert mem.messages(tid, "bob") == [] and mem.threads("bob") == []
    assert mem.recall("nginx", "bob") == [] and not mem.forget(fid, "bob")
    assert not mem.delete_thread(tid, "bob")
    with pytest.raises(KeyError):
        mem.save_messages(tid, "bob", [])
    assert mem.forget(fid, "alice") and mem.delete_thread(tid, "alice")


def test_recall_finds_facts_by_meaning_overlap(mem):
    mem.remember("Our public web servers run nginx 1.18 on Ubuntu", "w")
    mem.remember("The SOC on-call rotation changes every Monday", "w")
    top = mem.recall("which web server software do we run", "w")
    assert top and "nginx" in top[0]["text"]
    assert mem.recall("quantum chromodynamics", "w") == []


def test_secrets_are_never_stored(mem):
    assert mem.remember("my key is sk-ant-abcdefghijklmnop1234", "w") is None
    assert mem.remember("password: hunter2hunter2", "w") is None
    assert mem.facts("w") == []
    tid = mem.create_thread("w")
    mem.save_messages(tid, "w", [{"role": "user", "content": "use sk-abcdefghijklmnopqrstuv please"}])
    assert "sk-abc" not in mem.messages(tid, "w")[0]["content"]
    assert looks_secret("AKIAABCDEFGHIJKLMNOP") and redact("token=abcdef123456") == "[redacted]"


def test_duplicate_facts_collapse_and_the_workspace_is_capped(mem, monkeypatch):
    assert mem.remember("We use Okta SSO", "w") == mem.remember("we use okta sso", "w")
    assert len(mem.facts("w")) == 1
    monkeypatch.setattr("secagents.memory.MAX_FACTS", 2)
    mem.remember("second fact here", "w")
    assert mem.remember("third fact here", "w") is None


def test_export_then_import_into_a_fresh_database(mem, tmp_path):
    tid = mem.create_thread("w")
    mem.save_messages(tid, "w", [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}])
    mem.remember("prod is in eu-west-1", "w")
    dump = mem.export_json("w")
    other = Memory(tmp_path / "other.db")
    assert other.import_json(dump, "new") == {"facts": 1, "threads": 1}
    assert other.facts("new")[0]["text"] == "prod is in eu-west-1"
    assert other.messages(other.threads("new")[0]["id"], "new")[1]["content"] == "hi"
    assert other.import_json(dump, "new")["facts"] == 1  # a known fact maps to the same id, not a duplicate
    assert len(other.facts("new")) == 1


def test_import_rejects_garbage(mem):
    with pytest.raises(ValueError):
        mem.import_json("not json", "w")
    with pytest.raises(ValueError):
        mem.import_json(json.dumps([1, 2]), "w")


def test_in_memory_database_works():
    m = Memory(":memory:")
    assert m.remember("fact one two", "w")
    assert len(m.facts("w")) == 1
