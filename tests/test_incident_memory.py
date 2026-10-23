"""Memory of past incidents: recalled for the same owner only, relearned after a restart, never fatal."""

import uuid
from dataclasses import replace

import pytest

from secagents import history, incident_memory, session
from secagents.config import settings
from secagents.rag.store import KnowledgeBase

REAL_BACKFILL = incident_memory._backfill  # kept so the one test about relearning can switch it back on

SSH = {"id": "INC-01", "priority": "P1", "severity": "CRITICAL", "title": "Host compromise on web-01 via SSH brute force",
       "summary": "Attacker 203.0.113.45 gained access as admin, escalated to root and created a backdoor account."}
WEB = {"id": "INC-02", "priority": "P1", "severity": "CRITICAL", "title": "Web application exploitation (SQL injection)",
       "summary": "SQL injection from 192.0.2.77 returned HTTP 200 against a vulnerable login endpoint."}


@pytest.fixture
def kb(monkeypatch):
    k = KnowledgeBase(replace(settings, offline=True), persist=False)
    monkeypatch.setattr(incident_memory, "get_kb", lambda: k)
    return k


@pytest.fixture
def me(monkeypatch):
    name = f"owner-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(incident_memory, "owner", lambda: name)
    monkeypatch.setattr(incident_memory, "_backfilled", set())
    monkeypatch.setattr(incident_memory, "_backfill", lambda kb: None)  # never read the real saved scans in a test
    return name


def test_a_similar_incident_is_recalled_with_where_it_came_from(kb, me):
    assert incident_memory.remember("20261001T100000000000Z", [SSH, WEB]) == 2
    new = {"id": "INC-07", "title": "Host compromise on db-02 via SSH brute force", "summary": "Attacker gained access as admin after many failed SSH logins and created a backdoor user."}
    found = incident_memory.similar([new])
    top = found["INC-07"][0]
    assert top["scan"] == "20261001T100000000000Z" and top["incident"] == "INC-01" and "SSH brute force" in top["title"] and top["score"] > 0.5


def test_unrelated_incidents_are_not_reported_as_similar(kb, me):
    incident_memory.remember("20261001T100000000000Z", [SSH])
    odd = {"id": "INC-09", "title": "Quarterly access review overdue", "summary": "Accounts of former staff were not reviewed."}
    assert incident_memory.similar([odd]) == {}


def test_nobody_else_can_see_my_incidents(kb, monkeypatch):
    owners = {"now": "alice"}
    monkeypatch.setattr(incident_memory, "owner", lambda: owners["now"])
    monkeypatch.setattr(incident_memory, "_backfilled", set())
    monkeypatch.setattr(incident_memory, "_backfill", lambda kb: None)
    uid = uuid.uuid4().hex[:6]
    owners["now"] = f"alice-{uid}"
    incident_memory.remember("20261001T100000000000Z", [SSH])
    assert incident_memory.similar([SSH])  # alice finds hers
    owners["now"] = f"bob-{uid}"
    assert incident_memory.similar([SSH]) == {}  # bob finds nothing, even with identical text
    incident_memory.remember("20261002T100000000000Z", [WEB])
    assert [m["incident"] for m in incident_memory.similar([WEB])["INC-02"]] == ["INC-02"]  # and only his own
    owners["now"] = f"alice-{uid}"
    assert all(m["scan"] == "20261001T100000000000Z" for ms in incident_memory.similar([SSH, WEB]).values() for m in ms)


def test_saving_the_same_scan_twice_does_not_duplicate_the_memory(kb, me):
    for _ in range(3):
        incident_memory.remember("20261001T100000000000Z", [SSH])
    assert len(kb._incident_collection().get(where={"owner": me})["ids"]) == 1


def test_guests_leave_nothing_behind_and_find_nothing(kb, me, monkeypatch):
    monkeypatch.setattr(incident_memory, "settings", replace(settings, public=True))
    monkeypatch.setattr(session, "scan_store", lambda: None)  # a guest has no stored history
    assert incident_memory.enabled() is False
    assert incident_memory.remember("20261001T100000000000Z", [SSH]) == 0 and incident_memory.similar([SSH]) == {}
    assert kb._incident_collection().get(where={"owner": me})["ids"] == []
    monkeypatch.setattr(session, "scan_store", lambda: object())  # a signed-in user has one
    assert incident_memory.enabled() is True and incident_memory.remember("20261001T100000000000Z", [SSH]) == 1


def test_a_broken_memory_never_breaks_an_assessment_or_a_save(monkeypatch, me):
    def boom():
        raise RuntimeError("chroma is down")

    monkeypatch.setattr(incident_memory, "get_kb", boom)
    assert incident_memory.remember("20261001T100000000000Z", [SSH]) == 0
    assert incident_memory.similar([SSH]) == {}
    assert incident_memory.remember("x", []) == 0 and incident_memory.similar([]) == {}


def test_after_a_restart_the_memory_is_relearned_from_the_saved_scans(kb, me, monkeypatch, tmp_path):
    """The vector store is empty (a restart on a host with a temporary disk) but the scan history survived."""
    monkeypatch.setattr(history, "settings", replace(settings, history_dir=tmp_path))
    monkeypatch.setattr(incident_memory, "_backfill", REAL_BACKFILL)  # this is the one test about relearning
    monkeypatch.setattr(incident_memory, "remember", lambda *a, **k: 0)  # save without learning, to simulate the lost store
    sid = history.save({"incident_plan": {"incidents": [SSH]}, "threat_intel": {}}, "earlier scan", "demo")
    assert kb._incident_collection().get(where={"owner": me})["ids"] == []
    again = incident_memory.similar([{"id": "INC-05", "title": "Host compromise on db-02 via SSH brute force", "summary": "Attacker gained access as admin after many failed SSH logins and created a backdoor user."}])
    assert again["INC-05"][0]["scan"] == sid and again["INC-05"][0]["incident"] == "INC-01"


def test_the_incident_response_agent_attaches_what_it_remembers(me):
    from secagents.graph import run

    first = dict(run())
    assert not any("similar_past" in i for i in first["incident_plan"]["incidents"])  # nothing seen before
    incident_memory.remember("20261001T100000000000Z", first["incident_plan"]["incidents"])
    second = dict(run())
    with_history = [i for i in second["incident_plan"]["incidents"] if i.get("similar_past")]
    assert with_history and all(m["scan"] == "20261001T100000000000Z" for i in with_history for m in i["similar_past"])
    assert with_history[0]["similar_past"][0]["score"] >= 0.2
