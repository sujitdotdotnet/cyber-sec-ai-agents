import pytest
from fastapi.testclient import TestClient

from secagents import web
from secagents.llm import get_router

client = TestClient(web.app)

FAIL = "Oct  9 10:05:{s:02d} web-01 sshd[1]: Failed password for {u} from 203.0.113.9 port 22 ssh2"
BRUTE_FORCE = "\n".join(FAIL.format(s=i, u=u) for i, u in enumerate(["root", "admin"] * 6))


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("SECAGENTS_API_TOKEN", "SECAGENTS_API_ALLOW_LLM"):
        monkeypatch.delenv(var, raising=False)


def test_landing_and_health():
    assert "SecAgents API" in client.get("/").text
    body = client.get("/health").json()
    assert body["ok"] is True and body["auth_required"] is False and body["llm_enabled_on_server"] is False


def test_demo_scenario_returns_the_full_assessment():
    r = client.post("/api/assess", json={"demo": True})
    assert r.status_code == 200
    s = r.json()["summary"]
    assert s["overall_risk"] == "CRITICAL" and s["incidents"] == 3 and s["log_detections"] == 14
    assert set(s["compliance"]) == {"NIST 800-53", "NIST CSF 2.0", "ISO 27001:2022", "SOC 2"}
    assert r.json()["result"]["report_md"].startswith("# Security Assessment Report")


def test_own_logs_are_analysed_from_content_only():
    r = client.post("/api/assess", json={"logs": {"auth.log": BRUTE_FORCE}})
    assert r.status_code == 200
    events = r.json()["result"]["log_findings"]["events"]
    assert [e["type"] for e in events] == ["SSH brute force"] and events[0]["src_ip"] == "203.0.113.9"


def test_code_requirements_and_dockerfile_are_scanned():
    r = client.post("/api/assess", json={
        "code": {"app.py": 'password = "hunter2hunter2"\napp.run(debug=True)\n'},
        "requirements": "flask==2.0.0\nrequests==2.19.1\n",
        "dockerfile": "FROM python:3.8\nUSER root\n",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["code_config_findings"] >= 3 and body["summary"]["cves_affecting_us"] >= 1


def test_nothing_to_analyse_is_a_clear_error():
    assert client.post("/api/assess", json={}).status_code == 422


@pytest.mark.parametrize("name", ["../../etc/passwd", "/etc/passwd", "C:/Windows/win.ini", "", "a/../../b", "sub/auth.log"])
def test_file_names_cannot_escape_the_temp_folder(name):
    assert client.post("/api/assess", json={"logs": {name: "x"}}).status_code == 422


def test_code_paths_are_confined_too():
    for bad in ("../x.py", "/abs.py", "a/../../b.py"):
        assert client.post("/api/assess", json={"code": {bad: "x = 1"}}).status_code == 422
    assert client.post("/api/assess", json={"code": {"pkg/mod.py": "x = 1\n"}}).status_code == 200


def test_size_and_file_count_limits(monkeypatch):
    monkeypatch.setattr(web, "MAX_TOTAL_CHARS", 100)
    assert client.post("/api/assess", json={"logs": {"auth.log": "x" * 101}}).status_code == 413
    monkeypatch.setattr(web, "MAX_TOTAL_CHARS", 10_000)
    monkeypatch.setattr(web, "MAX_FILES", 2)
    files = {f"m{i}.py": "x = 1" for i in range(3)}
    assert client.post("/api/assess", json={"code": files}).status_code == 413


def test_bearer_token_is_enforced_when_configured(monkeypatch):
    monkeypatch.setenv("SECAGENTS_API_TOKEN", "s3cret")
    assert client.get("/health").json()["auth_required"] is True  # health stays public
    body = {"logs": {"auth.log": BRUTE_FORCE}}
    assert client.post("/api/assess", json=body).status_code == 401
    assert client.post("/api/assess", json=body, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/api/assess", json=body, headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert client.post("/api/export/pdf", json=body).status_code == 401  # exports are protected as well


@pytest.mark.parametrize("fmt, magic, mime", [
    ("pdf", b"%PDF", "application/pdf"), ("docx", b"PK", "wordprocessingml"), ("xlsx", b"PK", "spreadsheetml"),
    ("md", b"# Security Assessment Report", "text/markdown"),
])
def test_exports_download_as_files(fmt, magic, mime):
    r = client.post(f"/api/export/{fmt}", json={"logs": {"auth.log": BRUTE_FORCE}})
    assert r.status_code == 200 and r.content.startswith(magic) and mime in r.headers["content-type"]
    assert f'security_report.{fmt}"' in r.headers["content-disposition"]


def test_unknown_export_format_is_404():
    assert client.post("/api/export/exe", json={"demo": True}).status_code == 404


def test_llm_is_off_unless_the_operator_allows_it(monkeypatch):
    seen = []
    real_run = web.run

    def spy(inputs):
        seen.append(get_router().enabled)
        return real_run(inputs)

    monkeypatch.setattr(web, "run", spy)
    router = get_router()
    client.post("/api/assess", json={"logs": {"auth.log": BRUTE_FORCE}, "use_llm": True})
    assert seen == [False]  # asked for, but the server has not allowed it
    monkeypatch.setenv("SECAGENTS_API_ALLOW_LLM", "1")
    client.post("/api/assess", json={"logs": {"auth.log": BRUTE_FORCE}, "use_llm": True})
    assert seen == [False, True]
    client.post("/api/assess", json={"logs": {"auth.log": BRUTE_FORCE}})  # not requested: stays off even when allowed
    assert seen == [False, True, False]
    assert router.enabled is True  # restored afterwards, so the dashboard is unaffected


def test_api_runs_the_whole_pipeline_without_chromadb(monkeypatch):
    """The serverless install leaves chromadb out; the agents must still produce the same assessment."""
    from secagents.rag import store

    baseline = client.post("/api/assess", json={"demo": True}).json()["summary"]
    monkeypatch.setattr(store, "chromadb", None)
    monkeypatch.setattr(store, "_kb", None)  # force a fresh knowledge base, built in memory
    summary = client.post("/api/assess", json={"demo": True}).json()["summary"]
    assert isinstance(store._kb.client, store.MemoryClient)
    assert summary == baseline
