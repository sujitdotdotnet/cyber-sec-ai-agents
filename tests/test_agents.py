from secagents.agents.log_monitor import detect
from secagents.agents.threat_intel import satisfies, version_key
from secagents.agents.vuln_scanner import run_vuln_scanner, scan_dockerfile
from secagents.config import settings
from secagents.graph import default_inputs, next_agent, run

SAMPLES = settings.samples_dir


def test_log_monitor_detects_full_kill_chain():
    events = detect([str(p) for p in (SAMPLES / "logs").glob("*.log")])
    types = {e["type"] for e in events}
    assert "Successful login after brute force" in types
    assert "Backdoor account created" in types
    assert "Web attack: SQL injection" in types
    assert "Web attack: Log4Shell (JNDI injection)" in types
    assert "Port scan" in types
    assert any("outbound" in t.lower() for t in types)
    assert events[0]["severity"] == "CRITICAL"


def test_log_monitor_quiet_on_normal_traffic(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Oct  9 09:03:31 web-01 sshd[1]: Accepted publickey for alice from 198.51.100.11 port 48609 ssh2\n")
    assert detect([str(log)]) == []


def test_vuln_scanner_finds_injection_and_secrets():
    app = SAMPLES / "vulnerable_app"
    out = run_vuln_scanner({"inputs": {"code_path": str(app), "requirements_path": str(app / "requirements.txt")}})["vuln_findings"]
    cwes = {f.get("cwe") for f in out["findings"]}
    assert {"CWE-89", "CWE-22", "CWE-798"} <= cwes
    assert any(p["name"] == "pyyaml" and p["version"] == "5.3" for p in out["inventory"])


def test_dockerfile_rules():
    findings, meta = scan_dockerfile(SAMPLES / "vulnerable_app" / "Dockerfile")
    rules = {f["rule"] for f in findings}
    assert {"EOL-IMAGE", "DS002", "SECRET-ENV"} <= rules
    assert meta["base_image"] == "python:3.7"


def test_version_matching():
    assert satisfies("5.3", "<5.4")
    assert not satisfies("5.4", "<5.4")
    assert satisfies("8.9p1", ">=8.5,<9.8")
    assert not satisfies("1.9.9", "<1.9.5p2")
    assert satisfies("1.0.1f", ">=1.0.1,<1.0.1g")
    assert satisfies("2.0", "all servers") is None
    assert version_key("2.10.1") > version_key("2.9")


def test_supervisor_respects_dependencies():
    assert next_agent([]) == "log_monitor"
    assert next_agent(["log_monitor"]) == "vuln_scanner"
    assert next_agent(["log_monitor", "vuln_scanner"]) == "threat_intel"
    assert next_agent(list(["log_monitor", "vuln_scanner", "threat_intel", "incident_response", "policy_checker"])) == "reporter"


def test_full_pipeline_end_to_end():
    state = run(default_inputs())
    assert set(state["completed"]) == {"log_monitor", "vuln_scanner", "threat_intel", "incident_response", "policy_checker"}
    intel = state["threat_intel"]
    assert intel["overall_risk"] == "CRITICAL"
    assert {m["cve"] for m in intel["cve_matches"]} >= {"CVE-2020-14343", "CVE-2018-18074"}
    # Log4Shell was attempted but log4j is not deployed: must not be reported as affected.
    assert intel["exploit_attempts"][0]["cve"] == "CVE-2021-44228"
    assert intel["exploit_attempts"][0]["component_present"] is False
    assert any(c["cwe"] == "CWE-89" for c in intel["correlations"])
    ir = state["incident_plan"]
    assert ir["highest_priority"] == "P1"
    assert any("sysupdate" in s["action"] for s in ir["steps"])
    comp = state["compliance"]
    assert {f["framework"] for f in comp["frameworks"]} == {"NIST 800-53", "ISO 27001:2022", "SOC 2", "NIST CSF 2.0"}
    assert any(g["check"] == "mfa_enabled" for g in comp["gaps"])
    for heading in ("Log Monitor", "Threat Intelligence", "Vulnerability Scanner", "Incident Response", "Policy Checker"):
        assert heading in state["report_md"]


def test_pipeline_with_llm_responses(monkeypatch):
    """Exercise every LLM-dependent branch with canned model output."""
    from secagents import llm

    def fake_complete(self, system, prompt, *, agent="", max_tokens=8000):
        self.calls.append({"agent": agent, "provider": "fake", "model": "fake"})
        if agent.endswith("rag-grader"):
            text = '{"relevant": [0], "rewrite": ""}'
        elif agent == "incident_response":
            text = ('```json\n{"briefing": "LLM briefing", "additional_steps": [{"incident": "INC-01", '
                    '"phase": "Containment", "action": "Revoke cloud tokens", "owner": "Cloud", "priority": "P1"}]}\n```')
        else:
            text = f"LLM text for {agent}"
        return llm.LLMResult(text, "fake", "fake")

    monkeypatch.setattr(llm.LLMRouter, "available_providers", lambda self: ["fake"])
    monkeypatch.setattr(llm.LLMRouter, "complete", fake_complete)
    state = run(default_inputs())
    assert state["log_findings"]["narrative"] == "LLM text for log_monitor"
    assert state["threat_intel"]["summary"].startswith("LLM text for threat_intel")  # the model's text, then the critic's caveats
    assert "Review notes (uncertainty critic)" in state["threat_intel"]["summary"]
    assert any("graded" in t for t in state["threat_intel"]["rag_trace"])
    assert state["incident_plan"]["briefing"].startswith("LLM briefing") and "Review notes" in state["incident_plan"]["briefing"]
    assert any(s.get("source") == "llm" and s["action"] == "Revoke cloud tokens" for s in state["incident_plan"]["steps"])
    assert state["compliance"]["roadmap"] == "LLM text for policy_checker"


def test_scan_history_roundtrip(tmp_path, monkeypatch):
    from dataclasses import replace

    from secagents import history

    monkeypatch.setattr(history, "settings", replace(history.settings, history_dir=tmp_path))
    result = {"threat_intel": {"overall_risk": "CRITICAL"}, "incident_plan": {"incidents": [1, 2]}}
    first = history.save(result, "", "Demo attack scenario")
    second = history.save(result, "Prod web", "Upload my own files")
    scans = history.list_scans()
    assert [s["id"] for s in scans] == [second, first]
    assert scans[0]["name"] == "Prod web" and "result" not in scans[0]
    assert scans[1]["name"].startswith("Demo attack scenario") and scans[1]["name"].endswith("CRITICAL")
    assert history.load(first)["result"] == result
    history.rename(first, "Renamed")
    assert history.load(first)["name"] == "Renamed"
    history.delete(first)
    assert [s["id"] for s in history.list_scans()] == [second]
