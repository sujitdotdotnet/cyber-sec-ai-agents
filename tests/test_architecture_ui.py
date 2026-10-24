"""The dashboard shows the new pipeline: confidence, correlation, past incidents and the human approval gate."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from secagents import history
from secagents.config import settings

APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")


@pytest.fixture
def folders(tmp_path):
    saved = {k: getattr(settings, k) for k in ("history_dir", "live_dir", "memory_db")}
    object.__setattr__(settings, "history_dir", tmp_path / "history")
    object.__setattr__(settings, "live_dir", tmp_path / "live")
    object.__setattr__(settings, "memory_db", tmp_path / "memory.db")
    yield tmp_path
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


@pytest.fixture
def assessed(folders):
    at = AppTest.from_file(APP, default_timeout=240).run()
    [run] = [b for b in at.button if "Run assessment" in b.label]
    run.click().run()
    assert not at.exception
    return at


def text(at):
    return " ".join(m.value for m in [*at.markdown, *at.caption, *at.info, *at.warning])


def test_the_overview_shows_how_sure_the_findings_are_and_the_critics_doubts(assessed):
    assert "Confidence of the findings:" in text(assessed)
    [panel] = [e for e in assessed.expander if e.label.startswith("🧪 Critic review")]
    assert panel.proto.expanded is False
    body = " ".join(m.value for m in panel.markdown)
    assert "Review notes (uncertainty critic)" in body


def test_the_trace_shows_the_plan_the_parallel_waves_and_the_review_steps(assessed):
    messages = [t["message"] for t in assessed.session_state["result"]["trace"]]
    assert any(m.startswith("plan: log_monitor + vuln_scanner → threat_intel → incident_response + policy_checker") for m in messages)
    assert "dispatching log_monitor + vuln_scanner in parallel" in messages
    agents = [t["agent"] for t in assessed.session_state["result"]["trace"]]
    assert agents[-4:] == ["correlator", "critic", "human_gate", "reporter"]


def test_the_cve_table_puts_confidence_next_to_severity(assessed):
    import pandas as pd

    frames = [d.value for d in assessed.dataframe if isinstance(d.value, pd.DataFrame) and "cve" in d.value.columns]
    assert frames
    cols = list(frames[0].columns)
    assert cols[:7] == ["cve", "package", "installed", "fixed", "cvss", "severity", "confidence"]
    assert "affected_spec" not in cols and "osv_id" not in cols  # internal helpers are not shown


def test_the_response_tab_has_the_gate_and_nothing_is_approved_by_default(assessed):
    result = assessed.session_state["result"]
    assert "Human approval gate" in " ".join(h.value for h in assessed.subheader)
    assert "executes none of these steps" in text(assessed)
    scan_id = assessed.session_state["scan"]["id"]
    n = len(result["containment_gate"]["actions"])
    radios = [r for r in assessed.radio if r.key and r.key.startswith(f"gate-choice-{scan_id}-")]
    assert len(radios) == n and all(r.value == "Pending" for r in radios)
    assert result["containment_gate"]["status"] == "pending_approval"


def test_approving_an_edited_action_is_recorded_saved_and_exported(assessed):
    from secagents import approvals

    scan_id = assessed.session_state["scan"]["id"]
    first = assessed.session_state["result"]["containment_gate"]["actions"][0]
    assessed.radio(key=f"gate-choice-{scan_id}-{first['id']}-0").set_value("Approve")
    assessed.text_input(key=f"gate-cmd-{scan_id}-{first['id']}-0").set_value("sudo ufw insert 1 deny from 203.0.113.45 comment 'INC-01 reviewed'")
    [save] = [b for b in assessed.button if b.label == "Save decisions"]
    save.click().run()
    assert not assessed.exception
    gate = assessed.session_state["result"]["containment_gate"]
    done = next(a for a in gate["actions"] if a["id"] == first["id"])
    assert done["status"] == "approved" and done["approved_command"].endswith("comment 'INC-01 reviewed'") and done["decided_by"] == "local user"
    assert gate["status"] == "in_review" and gate["audit"][0]["by"] == "local user" and gate["audit"][0]["command_before"] == first["command"]
    stored = history.load(scan_id)["result"]["containment_gate"]  # and it was written to the saved scan
    assert stored["actions"][0]["status"] == "approved" and stored["audit"] == gate["audit"]
    script = approvals.runbook(gate)
    assert "comment 'INC-01 reviewed'" in script and f"[{first['id']}]" in script and "approved by local user" in script
    assert "Audit trail (1)" in [e.label for e in assessed.expander]


def test_a_reopened_scan_keeps_its_decisions(assessed):
    scan_id = assessed.session_state["scan"]["id"]
    first = assessed.session_state["result"]["containment_gate"]["actions"][0]
    assessed.radio(key=f"gate-choice-{scan_id}-{first['id']}-0").set_value("Reject")
    [b for b in assessed.button if b.label == "Save decisions"][0].click().run()
    again = AppTest.from_file(APP, default_timeout=240).run()  # a new browser session
    again.button(key=f"open-{scan_id}").click().run()
    assert not again.exception
    assert again.session_state["result"]["containment_gate"]["actions"][0]["status"] == "rejected"
    assert again.radio(key=f"gate-choice-{scan_id}-{first['id']}-0").value == "Reject"


def test_the_report_tab_carries_the_review_sections(assessed):
    md = assessed.session_state["result"]["report_md"]
    assert "## 6. Uncertainty review" in md and "### Containment approval (human gate)" in md


def test_after_saving_the_user_sees_what_was_saved_and_the_runbook_button_counts_it(assessed):
    scan_id = assessed.session_state["scan"]["id"]
    first = assessed.session_state["result"]["containment_gate"]["actions"][0]
    assert any("approved runbook (0 approved)" in b.label.lower() for b in assessed.get("download_button"))  # nothing chosen yet
    assessed.radio(key=f"gate-choice-{scan_id}-{first['id']}-0").set_value("Approve")
    [save] = [b for b in assessed.button if b.label == "Save decisions"]
    save.click().run()
    assert not assessed.exception
    assert any("Saved: 1 approved" in s.value for s in assessed.success)
    assert any("approved runbook (1 approved)" in b.label.lower() for b in assessed.get("download_button"))
