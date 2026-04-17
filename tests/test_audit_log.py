import pytest

from el.audit import AuditLog
from el.evidence import intake as intake_mod
from el.orchestrator.coordinator import Coordinator


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def test_audit_log_format_is_grep_friendly(tmp_path):
    a = AuditLog(tmp_path, "case-x")
    a.info("agent_done", agent="triage", findings_emitted=3)
    a.warn("plugin_no_rows", plugin="windows.netscan")
    a.error("agent_failed", agent="memory_forensicator", err="boom")
    text = a.path.read_text()
    assert "[INFO] case=case-x event=agent_done" in text
    assert "agent=triage" in text
    assert "findings_emitted=3" in text
    assert "[WARN]" in text and "plugin=windows.netscan" in text
    assert "[ERROR]" in text


def test_coordinator_writes_audit_lines_per_state(isolated):
    src = isolated / "fake.bin"
    src.write_bytes(b"x")
    result = Coordinator().investigate(src, case_id="t-audit")
    log = (result.case_dir / "analysis" / "forensic_audit.log").read_text()
    assert "intake_complete" in log
    assert "state_transition" in log
    assert "from_=triage" in log
    assert "to=hypothesis_gen" in log
    assert "agent_start" in log
    assert "agent_done" in log
    assert "case_complete" in log
    assert f"case=t-audit" in log
