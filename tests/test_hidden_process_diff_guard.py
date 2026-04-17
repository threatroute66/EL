"""Regression test from a real DC memory image (case dc-01): when Vol3
pslist returns 0 rows due to symbol/structure mismatch, MemoryForensicator
must NOT flag every psscan PID as 'hidden'. That false positive would
trigger H_PROCESS_INJECTION + H_ROOTKIT on a clean system."""
from pathlib import Path

from el.agents.base import AgentContext
from el.agents.memory_forensicator import MemoryForensicatorAgent
from el.evidence.ledger import open_ledger
from el.evidence.intake import intake as intake_mod_intake
from el.skills.vol3 import PluginRun


def _ctx(tmp_path, monkeypatch):
    from el.evidence import intake
    monkeypatch.setattr(intake, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "fake.bin"; src.write_bytes(b"x")
    m = intake.intake(src, case_id="t-guard")
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id="t-guard", case_dir=Path(m.case_dir),
                        input_path=Path(m.input_path), manifest=m.__dict__)


def _run(plugin, rows, tmp_path):
    p = tmp_path / f"{plugin}.json"
    p.write_text("[]")
    return PluginRun(
        plugin=plugin, image=tmp_path / "img",
        rc=0, stdout_path=p, stderr_path=tmp_path / f"{plugin}.stderr",
        rows=rows, command=["vol", "..."], version="2.27.0",
    )


def test_empty_pslist_does_not_flag_122_hidden(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    pslist = _run("pslist", [], tmp_path)
    psscan = _run("psscan", [{"PID": i} for i in range(1, 124)], tmp_path)
    findings = MemoryForensicatorAgent()._diff_hidden_processes(ctx, pslist, psscan)
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == "insufficient"
    assert "pslist returned 0 rows" in f.claim
    assert "H_PROCESS_INJECTION" not in f.hypotheses_supported


def test_genuine_hidden_processes_still_flagged(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    pslist = _run("pslist", [{"PID": p} for p in (4, 100, 200)], tmp_path)
    psscan = _run("psscan", [{"PID": p} for p in (4, 100, 200, 9999)], tmp_path)
    findings = MemoryForensicatorAgent()._diff_hidden_processes(ctx, pslist, psscan)
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == "high"
    assert "9999" in f.claim
    assert "H_PROCESS_INJECTION" in f.hypotheses_supported
