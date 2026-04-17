import pytest

from el.case_template import render
from el.evidence import intake as intake_mod
from el.intel.ach import HypothesisRow
from el.orchestrator.coordinator import Coordinator


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def test_renders_required_sections(tmp_path):
    manifest = {
        "case_id": "c-test", "intake_utc": "2026-04-17T10:00:00+00:00",
        "input_path": "/cases/x.bin", "input_size_bytes": 42,
        "input_sha256": "a" * 64, "input_sha1": "b" * 40, "input_md5": "c" * 32,
        "input_magic": "deadbeef", "evidence_kind": "pcap",
    }
    ranking = [HypothesisRow(hyp_id="H_C2_BEACONING", name="C2 beaconing", score=5),
               HypothesisRow(hyp_id="H_BENIGN_NO_INCIDENT", name="Benign", score=-3)]
    p = render(tmp_path, manifest, investigator="NetworkAnalystAgent",
               final_state="done", leading_hypothesis="H_C2_BEACONING",
               leading_hypothesis_score=5, ach_ranking=ranking, findings=[])
    text = p.read_text()
    assert "# CLAUDE.md" in text
    assert "Case Overview" in text
    assert "c-test" in text
    assert "NetworkAnalystAgent" in text
    assert "pcap" in text
    assert "H_C2_BEACONING" in text
    assert "Read-only" in text
    assert "findings.sqlite" in text
    assert "graph.kuzu" in text
    assert "iocs.json" in text
    assert "stix-bundle.json" in text
    assert "forensic_audit.log" in text
    assert "Hypothesis Ranking" in text


def test_coordinator_writes_per_case_claude_md(isolated):
    src = isolated / "fake.bin"
    src.write_bytes(b"x")
    result = Coordinator().investigate(src, case_id="t-cmd")
    cmd_path = result.case_dir / "CLAUDE.md"
    assert cmd_path.exists()
    txt = cmd_path.read_text()
    assert "case=t-cmd" not in txt  # audit log syntax shouldn't leak in
    assert "t-cmd" in txt
    assert "Hypothesis Ranking" in txt
