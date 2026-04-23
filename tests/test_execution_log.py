"""Tests for the Find Evil 2026 agent-execution-log artefacts.

Every Finding's evidence already carries tool + command + output_sha256,
so these tests verify the aggregator correctly merges the audit log +
findings ledger into a chronological stream and surfaces the
traceability matrix columns judges need."""
import json
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.evidence.ledger import insert as ledger_insert, open_ledger
from el.reporting.execution_log import (
    _parse_audit_line, build_events, write_all,
)
from el.schemas.finding import EvidenceItem, Finding


def _mk_case(tmp_path, monkeypatch, case_id="exec-log-t"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "evidence.bin"
    src.write_bytes(b"evidence\n")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return Path(m.case_dir)


# ---------------------------------------------------------------------------
# Audit-line parser
# ---------------------------------------------------------------------------

def test_parse_audit_line_kv():
    rec = _parse_audit_line(
        "2026-04-23T07:53:07+00:00 [INFO] case=foo event=agent_start "
        "pid=1234 agent=triage state=triage")
    assert rec["ts_utc"] == "2026-04-23T07:53:07+00:00"
    assert rec["level"] == "INFO"
    assert rec["case"] == "foo"
    assert rec["event"] == "agent_start"
    assert rec["agent"] == "triage"


def test_parse_audit_line_quoted_value():
    rec = _parse_audit_line(
        "2026-04-23T07:53:07+00:00 [INFO] case=foo event=x "
        "name='value with spaces'")
    assert rec["name"] == "value with spaces"


def test_parse_audit_line_rejects_malformed():
    assert _parse_audit_line("garbage") is None
    assert _parse_audit_line("") is None


# ---------------------------------------------------------------------------
# build_events — audit + findings merge
# ---------------------------------------------------------------------------

def test_build_events_merges_audit_and_findings(tmp_path, monkeypatch):
    case_dir = _mk_case(tmp_path, monkeypatch)
    # Seed a Finding with evidence
    ledger_insert(case_dir, Finding(
        case_id="exec-log-t", agent="triage",
        claim="disk image recognised",
        confidence="high",
        evidence=[EvidenceItem(
            tool="el.triage", version="0.1.0",
            command="magic bytes check",
            output_sha256="0" * 64, output_path="/tmp/xyz.head")],
        hypotheses_supported=["H_DISK_ARTIFACTS"],
    ))
    events = build_events(case_dir)
    types = {e.event_type for e in events}
    # At least tool_execution + finding_emitted land from the Finding
    assert "tool_execution" in types
    assert "finding_emitted" in types
    # Ordering — tool_execution comes before finding_emitted when
    # they share a ts
    idx_tool = next(i for i, e in enumerate(events)
                    if e.event_type == "tool_execution")
    idx_find = next(i for i, e in enumerate(events)
                    if e.event_type == "finding_emitted")
    # Same finding_id linkage
    t = events[idx_tool]
    f = events[idx_find]
    assert t.finding_id == f.finding_id
    assert t.tool == "el.triage"
    assert t.output_sha256 == "0" * 64
    assert idx_tool < idx_find


def test_build_events_chronological(tmp_path, monkeypatch):
    """Events sort by ts_utc primarily."""
    case_dir = _mk_case(tmp_path, monkeypatch)
    # Manually write a couple of audit lines with different timestamps
    log = case_dir / "analysis" / "forensic_audit.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(
        "2026-01-02T00:00:00+00:00 [INFO] case=exec-log-t event=state_transition pid=1 from_=intake to=triage\n"
        "2026-01-01T00:00:00+00:00 [INFO] case=exec-log-t event=intake_complete pid=1 input_path=/x\n"
    )
    events = build_events(case_dir)
    tss = [e.ts_utc for e in events]
    assert tss == sorted(tss)


# ---------------------------------------------------------------------------
# write_all — end-to-end artefact emission
# ---------------------------------------------------------------------------

def test_write_all_produces_three_artefacts(tmp_path, monkeypatch):
    case_dir = _mk_case(tmp_path, monkeypatch)
    ledger_insert(case_dir, Finding(
        case_id="exec-log-t", agent="malware_triage",
        claim="mimikatz strings in dump",
        confidence="high",
        evidence=[EvidenceItem(
            tool="el.dump_analysis", version="0.1.0",
            command="scan_dump(pid.1234.vad.dmp)",
            output_sha256="a" * 64,
            output_path="/tmp/pid.1234.vad.dmp")],
        hypotheses_supported=["H_CREDENTIAL_ACCESS"],
    ))
    res = write_all(case_dir)
    assert res["jsonl"].is_file()
    assert res["md"].is_file()
    assert res["traceability"].is_file()
    assert res["event_count"] >= 2     # at least tool_exec + finding

    # JSONL: one JSON per line, all parseable
    lines = res["jsonl"].read_text().strip().splitlines()
    assert lines
    for ln in lines:
        obj = json.loads(ln)
        assert "ts_utc" in obj
        assert "event" in obj
        assert "case_id" in obj

    # Markdown: headings + Finding citation present
    md = res["md"].read_text()
    assert "# Agent Execution Log" in md
    assert "tool_execution" in md or "tool `el.dump_analysis`" in md

    # Traceability matrix: finding_id + tool + sha256 columns present
    tm = res["traceability"].read_text()
    assert "| finding_id | agent |" in tm
    assert "el.dump_analysis" in tm
    assert "a" * 16 in tm               # truncated sha256 marker


def test_write_all_handles_empty_case(tmp_path, monkeypatch):
    """No findings, no audit log — emit empty-but-valid artefacts."""
    case_dir = _mk_case(tmp_path, monkeypatch, case_id="empty-t")
    res = write_all(case_dir)
    assert res["event_count"] == 0
    assert res["jsonl"].is_file()
    assert res["md"].is_file()
    assert res["traceability"].is_file()
    # Header present even with zero rows
    assert "# Agent Execution Log" in res["md"].read_text()
    assert "# Traceability Matrix" in res["traceability"].read_text()


def test_execution_log_linked_by_finding_id(tmp_path, monkeypatch):
    """Core Find Evil contract: every tool_execution in the output must
    carry a finding_id that matches a finding_emitted row — no orphan
    tool runs."""
    case_dir = _mk_case(tmp_path, monkeypatch)
    f1 = Finding(
        case_id="exec-log-t", agent="a1", claim="c1", confidence="high",
        evidence=[EvidenceItem(tool="t1", version="v", command="cmd",
                                output_sha256="0"*64,
                                output_path="/tmp/1")],
    )
    f2 = Finding(
        case_id="exec-log-t", agent="a2", claim="c2", confidence="medium",
        evidence=[
            EvidenceItem(tool="t2", version="v", command="cmd",
                          output_sha256="1"*64,
                          output_path="/tmp/2a"),
            EvidenceItem(tool="t3", version="v", command="cmd",
                          output_sha256="2"*64,
                          output_path="/tmp/2b"),
        ],
    )
    ledger_insert(case_dir, f1)
    ledger_insert(case_dir, f2)
    events = build_events(case_dir)
    finding_ids = {e.finding_id for e in events
                   if e.event_type == "finding_emitted"}
    tool_ids = {e.finding_id for e in events
                if e.event_type == "tool_execution"}
    # Every tool_execution finding_id must exist in finding_emitted
    assert tool_ids <= finding_ids
    # Exactly 3 tool_executions (1 from f1 + 2 from f2) and 2 findings
    assert sum(1 for e in events if e.event_type == "tool_execution") == 3
    assert sum(1 for e in events if e.event_type == "finding_emitted") == 2
