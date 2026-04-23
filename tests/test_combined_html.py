"""Tests for the combined multi-host HTML dashboard."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from el.reporting.combined_html import render_combined_html


def _make_case(root: Path, case_id: str, leading: str, score: int,
                claims: list[tuple[str, str, str]]) -> Path:
    case_dir = root / case_id
    (case_dir / "reports").mkdir(parents=True)
    (case_dir / "manifest.json").write_text(json.dumps({
        "case_id": case_id, "input_path": f"/evidence/{case_id}",
        "input_sha256": "0" * 64,
    }))
    (case_dir / "ach_matrix.json").write_text(json.dumps({
        "ranking": [
            {"hyp_id": leading, "name": "X", "score": score,
             "support_count": 1, "refute_count": 0},
            {"hyp_id": "H_BENIGN_NO_INCIDENT", "name": "Benign",
             "score": 0, "support_count": 0, "refute_count": 0},
        ],
        "matrix": [],
    }))
    (case_dir / "iocs.json").write_text(json.dumps({}))
    conn = sqlite3.connect(case_dir / "findings.sqlite")
    conn.execute("""
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY, case_id TEXT NOT NULL,
            agent TEXT NOT NULL, claim TEXT NOT NULL,
            confidence TEXT NOT NULL, created_utc TEXT NOT NULL,
            payload_json TEXT NOT NULL)
    """)
    for i, (agent, conf, claim) in enumerate(claims):
        conn.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?)",
            (f"{case_id}-f{i}", case_id, agent, claim, conf,
              f"2026-04-23T00:00:0{i}Z",
              json.dumps({"hypotheses_supported": [leading],
                          "evidence": []})))
    conn.commit()
    conn.close()
    (case_dir / "reports" / "report.md").write_text("# per-case\n")
    (case_dir / "reports" / "narrative.md").write_text(
        f"**Lead hypothesis:** {leading}.\n\n"
        f"Per-case synthesis for {case_id}.\n")
    return case_dir


def test_render_combined_html_produces_complete_document(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    a = _make_case(tmp_path, "ent-host-a-memory", "H_APT_ESPIONAGE", 46, [
        ("memory_forensicator", "high",
         "malfind flagged 100 regions across lsass.exe"),
        ("memory_forensicator", "high",
         "Hidden processes detected — 16 PIDs in psscan"),
    ])
    b = _make_case(tmp_path, "ent-host-b-disk", "H_APT_ESPIONAGE", 32, [
        ("lateral_movement_analyst", "high",
         "Lateral movement [psexec/service_install] — PSEXESVC installed"),
        ("credential_analyst", "high",
         "Credential access [kerberoasting/tgs_rc4_downgrade] — 223 × 4769 RC4"),
    ])
    out = tmp_path / "combined.html"
    written = render_combined_html([a, b], out, name="ent")
    assert written == out
    doc = out.read_text()

    # Document structure
    assert "<!doctype html>" in doc
    assert "EL Combined Report" in doc
    assert "ent-host-a-memory" in doc and "ent-host-b-disk" in doc
    # All six main sections present
    for anchor in ("#narrative", "#hosts", "#ach", "#signals",
                    "#timeline", "#graph", "#attack", "#iocs"):
        assert anchor in doc
    # Joint ACH matrix actually renders scores for both cases
    assert "H_APT_ESPIONAGE" in doc
    # Signal matrix lights up both hosts
    assert "malfind regions" in doc
    assert "psexec install" in doc
    # Timeline SVG + JS both present
    assert "timeline-svg" in doc
    assert "renderTimeline" in doc
    # Graph SVG + JS both present
    assert "graph-svg" in doc
    assert "renderGraph" in doc
    # Per-case narrative blocks appear
    assert "Per-case synthesis for ent-host-a-memory" in doc


def test_narrative_intro_mentions_dominant_hypothesis(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    a = _make_case(tmp_path, "c1", "H_APT_ESPIONAGE", 46, [])
    b = _make_case(tmp_path, "c2", "H_APT_ESPIONAGE", 32, [])
    c = _make_case(tmp_path, "c3", "H_INSIDER_DATA_EXFIL", 16, [])
    out = tmp_path / "c.html"
    render_combined_html([a, b, c], out, name="test")
    doc = out.read_text()
    # Dominant (2/3 cases) = H_APT_ESPIONAGE; intro should cite it
    assert "H_APT_ESPIONAGE" in doc
    assert "lead in 2 of 3 cases" in doc


def test_render_without_narrative_md_still_works(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    a = _make_case(tmp_path, "x", "H_BENIGN_NO_INCIDENT", 2, [])
    # Remove the narrative file to exercise the fallback path
    (a / "reports" / "narrative.md").unlink()
    out = tmp_path / "x.html"
    render_combined_html([a], out, name="solo")
    doc = out.read_text()
    assert "No narrative.md was" in doc
    assert "el report /opt/EL/cases/x" in doc
