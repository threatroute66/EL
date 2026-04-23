"""Tests for the combined multi-host report."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from el.reporting.combined import load_case, render_combined


def _make_case(root: Path, case_id: str, leading: str, score: int,
                claims: list[tuple[str, str, str]]) -> Path:
    """Build a minimal case dir with manifest, ach_matrix, iocs, findings."""
    case_dir = root / case_id
    (case_dir / "reports").mkdir(parents=True)
    (case_dir / "manifest.json").write_text(json.dumps({
        "case_id": case_id, "input_path": f"/evidence/{case_id}",
        "input_sha256": "0" * 64,
    }))
    (case_dir / "ach_matrix.json").write_text(json.dumps({
        "ranking": [
            {"hyp_id": leading, "name": leading.replace("H_", ""),
             "score": score, "support_count": 1, "refute_count": 0},
        ],
        "matrix": [],
    }))
    (case_dir / "iocs.json").write_text(json.dumps({"ipv4": [], "domain": []}))
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
                          "evidence": []})),
        )
    conn.commit()
    conn.close()
    (case_dir / "reports" / "report.md").write_text(
        f"# per-case report for {case_id}\n")
    return case_dir


def test_render_combined_stitches_two_hosts(tmp_path, monkeypatch):
    # Isolate knowledge DB so the overlap section is inert
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))

    a = _make_case(tmp_path, "ent-host-a-memory", "H_APT_ESPIONAGE", 46, [
        ("memory_forensicator", "high",
         "malfind flagged 100 regions across lsass.exe, svchost.exe"),
        ("memory_forensicator", "high",
         "Hidden processes detected — 16 PIDs in psscan but absent from pslist"),
    ])
    b = _make_case(tmp_path, "ent-host-b-disk", "H_APT_ESPIONAGE", 32, [
        ("lateral_movement_analyst", "high",
         "Lateral movement [psexec/service_install] — PSEXESVC installed"),
        ("credential_analyst", "high",
         "Credential access [kerberoasting/tgs_rc4_downgrade] — 223 × 4769 RC4"),
    ])

    out = tmp_path / "combined" / "report.md"
    written = render_combined([a, b], out, name="ent")
    assert written == out
    text = out.read_text()

    assert "# EL Combined Case Report — ent" in text
    assert "ent-host-a-memory" in text and "ent-host-b-disk" in text
    assert "H_APT_ESPIONAGE" in text
    # The signal-matrix should light up malfind on a, psexec + kerberoast on b
    assert "malfind regions" in text
    assert "psexec install" in text
    assert "kerberoasting" in text.lower()


def test_load_case_missing_pieces_fails_soft(tmp_path):
    """A case with only manifest.json should still hydrate without crashing."""
    cd = tmp_path / "spartan"
    cd.mkdir()
    (cd / "manifest.json").write_text(json.dumps({"case_id": "spartan"}))
    slice_ = load_case(cd)
    assert slice_.case_id == "spartan"
    assert slice_.ach_ranking == []
    assert slice_.findings == []
    assert slice_.leading == (None, 0)


def test_host_label_strips_prefix_and_suffix(tmp_path):
    """case_id 'srl2015-nromanoff-memory' → host_label 'nromanoff / memory'."""
    cd = _make_case(tmp_path, "srl2015-nromanoff-memory", "H_X", 1, [])
    s = load_case(cd)
    assert s.host_label == "nromanoff / memory"


def test_render_with_single_case_still_works(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    a = _make_case(tmp_path, "solo-case", "H_BENIGN_NO_INCIDENT", 0, [
        ("triage", "high", "Input identified as pcap"),
    ])
    out = tmp_path / "out.md"
    render_combined([a], out, name="solo")
    text = out.read_text()
    assert "Cases stitched: **1**" in text
