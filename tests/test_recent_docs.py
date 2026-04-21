"""RecentDocs / OpenSave-MRU skill tests."""
from pathlib import Path

import pytest

from el.skills import recent_docs as rd


# ---------------------------------------------------------------------------
# UTF-16LE decoder
# ---------------------------------------------------------------------------

def test_decode_mru_value_strips_nul_terminator():
    # Filename + U+0000 NUL pair + trailing IDL bytes
    filename = "evil.docx"
    raw = filename.encode("utf-16-le") + b"\x00\x00" + b"\x42" * 20
    assert rd._decode_mru_value(raw) == filename


def test_decode_mru_value_handles_hex_string_from_regipy():
    filename = "report.pdf"
    raw = filename.encode("utf-16-le") + b"\x00\x00"
    assert rd._decode_mru_value(raw.hex()) == filename


def test_decode_mru_value_empty_returns_empty():
    assert rd._decode_mru_value(b"") == ""
    assert rd._decode_mru_value(b"\x00\x00") == ""


# ---------------------------------------------------------------------------
# Suspicious-path overlay
# ---------------------------------------------------------------------------

def test_is_suspicious_path_marker_set():
    for p in (
        r"C:\Users\alice\AppData\Local\Temp\dropper.doc",
        r"C:\Users\alice\Downloads\x.pdf",
        r"C:\ProgramData\Evil\doc.xlsx",
        r"C:\Users\Public\y.pdf",
    ):
        assert rd.is_suspicious_path(p), f"should flag {p}"


def test_is_suspicious_path_clean():
    for p in (
        r"C:\Users\alice\Documents\report.docx",
        r"C:\Users\alice\Desktop\budget.xlsx",
        r"",
    ):
        assert not rd.is_suspicious_path(p)


# ---------------------------------------------------------------------------
# Summary aggregation
# ---------------------------------------------------------------------------

def test_summarise_groups_by_extension_and_source():
    entries = [
        rd.RecentDocEntry("recentdocs", ".docx", r"C:\Users\alice\a.docx", 0),
        rd.RecentDocEntry("recentdocs", ".docx", r"C:\Users\alice\b.docx", 1),
        rd.RecentDocEntry("recentdocs", ".pdf", r"C:\Users\alice\c.pdf", 0),
        rd.RecentDocEntry("opensave", ".zip",
                           r"C:\Users\alice\AppData\Local\Temp\x.zip", 0,
                           last_write_utc="2024-02-01T10:00:00"),
    ]
    s = rd.summarise(entries)
    assert s.total_entries == 4
    assert s.per_extension == {".docx": 2, ".pdf": 1, ".zip": 1}
    assert s.per_source == {"recentdocs": 3, "opensave": 1}
    assert len(s.suspicious) == 1
    assert s.suspicious[0].extension == ".zip"


def test_summarise_suspicious_sorted_newest_first():
    entries = [
        rd.RecentDocEntry("recentdocs", ".exe",
                           r"C:\Users\a\AppData\Local\Temp\old.exe", 0,
                           last_write_utc="2023-01-01T10:00:00"),
        rd.RecentDocEntry("recentdocs", ".exe",
                           r"C:\Users\a\AppData\Local\Temp\new.exe", 0,
                           last_write_utc="2024-06-01T10:00:00"),
    ]
    s = rd.summarise(entries)
    assert s.suspicious[0].filename.endswith("new.exe")


# ---------------------------------------------------------------------------
# parse_recentdocs on missing file
# ---------------------------------------------------------------------------

def test_parse_missing_ntuser_returns_empty(tmp_path):
    assert rd.parse_recentdocs(tmp_path / "nope.DAT") == []


# ---------------------------------------------------------------------------
# Agent wiring — synthetic NTUSER.DAT via regipy write (can't easily
# synthesize one). Test the agent path on a case-dir without registry
# dir (insufficient path) and with a dir holding a file that isn't a
# real hive (also insufficient).
# ---------------------------------------------------------------------------

def test_agent_silent_when_no_registry_dir(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.windows_artifact import WindowsArtifactAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    input_dir = tmp_path / "artifacts"
    input_dir.mkdir()
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-rd-empty")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-rd-empty", case_dir=Path(m.case_dir),
                       input_path=input_dir, manifest=m.__dict__)
    assert WindowsArtifactAgent()._recent_docs(ctx, input_dir, tmp_path) == []


def test_agent_insufficient_when_ntuser_present_but_empty(tmp_path, monkeypatch):
    """A zero-byte NTUSER placeholder triggers regipy's failure path
    → parse returns []; agent must emit insufficient rather than a
    summary claim of 'N entries'."""
    from el.agents.base import AgentContext
    from el.agents.windows_artifact import WindowsArtifactAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    input_dir = tmp_path / "artifacts"
    reg_dir = input_dir / "registry"
    reg_dir.mkdir(parents=True)
    (reg_dir / "NTUSER-alice.DAT").write_bytes(b"\x00" * 4096)
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-rd-bad")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-rd-bad", case_dir=Path(m.case_dir),
                       input_path=input_dir, manifest=m.__dict__)
    findings = WindowsArtifactAgent()._recent_docs(ctx, input_dir, tmp_path)
    assert findings
    assert findings[0].confidence == "insufficient"
    assert "no MRU entries recovered" in findings[0].claim


# ---------------------------------------------------------------------------
# Real-hive sanity (skipped unless the SRL case is present)
# ---------------------------------------------------------------------------

_SRL_NTUSER = next(
    (p for p in [
        Path("/opt/EL/cases/srl-wkstn-01-disk-r4/exports/windows-artifacts/"
             "registry/NTUSER-mhill.DAT"),
        Path("/opt/EL/cases/srl-dc-disk-r3/exports/windows-artifacts/"
             "registry/NTUSER-Administrator.DAT"),
    ] if p.is_file()),
    None,
)


@pytest.mark.skipif(_SRL_NTUSER is None, reason="SRL-2018 NTUSER hive not present")
def test_parse_real_ntuser():
    entries = rd.parse_recentdocs(_SRL_NTUSER)
    # Either empty (user didn't use Explorer) or non-empty; both OK.
    # Invariant: every entry has a non-empty filename + valid position.
    for e in entries:
        assert e.filename
        assert e.source in ("recentdocs", "opensave")
