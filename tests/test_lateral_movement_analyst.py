"""PR-G: LateralMovementAnalyst — Hunt-Evil 7-technique detector tests.

Tests build synthetic EvtxECmd-shaped CSVs and assert that each detector
fires on the right EIDs + channels without accidentally firing on
benign event-log content.
"""
import csv
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.lateral_movement_analyst import LateralMovementAnalystAgent
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.skills import evtx_triage as evt


EVTX_COLUMNS = [
    "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
    "Provider", "Channel", "ProcessId", "ThreadId", "Computer",
    "ChunkNumber", "UserId", "MapDescription", "UserName", "RemoteHost",
    "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
    "PayloadData5", "PayloadData6", "ExecutableInfo", "HiddenRecord",
    "SourceFile", "Keywords", "ExtraDataOffset", "Payload",
]


def _make_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=EVTX_COLUMNS)
        w.writeheader()
        for i, r in enumerate(rows, 1):
            base = {c: "" for c in EVTX_COLUMNS}
            base.update({
                "RecordNumber": str(i),
                "EventRecordId": str(1000 + i),
                "Level": "Info",
            })
            base.update(r)
            w.writerow(base)


def _event(eid: int, channel: str, **payload) -> dict:
    row = {"EventId": str(eid), "Channel": channel,
           "Provider": payload.pop("Provider", "Microsoft-Windows"),
           "TimeCreated": payload.pop("TimeCreated",
                                       "2023-08-15 12:34:56.000"),
           "Computer": payload.pop("Computer", "VICTIM-PC"),
           "MapDescription": payload.pop("MapDescription", ""),
           "UserName": payload.pop("UserName", "SYSTEM")}
    for i, key in enumerate(("PayloadData1", "PayloadData2", "PayloadData3",
                              "PayloadData4", "PayloadData5", "PayloadData6"), 1):
        row[key] = payload.pop(f"p{i}", "")
    return row


# ---------------------------------------------------------------------------
# Skill: per-detector positive/negative
# ---------------------------------------------------------------------------

def test_psexec_detector_fires_on_psexesvc_7045(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    _make_csv(csv_path, [
        _event(7045, "System", Provider="Service Control Manager",
               p1="PSEXESVC", p2="%SystemRoot%\\PSEXESVC.exe",
               MapDescription="A service was installed in the system: PSEXESVC"),
        _event(7045, "System", Provider="Service Control Manager",
               p1="WUAUserv", p2="%SystemRoot%\\system32\\svchost.exe -k netsvcs"),
    ])
    hits = evt.run_all(csv_path)
    psexec = [h for h in hits if h.technique == "psexec"]
    assert psexec and psexec[0].event_count == 1


def test_psexec_detector_ignores_benign_service_installs(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    _make_csv(csv_path, [
        _event(7045, "System", p1="Windows Modules Installer"),
        _event(7045, "System", p1="Intel SGX"),
        _event(7045, "System", p1="VMware Tools"),
    ])
    hits = evt.run_all(csv_path)
    assert not any(h.technique == "psexec" for h in hits)
    # And service_install detector also skips these benign ones
    assert not any(h.technique == "service_install" for h in hits)


def test_scheduled_task_creation_detector(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    _make_csv(csv_path, [
        _event(4698, "Security", p1="TaskName: \\Microsoft\\Windows\\Defrag"),
        _event(106, "Microsoft-Windows-TaskScheduler/Operational",
               p1="TaskName: \\EvilTask"),
    ])
    hits = evt.run_all(csv_path)
    sched = [h for h in hits if h.technique == "scheduled_task"]
    assert sched and sched[0].event_count == 2


def test_wmi_persistence_5860_5861(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    _make_csv(csv_path, [
        _event(5860, "Microsoft-Windows-WMI-Activity/Operational",
               p1="Namespace = //./root/subscription; EventFilter"),
        _event(5861, "Microsoft-Windows-WMI-Activity/Operational",
               p1="Namespace = //./root/subscription; EventConsumer"),
    ])
    hits = evt.run_all(csv_path)
    wmi = [h for h in hits if h.technique == "wmi"
           and h.subtechnique == "event_consumer_registration"]
    assert wmi and wmi[0].event_count == 2


def test_wmi_5857_only_fires_on_user_writable_path(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    # Benign Windows system-owned provider — should NOT fire
    _make_csv(csv_path, [
        _event(5857, "Microsoft-Windows-WMI-Activity/Operational",
               p1="ProviderPath = C:\\Windows\\System32\\wbem\\cimwin32.dll"),
    ])
    hits = evt.run_all(csv_path)
    assert not any(h.technique == "wmi" for h in hits)
    # Now one from AppData — SHOULD fire
    _make_csv(csv_path, [
        _event(5857, "Microsoft-Windows-WMI-Activity/Operational",
               p1="ProviderPath = C:\\Users\\Alice\\AppData\\Local\\Temp\\evil.dll"),
    ])
    hits = evt.run_all(csv_path)
    wmi = [h for h in hits if h.technique == "wmi"
           and h.subtechnique == "provider_load_from_user_writable_path"]
    assert wmi


def test_powershell_remoting_inbound(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    _make_csv(csv_path, [
        _event(91, "Microsoft-Windows-WinRM/Operational",
               p1="User authenticated for WinRM connection"),
        _event(4104, "Microsoft-Windows-PowerShell/Operational",
               p1="ScriptBlockText = Invoke-Mimikatz"),
        _event(4104, "Microsoft-Windows-PowerShell/Operational",
               p1="ScriptBlockText = Get-Process"),
    ])
    hits = evt.run_all(csv_path)
    ps = [h for h in hits if h.technique == "ps_remoting"]
    assert ps and ps[0].event_count == 3


def test_rdp_destination_detection_via_1149_and_4624_type10(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    _make_csv(csv_path, [
        _event(1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
               p1="User: bob Domain: CORP Source Network Address: 192.0.2.50"),
        _event(4624, "Security",
               MapDescription="Successful logon, LogonType = 10 (RemoteInteractive)",
               p1="LogonType: 10", p2="SourceIP: 192.0.2.50"),
    ])
    hits = evt.run_all(csv_path)
    rdp = [h for h in hits if h.technique == "rdp"]
    assert rdp
    assert rdp[0].event_count == 2
    # Source IP extracted from 1149 payload
    assert rdp[0].source_ip == "192.0.2.50"


def test_log_clearing_always_surfaces(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    _make_csv(csv_path, [
        _event(1102, "Security",
               MapDescription="The audit log was cleared",
               UserName="evil-admin"),
    ])
    hits = evt.run_all(csv_path)
    assert any(h.technique == "anti_forensic" for h in hits)


def test_benign_event_log_produces_zero_hits(tmp_path):
    """A clean Windows host generates 1000s of 4624 Type 2/3/5, 4634,
    4648, 4672 events — none of our detectors should fire unless the
    specific lateral-movement EIDs are present."""
    csv_path = tmp_path / "evtx_parsed.csv"
    rows = []
    for _ in range(50):
        rows.append(_event(4624, "Security",
                            MapDescription="Local logon, LogonType = 2"))
        rows.append(_event(4634, "Security"))
    _make_csv(csv_path, rows)
    hits = evt.run_all(csv_path)
    assert hits == []


# ---------------------------------------------------------------------------
# Agent: confidence escalation + aggregate finding
# ---------------------------------------------------------------------------

def _ctx(tmp_path, monkeypatch, case_id="t-lma"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def test_agent_emits_insufficient_when_csv_missing(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, "t-nocsv")
    findings = LateralMovementAnalystAgent().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"


def test_agent_emits_high_confidence_on_multi_channel_chain(tmp_path, monkeypatch):
    """PsExec + RDP + log-clear = 3 techniques → aggregate high-confidence
    finding AND H_APT_ESPIONAGE lift."""
    ctx = _ctx(tmp_path, monkeypatch, "t-chain")
    evt_dir = ctx.case_dir / "analysis" / "windows_artifact" / "evtx"
    evt_dir.mkdir(parents=True)
    _make_csv(evt_dir / "evtx_parsed.csv", [
        _event(7045, "System", p1="PSEXESVC",
               MapDescription="PSEXESVC service installed"),
        _event(1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
               p1="Source Network Address: 10.1.2.3"),
        _event(4624, "Security",
               MapDescription="LogonType = 10"),
        _event(1102, "Security",
               MapDescription="The audit log was cleared"),
    ])

    findings = LateralMovementAnalystAgent().run(ctx)
    techniques = {f.evidence[0].extracted_facts.get("technique")
                  for f in findings if f.evidence}
    assert "psexec" in techniques
    assert "rdp" in techniques
    assert "anti_forensic" in techniques
    # Aggregate chain finding
    chain = [f for f in findings
             if "Multi-technique lateral-movement chain" in f.claim]
    assert chain and chain[0].confidence == "high"
    assert "H_APT_ESPIONAGE" in chain[0].hypotheses_supported


def test_agent_anti_forensic_always_high_confidence(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, "t-1102")
    evt_dir = ctx.case_dir / "analysis" / "windows_artifact" / "evtx"
    evt_dir.mkdir(parents=True)
    _make_csv(evt_dir / "evtx_parsed.csv", [
        _event(1102, "Security"),
    ])
    findings = LateralMovementAnalystAgent().run(ctx)
    af = [f for f in findings if "[anti_forensic" in f.claim]
    assert af and af[0].confidence == "high"
    assert "H_EID_1102" in af[0].hypotheses_supported


def test_agent_insufficient_on_empty_csv(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, "t-empty")
    evt_dir = ctx.case_dir / "analysis" / "windows_artifact" / "evtx"
    evt_dir.mkdir(parents=True)
    _make_csv(evt_dir / "evtx_parsed.csv", [])
    findings = LateralMovementAnalystAgent().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"
    assert "none of the 7 Hunt-Evil" in findings[0].claim
