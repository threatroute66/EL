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
