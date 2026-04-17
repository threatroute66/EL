import json
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State
from el.skills import cloudtrail


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    yield tmp_path


def _make_ct(path: Path) -> None:
    records = {"Records": [
        {"eventTime": "2026-04-17T10:00:00Z", "eventName": "ConsoleLogin",
         "responseElements": {"ConsoleLogin": "Success"},
         "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
         "sourceIPAddress": "203.0.113.10", "awsRegion": "us-east-1"},
        {"eventTime": "2026-04-17T10:01:00Z", "eventName": "ConsoleLogin",
         "responseElements": {"ConsoleLogin": "Failure"},
         "userIdentity": {"arn": "arn:aws:iam::123:user/bob"},
         "sourceIPAddress": "198.51.100.20", "awsRegion": "us-east-1",
         "errorMessage": "Failed authentication"},
        {"eventTime": "2026-04-17T10:02:00Z", "eventName": "CreateAccessKey",
         "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
         "sourceIPAddress": "203.0.113.10", "awsRegion": "us-east-1"},
        {"eventTime": "2026-04-17T10:03:00Z", "eventName": "GetCallerIdentity",
         "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
         "sourceIPAddress": "203.0.113.10", "awsRegion": "us-east-1"},
    ]}
    path.write_text(json.dumps(records))


def test_parse_extracts_high_value_events(tmp_path):
    p = tmp_path / "ct.json"
    _make_ct(p)
    s = cloudtrail.parse(p, tmp_path / "out")
    assert s.record_count == 4
    assert s.failed_console_logins == 1
    names = {e["name"] for e in s.high_value_events}
    assert "CreateAccessKey" in names
    assert "ConsoleLogin" in names


def test_coordinator_routes_cloudtrail_and_emits_attack(isolated, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    p = isolated / "ct.json"
    _make_ct(p)
    result = Coordinator().investigate(p, case_id="t-ct")
    assert result.investigator == "CloudForensicatorAgent"
    assert result.final_state == State.DONE
