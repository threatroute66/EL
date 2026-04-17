"""Tests for `el report` and `el hunt` standalone CLI commands.

Both operate on an EXISTING case directory — they must not re-investigate
or modify the chain-of-custody state.
"""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from el.cli import app
from el.evidence import intake as intake_mod
from el.orchestrator.coordinator import Coordinator


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def _seed_case(tmp_path: Path) -> Path:
    src = tmp_path / "fake.bin"
    src.write_bytes(b"x")
    result = Coordinator().investigate(src, case_id="rerun-x")
    return result.case_dir


def test_report_command_rerenders_without_re_running_agents(isolated):
    cd = _seed_case(isolated)
    audit_before = (cd / "analysis" / "forensic_audit.log").read_text().count("\n")
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(cd)])
    assert result.exit_code == 0, result.output
    assert "report" in result.output
    audit_after = (cd / "analysis" / "forensic_audit.log").read_text().count("\n")
    assert audit_before == audit_after, "report cmd must not write to forensic_audit.log"


def test_hunt_command_runs_threat_hunter_against_existing_case(isolated):
    cd = _seed_case(isolated)
    iocs = json.loads((cd / "iocs.json").read_text())
    iocs.setdefault("domain", []).append("late-added.example.com")
    (cd / "iocs.json").write_text(json.dumps(iocs))

    runner = CliRunner()
    result = runner.invoke(app, ["hunt", str(cd)])
    assert result.exit_code == 0, result.output


def test_report_command_errors_on_non_case_dir(tmp_path):
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(tmp_path)])
    assert result.exit_code != 0
