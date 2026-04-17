"""Triage + routing of an extracted Windows artifacts directory.

We don't have real $MFT bytes that MFTECmd can parse in unit tests, so this
test verifies the *routing* and the agent's failure-handling contract:
when files match expected names but aren't real artifacts, the agent must
emit insufficient findings (not crash, not fabricate)."""
import pytest

from el.evidence import intake as intake_mod
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def test_directory_with_artifact_filenames_routes_to_windows_artifact_agent(isolated):
    art = isolated / "extracted"
    (art / "mft").mkdir(parents=True)
    (art / "registry").mkdir()
    (art / "mft" / "$MFT").write_bytes(b"NOT_A_REAL_MFT")
    (art / "registry" / "SYSTEM").write_bytes(b"NOT_A_REAL_HIVE")
    (art / "registry" / "SOFTWARE").write_bytes(b"NOT_A_REAL_HIVE")
    (art / "registry" / "Amcache.hve").write_bytes(b"NOT_A_REAL_HIVE")

    result = Coordinator().investigate(art, case_id="t-art")
    assert result.investigator == "WindowsArtifactAgent"
    assert result.final_state == State.DONE
