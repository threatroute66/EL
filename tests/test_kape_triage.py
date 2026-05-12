"""Triage + routing of a KAPE-Triage output directory.

KAPE preserves the native Windows path layout under a drive-letter root
(typically `C/`). EL's triage must recognise this as a distinct
`evidence_kind` (so report telemetry is accurate) and route it to the
same WindowsArtifactAgent that handles DiskForensicator-extracted dirs
— the agent's rglob finders are layout-agnostic.

Like test_windows_artifact_dir.py, we don't have real $MFT/hive bytes
that EZ Tools can parse in unit tests, so this verifies *routing* and
*classification*, not parser success."""
import pytest

from el.evidence import intake as intake_mod
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def test_kape_triage_dir_classifies_and_routes(isolated):
    art = isolated / "kape-out"
    cfg = art / "C" / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"NOT_A_REAL_HIVE")
    (cfg / "SOFTWARE").write_bytes(b"NOT_A_REAL_HIVE")
    (art / "C" / "Windows" / "Prefetch").mkdir()
    (art / "C" / "Windows" / "System32" / "winevt" / "Logs").mkdir(
        parents=True)
    (art / "C" / "$MFT").write_bytes(b"NOT_A_REAL_MFT")

    result = Coordinator().investigate(art, case_id="t-kape")
    assert result.investigator == "WindowsArtifactAgent"
    assert result.final_state == State.DONE

    # Verify triage tagged it as KAPE rather than the generic
    # windows-artifacts-dir — distinct classification matters for
    # report telemetry and downstream cross-case correlation.
    import sqlite3
    db = isolated / "cases" / "t-kape" / "findings.sqlite"
    with sqlite3.connect(db) as cx:
        claims = [r[0] for r in cx.execute(
            "SELECT claim FROM findings WHERE agent='triage'"
        ).fetchall()]
    assert any("KAPE triage collection" in c for c in claims), (
        f"expected a KAPE classification claim, got: {claims}"
    )


def test_disk_forensicator_layout_still_routes_via_windows_artifacts(isolated):
    """Regression: the DiskForensicator-extracted curated layout
    (`mft/`, `registry/`) must still classify as `windows-artifacts-dir`
    rather than getting swept into the new KAPE branch."""
    art = isolated / "extracted"
    (art / "mft").mkdir(parents=True)
    (art / "registry").mkdir()
    (art / "mft" / "$MFT").write_bytes(b"NOT_A_REAL_MFT")
    (art / "registry" / "SYSTEM").write_bytes(b"NOT_A_REAL_HIVE")
    (art / "registry" / "SOFTWARE").write_bytes(b"NOT_A_REAL_HIVE")

    result = Coordinator().investigate(art, case_id="t-extracted")
    assert result.investigator == "WindowsArtifactAgent"
    assert result.final_state == State.DONE

    import sqlite3
    db = isolated / "cases" / "t-extracted" / "findings.sqlite"
    with sqlite3.connect(db) as cx:
        claims = [r[0] for r in cx.execute(
            "SELECT claim FROM findings WHERE agent='triage'"
        ).fetchall()]
    assert any("extracted Windows artifacts collection" in c for c in claims)
    assert not any("KAPE triage collection" in c for c in claims)
