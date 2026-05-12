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


def test_kape_per_user_artifacts_stage_into_curated_layout(tmp_path):
    """KAPE captures per-user artifacts at native paths under
    `Users/<user>/`. The staging helper must enumerate every user and
    map their artifacts into the curated layout the WindowsArtifactAgent
    parsers already understand — so multi-user cases don't silently
    drop everyone after the first user the rglob hit."""
    from el.agents.windows_artifact import _stage_kape_layout

    kape = tmp_path / "kape-out"
    c = kape / "C"
    c.mkdir(parents=True)
    (c / "$MFT").write_bytes(b"NOT_A_REAL_MFT")

    cfg = c / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    for hive in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY"):
        (cfg / hive).write_bytes(b"NOT_A_REAL_HIVE")
    (c / "Windows" / "appcompat" / "Programs").mkdir(parents=True)
    (c / "Windows" / "appcompat" / "Programs" / "Amcache.hve").write_bytes(b"x")
    (c / "Windows" / "Prefetch").mkdir()
    (c / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)

    # Three real users + one default-template that we still capture
    # (recent_docs handles empty hives gracefully).
    for user in ("alice", "bob", "carol"):
        u = c / "Users" / user
        (u / "AppData" / "Roaming" / "Microsoft" / "Windows"
         / "Recent" / "AutomaticDestinations").mkdir(parents=True)
        (u / "AppData" / "Roaming" / "Microsoft" / "Windows"
         / "Recent" / "CustomDestinations").mkdir(parents=True)
        (u / "AppData" / "Local" / "Microsoft" / "Windows"
         / "Clipboard").mkdir(parents=True)
        (u / "AppData" / "Local" / "Microsoft" / "Windows"
         / "Temporary Internet Files" / "Content.IE5").mkdir(parents=True)
        (u / "NTUSER.DAT").write_bytes(b"NOT_A_REAL_HIVE")
        (u / "AppData" / "Local" / "Microsoft" / "Windows"
         / "UsrClass.dat").write_bytes(b"NOT_A_REAL_HIVE")

    staged = tmp_path / "staged"
    counts = _stage_kape_layout(kape, staged)

    assert counts["user_ntusers"] == 3
    assert counts["user_usrclass"] == 3
    assert counts["lnk_users"] == 3
    assert counts["jumplists_users"] == 3
    assert counts["ie_cache_users"] == 3
    assert counts["clipboard_users"] == 3
    assert counts["registry_hives"] == 4
    assert counts["mft"] == 1

    # Verify the curated-layout shape that downstream parsers expect.
    assert (staged / "mft" / "$MFT").is_symlink()
    assert (staged / "registry" / "SYSTEM").is_symlink()
    assert (staged / "registry" / "NTUSER-alice.DAT").is_symlink()
    assert (staged / "registry" / "NTUSER-bob.DAT").is_symlink()
    assert (staged / "registry" / "NTUSER-carol.DAT").is_symlink()
    assert (staged / "registry" / "UsrClass-alice.DAT").is_symlink()
    assert (staged / "lnk" / "alice").is_symlink()
    assert (staged / "jumplists" / "alice-automatic").is_symlink()
    assert (staged / "jumplists" / "alice-custom").is_symlink()
    assert (staged / "ie_cache" / "alice-content.ie5").is_symlink()
    assert (staged / "uwp-clipboard" / "alice" / "Clipboard").is_symlink()
    # Confirm symlinks resolve to the original KAPE evidence (read-only,
    # no copies).
    assert (staged / "registry" / "NTUSER-alice.DAT").resolve() == (
        c / "Users" / "alice" / "NTUSER.DAT").resolve()


def test_kape_staging_no_drive_returns_empty_counts(tmp_path):
    """A directory that isn't KAPE-shaped must produce zero counts and
    not create the staged tree (the run() path also guards on this,
    but the helper should be safe to call standalone)."""
    from el.agents.windows_artifact import _stage_kape_layout

    not_kape = tmp_path / "random"
    not_kape.mkdir()
    counts = _stage_kape_layout(not_kape, tmp_path / "staged")
    assert all(v == 0 for v in counts.values())


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
