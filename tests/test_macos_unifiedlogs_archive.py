"""Tests for the Unified Logs logarchive-builder and the MacOSForensicator
short-circuit fix.

Two regressions are locked in here:

  1. ``build_logarchive`` must materialise REAL directories (never symlinks)
     containing both the tracev3 chunk store (diagnostics subdirs) and the
     format-string tables (uuidtext dsc + hex dirs) at the archive root —
     because ``unifiedlog_iterator --mode log-archive`` skips symlinked dirs
     and leaves messages unresolved without the uuidtext tables.

  2. ``MacOSForensicatorAgent`` must run the Unified Logs deep-dive even when
     the malicious-pattern suite returns no hits (a benign-but-rich Mac still
     has a parseable log store). It used to early-return on no hits.
"""
from pathlib import Path

from el.skills import macos_unifiedlogs as mul


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_macos_root(tmp_path: Path) -> Path:
    """Synthesize a minimal mounted-macOS-filesystem skeleton with both the
    diagnostics store and the uuidtext string tables in their canonical
    sibling locations."""
    root = tmp_path / "fsroot"
    diag = root / "private" / "var" / "db" / "diagnostics"
    uuid = root / "private" / "var" / "db" / "uuidtext"
    (diag / "Persist").mkdir(parents=True)
    (diag / "Special").mkdir(parents=True)
    (diag / "timesync").mkdir(parents=True)
    (uuid / "dsc").mkdir(parents=True)
    (uuid / "0A").mkdir(parents=True)

    (diag / "Persist" / "0000000000000001.tracev3").write_bytes(b"persist-data")
    (diag / "Special" / "0000000000000002.tracev3").write_bytes(b"special-data")
    (diag / "timesync" / "0000000000000000.timesync").write_bytes(b"ts")
    (uuid / "dsc" / "ABCDEF0123456789").write_bytes(b"shared-strings")
    (uuid / "0A" / "1122334455667788").write_bytes(b"uuid-strings")
    return root


# ---------------------------------------------------------------------------
# build_logarchive
# ---------------------------------------------------------------------------

def test_build_logarchive_materialises_real_dirs(tmp_path):
    root = _make_macos_root(tmp_path)
    dest = tmp_path / "archive"

    out = mul.build_logarchive(root, dest)
    assert out == dest

    # diagnostics subdirs present as REAL dirs (not symlinks — the parser
    # skips symlinked dirs and would yield zero events).
    for sub in ("Persist", "Special", "timesync"):
        d = dest / sub
        assert d.is_dir() and not d.is_symlink(), sub

    # uuidtext children land at the archive ROOT alongside Persist/.
    assert (dest / "dsc").is_dir() and not (dest / "dsc").is_symlink()
    assert (dest / "0A").is_dir() and not (dest / "0A").is_symlink()

    # leaf files materialised with content preserved.
    assert (dest / "Persist" / "0000000000000001.tracev3").read_bytes() \
        == b"persist-data"
    assert (dest / "dsc" / "ABCDEF0123456789").read_bytes() == b"shared-strings"
    assert (dest / "0A" / "1122334455667788").read_bytes() == b"uuid-strings"


def test_build_logarchive_none_without_uuidtext(tmp_path):
    """No format-string table → assembling buys nothing over parsing the
    diagnostics dir directly, so the builder declines (returns None)."""
    root = tmp_path / "fsroot"
    diag = root / "private" / "var" / "db" / "diagnostics" / "Persist"
    diag.mkdir(parents=True)
    (diag / "x.tracev3").write_bytes(b"d")
    assert mul.build_logarchive(root, tmp_path / "arch") is None


def test_build_logarchive_none_without_diagnostics(tmp_path):
    root = tmp_path / "fsroot"
    uuid = root / "private" / "var" / "db" / "uuidtext" / "dsc"
    uuid.mkdir(parents=True)
    (uuid / "x").write_bytes(b"s")
    assert mul.build_logarchive(root, tmp_path / "arch") is None


def test_build_logarchive_none_without_chunk_store(tmp_path):
    """diagnostics/ exists but has no Persist/Special/HighVolume chunk store
    (only timesync) → nothing parseable, return None."""
    root = tmp_path / "fsroot"
    diag = root / "private" / "var" / "db" / "diagnostics" / "timesync"
    uuid = root / "private" / "var" / "db" / "uuidtext" / "dsc"
    diag.mkdir(parents=True)
    uuid.mkdir(parents=True)
    (diag / "0.timesync").write_bytes(b"t")
    (uuid / "x").write_bytes(b"s")
    assert mul.build_logarchive(root, tmp_path / "arch") is None


def test_build_logarchive_idempotent(tmp_path):
    root = _make_macos_root(tmp_path)
    dest = tmp_path / "archive"
    assert mul.build_logarchive(root, dest) == dest
    # second pass must not raise and must leave content intact.
    assert mul.build_logarchive(root, dest) == dest
    assert (dest / "Persist" / "0000000000000001.tracev3").read_bytes() \
        == b"persist-data"


def test_build_logarchive_force_copy(tmp_path):
    root = _make_macos_root(tmp_path)
    dest = tmp_path / "archive"
    out = mul.build_logarchive(root, dest, force_copy=True)
    assert out == dest
    assert (dest / "Special" / "0000000000000002.tracev3").read_bytes() \
        == b"special-data"


def test_build_logarchive_accepts_var_db_layout(tmp_path):
    """Some extractions drop the tree at var/db/... (no private/ prefix)."""
    root = tmp_path / "fsroot"
    diag = root / "var" / "db" / "diagnostics"
    uuid = root / "var" / "db" / "uuidtext"
    (diag / "Persist").mkdir(parents=True)
    (uuid / "dsc").mkdir(parents=True)
    (diag / "Persist" / "a.tracev3").write_bytes(b"p")
    (uuid / "dsc" / "h").write_bytes(b"s")
    dest = tmp_path / "arch"
    assert mul.build_logarchive(root, dest) == dest
    assert (dest / "Persist" / "a.tracev3").is_file()
    assert (dest / "dsc" / "h").is_file()


# ---------------------------------------------------------------------------
# Agent short-circuit fix: Unified Logs run even with no malicious hits
# ---------------------------------------------------------------------------

def test_agent_runs_unified_logs_when_no_malicious_hits(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents import macos_forensicator as mf
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.schemas.finding import Finding

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-mac-uld")
    with open_ledger(m.case_dir):
        pass

    exports = Path(m.case_dir) / "exports" / "macos-artifacts"
    exports.mkdir(parents=True)
    (exports / "placeholder").write_text("nothing malicious here")

    # No malicious-pattern hits.
    monkeypatch.setattr(mf.mt, "run_all", lambda _p: [])

    # Sentinel so we can prove the deep-dive was reached despite zero hits.
    sentinel = Finding(case_id="t-mac-uld", agent="macos_forensicator",
                       confidence="insufficient",
                       claim="UNIFIED-LOGS-REACHED")
    monkeypatch.setattr(
        mf.MacOSForensicatorAgent, "_run_unified_logs",
        lambda self, ctx, ex: [sentinel],
    )

    ctx = AgentContext(case_id="t-mac-uld", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"macos_artifacts_dir": str(exports)})
    findings = mf.MacOSForensicatorAgent().run(ctx)

    claims = [f.claim for f in findings]
    # The "no malicious-pattern hits" finding is still emitted ...
    assert any("no malicious-pattern" in c for c in claims)
    # ... AND the Unified Logs deep-dive ran instead of being short-circuited.
    assert "UNIFIED-LOGS-REACHED" in claims
