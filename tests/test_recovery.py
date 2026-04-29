"""Phase 6 tests for the RecoveryAgent + recommendation update.

Real carving is out of scope for the unit-test budget (tsk_recover
on a real image is minutes; bulk_extractor longer). We mock the
two skill entry points and exercise the agent's gating + finding-
emission contract:

  * No anti-forensic triggers → agent is a silent no-op (returns []).
  * Triggers + clean recovery → low-confidence findings per partition.
  * Triggers + a recovered file matching a wiped-binary name →
    medium-confidence "corroborates anti-forensic activity" finding.
  * Recommendation rule flips its wording when RecoveryAgent has
    already produced findings.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from el.agents.base import AgentContext
from el.agents.recovery import (
    RecoveryAgent, _find_recovered_basenames, _triggers_present,
)
from el.evidence.ledger import insert as ledger_insert, list_findings
from el.schemas.finding import EvidenceItem, Finding


def _ev() -> EvidenceItem:
    return EvidenceItem(
        tool="x", version="1", command="y", output_sha256="0" * 64,
        output_path="/tmp/z",
    )


@pytest.fixture
def case(tmp_path):
    """Bare-bones case dir with manifest + ledger schema initialised."""
    cd = tmp_path / "cases" / "rec-test"
    for sub in ("analysis", "exports", "reports", "raw"):
        (cd / sub).mkdir(parents=True, exist_ok=True)
    # Touch a fake raw image; agent's input_path points here for raw mode.
    raw = tmp_path / "image.raw"
    raw.write_bytes(b"\x00" * 1024)
    return cd, raw


def _ctx(case_dir: Path, raw: Path,
          partitions: list[dict] | None = None) -> AgentContext:
    return AgentContext(
        case_id="rec-test", case_dir=case_dir,
        input_path=raw, manifest={},
        shared={"partitions": partitions or [],
                 "raw_input_path": str(raw)},
    )


def _trigger_finding(claim: str) -> Finding:
    return Finding(
        case_id="rec-test", agent="disk_forensicator",
        confidence="high", claim=claim, evidence=[_ev()],
    )


# ---------------------------------------------------------------------------
# Trigger detection helper
# ---------------------------------------------------------------------------

def test_triggers_present_picks_canonical_patterns():
    fs = [
        _trigger_finding("Disk anomaly [MACB_TIMESTOMP_SKEW] in slot002"),
        _trigger_finding("Disk anomaly [SYSTEM_BINARY_ZERO_SIZE] ..."),
        _trigger_finding("Lateral movement [security_log_cleared] EID 1102"),
    ]
    assert len(_triggers_present(fs)) == 3


def test_triggers_present_ignores_non_disk_findings():
    fs = [
        Finding(case_id="c", agent="ios_forensicator",
                claim="MACB_TIMESTOMP_SKEW (mention)",
                confidence="high", evidence=[_ev()]),
    ]
    assert _triggers_present(fs) == []


def test_triggers_present_ignores_insufficient():
    fs = [
        Finding(case_id="c", agent="disk_forensicator",
                claim="MACB_TIMESTOMP_SKEW noted but unparsed",
                confidence="insufficient"),
    ]
    assert _triggers_present(fs) == []


# ---------------------------------------------------------------------------
# Agent gating
# ---------------------------------------------------------------------------

def test_no_triggers_yields_silent_noop(case):
    """Clean cases must not produce recovery findings — the agent
    runs on every disk case but is a no-op without anti-forensic
    signals."""
    cd, raw = case
    out = RecoveryAgent().run(_ctx(cd, raw, partitions=[
        {"slot": "0", "start_sector": 2048,
         "description": "NTFS / exFAT (0x07)"},
    ]))
    assert out == []


def test_triggers_with_no_partitions_yields_noop(case, monkeypatch):
    """Agent triggers fire but partitions list is empty → no per-partition
    work to do; only bulk_extractor runs (mocked here to fail-fast and
    exit cleanly)."""
    cd, raw = case
    ledger_insert(cd, _trigger_finding(
        "Disk anomaly [MACB_TIMESTOMP_SKEW] in slot002"))
    # Mock bulk_extractor to error (clean case); agent should produce
    # an insufficient finding, not crash.
    from el.skills import bulk_extractor as be

    def _fail(*a, **kw):
        raise be.BulkExtractorError("test stub: simulated failure")
    monkeypatch.setattr(be, "scan", _fail)

    out = RecoveryAgent().run(_ctx(cd, raw, partitions=[]))
    # Should record the bulk_extractor failure as insufficient.
    assert any(f.agent == "recovery" and f.confidence == "insufficient"
               and "bulk_extractor failed" in (f.claim or "")
               for f in out)


# ---------------------------------------------------------------------------
# Successful recovery path with mocks
# ---------------------------------------------------------------------------

def test_successful_recovery_emits_low_confidence_findings(case, monkeypatch):
    cd, raw = case
    ledger_insert(cd, _trigger_finding(
        "Disk anomaly [MACB_TIMESTOMP_SKEW] in slot002"))

    # Stub tsk_recover: write 3 fake recovered files into the target
    # directory and return a TskRun-like object with as_evidence().
    from el.skills import sleuthkit as sk

    def _fake_tsk_recover(image, out_subdir, mode="alloc",
                           offset=None, timeout=7200):
        out_subdir.mkdir(parents=True, exist_ok=True)
        for name in ("file_a.txt", "file_b.dat", "comres.dll"):
            (out_subdir / name).write_text(name)
        return SimpleNamespace(
            tool="tsk_recover", image=image, rc=0,
            stdout_path=cd / "analysis" / "tsk_stub.log",
            stderr_path=cd / "analysis" / "tsk_stub.err",
            command=["tsk_recover", "-e", str(image), str(out_subdir)],
            as_evidence=lambda facts=None: EvidenceItem(
                tool="sleuthkit/tsk_recover", version="4.x",
                command="tsk_recover -e ...", output_sha256="0" * 64,
                output_path=str(out_subdir),
                extracted_facts=facts or {},
            ),
        )
    # Touch a fake stdout/stderr file so as_evidence's stub doesn't trip.
    (cd / "analysis").mkdir(parents=True, exist_ok=True)
    (cd / "analysis" / "tsk_stub.log").write_text("")
    (cd / "analysis" / "tsk_stub.err").write_text("")
    monkeypatch.setattr(sk, "tsk_recover", _fake_tsk_recover)

    # Stub bulk_extractor: return a BulkRun-like object with one feature file.
    from el.skills import bulk_extractor as be
    fake_features_dir = cd / "exports" / "recovery" / "bulk_extractor"

    def _fake_be_scan(target, out_dir, **kw):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "email.txt").write_text(
            "# bulk_extractor email\nalice@example.com\nbob@example.org\n")
        return SimpleNamespace(
            target=target, out_dir=out_dir, rc=0,
            feature_files=[out_dir / "email.txt"],
            command=["bulk_extractor", "-o", str(out_dir), str(target)],
            features=lambda: {"email": 2},
            as_evidence=lambda facts=None: EvidenceItem(
                tool="bulk_extractor", version="1.6.1",
                command="bulk_extractor -o ...", output_sha256="0" * 64,
                output_path=str(out_dir), extracted_facts=facts or {},
            ),
        )
    monkeypatch.setattr(be, "scan", _fake_be_scan)

    out = RecoveryAgent().run(_ctx(cd, raw, partitions=[
        {"slot": "0", "start_sector": 2048,
         "description": "NTFS / exFAT (0x07)"},
    ]))

    # Per-partition tsk_recover finding (low confidence — recovery)
    assert any(
        f.agent == "recovery" and f.confidence == "low"
        and "Recovered 3 file(s)" in (f.claim or "")
        for f in out
    ), [f.claim for f in out]
    # bulk_extractor finding (low confidence)
    assert any(
        f.agent == "recovery" and f.confidence == "low"
        and "bulk_extractor surfaced" in (f.claim or "")
        for f in out
    )


def test_zeroed_basenames_case_insensitive_path():
    """XP-era Windows images (M57-Jean) carry paths like
    /WINDOWS/system32/foo.dll — different casing from modern
    /Windows/System32/. The basename extractor must accept both,
    or the corroboration finding silently fails to fire on real
    legacy cases. This test reproduces the v1 bug."""
    from el.agents.recovery import _zeroed_or_wiped_basenames
    triggers = [
        Finding(case_id="c", agent="disk_forensicator", confidence="high",
                claim=(
                    "Disk anomaly [SYSTEM_BINARY_ZERO_SIZE] in slot000:000-off63: "
                    "Windows system binary / DLL / driver with size=0. 15 match(es). "
                    "Samples: /WINDOWS/system32/auditusr.exe (deleted); "
                    "/WINDOWS/system32/pdh.dll (deleted); "
                    "/WINDOWS/system32/ciadmin.dll (deleted)"),
                evidence=[_ev()]),
    ]
    names = _zeroed_or_wiped_basenames(triggers)
    assert "auditusr.exe" in names
    assert "pdh.dll" in names
    assert "ciadmin.dll" in names


def test_find_recovered_basenames_locates_targets_in_deep_tree(tmp_path):
    """Targeted scan must find specific filenames even when the
    recovery tree contains many unrelated files (regression check
    against the v1 walk-everything-cap-at-5000 bug that hid M57's
    wiped binaries because they sat past the cap in /WINDOWS/system32/)."""
    root = tmp_path / "recovery"
    # Plant 50 unrelated files under various subdirs so the walk
    # naturally has to descend before reaching the targets.
    for sub in ("a", "b", "c"):
        d = root / sub / "deep" / "tree"
        d.mkdir(parents=True)
        for i in range(15):
            (d / f"file_{i}.txt").write_text("x")
    # Drop the targets in a deeper, alphabetically-later dir.
    target_dir = root / "z" / "WINDOWS" / "system32"
    target_dir.mkdir(parents=True)
    (target_dir / "auditusr.exe").write_text("recovered")
    (target_dir / "pdh.dll").write_text("recovered")
    found = _find_recovered_basenames(
        root, {"auditusr.exe", "pdh.dll", "ciadmin.dll"},
    )
    assert found == {"auditusr.exe", "pdh.dll"}


def test_find_recovered_basenames_empty_targets_short_circuits(tmp_path):
    root = tmp_path / "recovery"
    root.mkdir()
    (root / "anything.txt").write_text("x")
    assert _find_recovered_basenames(root, set()) == set()


def test_bulk_extractor_timeout_scales_with_disk_size():
    """Phase 9.2: 600s default times out on very large disks
    (Lone Wolf 476 GiB). Cap scales with image size so larger
    images get more wall time."""
    from el.agents.recovery import _bulk_extractor_timeout_for
    # ≤ 50 GiB: stays at the original 10-min cap
    assert _bulk_extractor_timeout_for(0) == 600
    assert _bulk_extractor_timeout_for(10 * 1024**3) == 600
    assert _bulk_extractor_timeout_for(50 * 1024**3) == 600
    # 50-200 GiB: 30 min
    assert _bulk_extractor_timeout_for(51 * 1024**3) == 1800
    assert _bulk_extractor_timeout_for(150 * 1024**3) == 1800
    assert _bulk_extractor_timeout_for(200 * 1024**3) == 1800
    # > 200 GiB: 60 min (Lone Wolf 476 GiB falls here)
    assert _bulk_extractor_timeout_for(201 * 1024**3) == 3600
    assert _bulk_extractor_timeout_for(476 * 1024**3) == 3600
    assert _bulk_extractor_timeout_for(2 * 1024**4) == 3600   # 2 TiB


def test_zeroed_basenames_modern_windows_path():
    """Modern /Windows/System32/ casing also works (regression check
    against the fix that made the regex case-insensitive)."""
    from el.agents.recovery import _zeroed_or_wiped_basenames
    triggers = [
        Finding(case_id="c", agent="disk_forensicator", confidence="high",
                claim=("Disk anomaly [SYSTEM_BINARY_ZERO_SIZE] Samples: "
                        "/Windows/System32/comres.dll (deleted); "
                        "/Windows/System32/dxgwdi.dll (deleted)"),
                evidence=[_ev()]),
    ]
    names = _zeroed_or_wiped_basenames(triggers)
    assert "comres.dll" in names
    assert "dxgwdi.dll" in names


def test_recovery_corroboration_finding_when_wiped_binary_recovered(case, monkeypatch):
    """When carve recovers a file whose name matches the
    SYSTEM_BINARY_ZERO trigger's referenced binary, the agent emits a
    medium-confidence corroboration finding linking the two."""
    cd, raw = case
    ledger_insert(cd, _trigger_finding(
        "Disk anomaly [SYSTEM_BINARY_ZERO_SIZE] in slot002. "
        "Samples: /Windows/System32/comres.dll (deleted); "
        "/Windows/System32/dxgwdi.dll (deleted)."
    ))

    from el.skills import sleuthkit as sk

    def _fake_tsk_recover(image, out_subdir, mode="alloc",
                           offset=None, timeout=7200):
        out_subdir.mkdir(parents=True, exist_ok=True)
        # Recover a file whose name matches the wiped binary
        (out_subdir / "comres.dll").write_text("recovered from unallocated")
        (out_subdir / "junk.tmp").write_text("noise")
        return SimpleNamespace(
            rc=0, as_evidence=lambda facts=None: EvidenceItem(
                tool="sleuthkit/tsk_recover", version="4.x",
                command="tsk_recover ...", output_sha256="0" * 64,
                output_path=str(out_subdir),
                extracted_facts=facts or {},
            ),
        )
    monkeypatch.setattr(sk, "tsk_recover", _fake_tsk_recover)

    # Bulk_extractor: stub no-op
    from el.skills import bulk_extractor as be

    def _fake_be(target, out_dir, **kw):
        out_dir.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            features=lambda: {},
            as_evidence=lambda facts=None: EvidenceItem(
                tool="bulk_extractor", version="x",
                command="be ...", output_sha256="0" * 64,
                output_path=str(out_dir), extracted_facts=facts or {},
            ),
        )
    monkeypatch.setattr(be, "scan", _fake_be)

    out = RecoveryAgent().run(_ctx(cd, raw, partitions=[
        {"slot": "0", "start_sector": 2048,
         "description": "NTFS / exFAT (0x07)"},
    ]))

    # The corroboration finding is medium confidence and references
    # the recovered binary by name.
    corroboration = [
        f for f in out
        if f.agent == "recovery" and f.confidence == "medium"
        and "corroborates anti-forensic" in (f.claim or "").lower()
    ]
    assert len(corroboration) == 1
    assert "comres.dll" in corroboration[0].claim


# ---------------------------------------------------------------------------
# Recommendation rule update
# ---------------------------------------------------------------------------

def test_recommendation_uses_pre_recovery_phrasing_when_no_recovery(tmp_path):
    """No RecoveryAgent findings present → rec is the original 'consider
    running tsk_recover' wording."""
    from el.reporting.recommendations import build_recommendations
    from el.reporting.narrative import BeatBlock, BEATS, NarrativeReport

    trigger = _trigger_finding(
        "Disk anomaly [MACB_TIMESTOMP_SKEW] something")
    nr = NarrativeReport(
        case_id="c", leading_hypothesis="H_ANTI_FORENSICS",
        leading_score=10, leading_gap=2,
        runner_up_hypothesis=None, runner_up_score=0,
        beats=[BeatBlock(beat=b, heading=b, earliest=None,
                          latest=None, finding_count=0) for b in BEATS],
        alt_beats=[], unresolved_count=0, insufficient_count=0,
        insufficient_findings=[],
    )
    recs = build_recommendations(nr, [trigger])
    rec = next((r for r in recs if "tsk_recover" in r.action), None)
    assert rec is not None, [r.action for r in recs]
    assert "Attempt to recover" in rec.action


def test_recommendation_uses_post_recovery_phrasing_with_corroboration(tmp_path):
    """When a recovery corroboration finding is present, the rec
    explicitly points at the corroboration result."""
    from el.reporting.recommendations import build_recommendations
    from el.reporting.narrative import BeatBlock, BEATS, NarrativeReport

    trigger = _trigger_finding(
        "Disk anomaly [SYSTEM_BINARY_ZERO_SIZE] something")
    corroboration = Finding(
        case_id="c", agent="recovery", confidence="medium",
        claim=("Recovery corroborates anti-forensic activity: 1 system "
                "binary name matches recovered file."),
        evidence=[_ev()],
    )
    nr = NarrativeReport(
        case_id="c", leading_hypothesis="H_ANTI_FORENSICS",
        leading_score=10, leading_gap=2,
        runner_up_hypothesis=None, runner_up_score=0,
        beats=[BeatBlock(beat=b, heading=b, earliest=None,
                          latest=None, finding_count=0) for b in BEATS],
        alt_beats=[], unresolved_count=0, insufficient_count=0,
        insufficient_findings=[],
    )
    recs = build_recommendations(nr, [trigger, corroboration])
    rec = next((r for r in recs if "corroboration" in r.action.lower()
                or "review the anti-forensic" in r.action.lower()), None)
    assert rec is not None, [r.action for r in recs]
    assert corroboration.finding_id in rec.triggered_by


def test_recommendation_uses_post_recovery_phrasing_without_corroboration(tmp_path):
    """RecoveryAgent ran but found no name-matching corroboration:
    the rec still flips to 'review exports/recovery/' rather than
    'go run tsk_recover'."""
    from el.reporting.recommendations import build_recommendations
    from el.reporting.narrative import BeatBlock, BEATS, NarrativeReport

    trigger = _trigger_finding(
        "Disk anomaly [MACB_TIMESTOMP_SKEW] something")
    recovery_finding = Finding(
        case_id="c", agent="recovery", confidence="low",
        claim="Recovered 1234 file(s) from slot0 (NTFS) via tsk_recover.",
        evidence=[_ev()], hypotheses_supported=["H_ANTI_FORENSICS"],
    )
    nr = NarrativeReport(
        case_id="c", leading_hypothesis="H_ANTI_FORENSICS",
        leading_score=10, leading_gap=2,
        runner_up_hypothesis=None, runner_up_score=0,
        beats=[BeatBlock(beat=b, heading=b, earliest=None,
                          latest=None, finding_count=0) for b in BEATS],
        alt_beats=[], unresolved_count=0, insufficient_count=0,
        insufficient_findings=[],
    )
    recs = build_recommendations(nr, [trigger, recovery_finding])
    rec = next((r for r in recs if "exports/recovery/" in r.action), None)
    assert rec is not None, [r.action for r in recs]
    assert "Attempt to recover" not in rec.action
