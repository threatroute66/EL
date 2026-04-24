"""Cross-evidence divergence detector in the combined report.

From SRL-2018 shakedown: `base-wkstn-05` memory was quiet (tied leader,
score 0) while its disk independently scored H_APT_ESPIONAGE 22. The
analyst spotted the mismatch by eye; the combined report should point
at it directly. Regression test locks in that behaviour.
"""
from pathlib import Path

from el.reporting.combined import (
    CaseSlice, _cross_evidence_divergence, render_combined,
)


def _slice(case_id: str, leader_hyp: str | None, leader_score: int) -> CaseSlice:
    ach = [{"hyp_id": leader_hyp, "score": leader_score}] if leader_hyp else []
    return CaseSlice(
        case_id=case_id,
        case_dir=Path("/nonexistent"),
        manifest={"case_id": case_id},
        ach_ranking=ach,
    )


# --- host_bare / kind parsing ---------------------------------------------

def test_host_bare_strips_prefix_and_kind_suffix():
    assert _slice("srl2018-wkstn05-memory", None, 0).host_bare == "wkstn05"
    assert _slice("srl2018-wkstn05-disk",   None, 0).host_bare == "wkstn05"
    assert _slice("srl2015-nromanoff-memory", None, 0).host_bare == "nromanoff"


def test_host_bare_handles_rerun_suffixes():
    # The SRL-2018 mail case required three retries; host grouping must
    # still put all three under 'mail'.
    for cid in ("srl2018-mail-memory", "srl2018-mail-memory-r2",
                "srl2018-mail-memory-r3", "srl2018-mail-memory-retry"):
        assert _slice(cid, None, 0).host_bare == "mail", cid


def test_kind_extraction():
    assert _slice("srl2018-mail-memory-r3", None, 0).kind == "memory-r3"
    assert _slice("srl2018-dc-disk", None, 0).kind == "disk"


# --- divergence detector --------------------------------------------------

def test_wkstn05_memory_quiet_vs_disk_hot_flagged():
    """The motivating case from the SRL-2018 shakedown."""
    cases = [
        _slice("srl2018-wkstn05-disk",   "H_APT_ESPIONAGE", 22),
        _slice("srl2018-wkstn05-memory", "H_APT_ESPIONAGE", 0),
    ]
    out = _cross_evidence_divergence(cases)
    assert len(out) == 1, out
    rec = out[0]
    assert rec["host"] == "wkstn05"
    assert rec["span"] == 22
    assert any("score span" in r for r in rec["reasons"])


def test_different_leaders_flagged():
    # Same host, different leading hypothesis per kind — should flag
    # even when scores happen to match.
    cases = [
        _slice("srl-foo-disk",   "H_APT_ESPIONAGE",   18),
        _slice("srl-foo-memory", "H_LATERAL_MOVEMENT", 18),
    ]
    out = _cross_evidence_divergence(cases)
    assert len(out) == 1
    assert "different leading hypotheses" in "; ".join(out[0]["reasons"])


def test_aligned_hosts_not_flagged():
    # Both disk and memory saying H_APT_ESPIONAGE at similar scores =
    # no divergence, keep the combined-report short.
    cases = [
        _slice("srl-bar-disk",   "H_APT_ESPIONAGE", 25),
        _slice("srl-bar-memory", "H_APT_ESPIONAGE", 28),
    ]
    assert _cross_evidence_divergence(cases) == []


def test_all_zero_scores_suppressed():
    # rd-05/rd-06 style: nothing fired on either side — not a
    # divergence worth flagging.
    cases = [
        _slice("srl-quiet-disk",   "H_APT_ESPIONAGE", 0),
        _slice("srl-quiet-memory", "H_APT_ESPIONAGE", 0),
    ]
    assert _cross_evidence_divergence(cases) == []


def test_single_case_per_host_not_flagged():
    # One-sided evidence isn't a divergence — nothing to compare.
    cases = [_slice("srl-only-memory", "H_APT_ESPIONAGE", 30)]
    assert _cross_evidence_divergence(cases) == []


# --- end-to-end: section renders ------------------------------------------

def test_divergence_section_appears_in_combined_report(tmp_path, monkeypatch):
    """End-to-end: the Cross-Evidence Divergence section reaches the
    rendered markdown when a divergence is present."""
    from el.reporting import combined as combined_mod

    slices_raw = [
        ("srl-wkstn05-disk",   "H_APT_ESPIONAGE", 22),
        ("srl-wkstn05-memory", "H_APT_ESPIONAGE", 0),
        ("srl-quiet-disk",     "H_APT_ESPIONAGE", 25),
        ("srl-quiet-memory",   "H_APT_ESPIONAGE", 28),
    ]
    # Build slices whose case_dir actually points at the tmp directories
    # (load_case normally reads manifest.json / findings.sqlite from them).
    slice_by_name = {}
    for cid, hyp, score in slices_raw:
        d = tmp_path / cid
        d.mkdir()
        ach = [{"hyp_id": hyp, "score": score}]
        slice_by_name[cid] = CaseSlice(
            case_id=cid, case_dir=d, manifest={"case_id": cid},
            ach_ranking=ach,
        )

    # Bypass the on-disk loader — we're testing the renderer directly.
    monkeypatch.setattr(combined_mod, "load_case",
                        lambda d: slice_by_name[d.name])
    case_dirs = [s.case_dir for s in slice_by_name.values()]

    out_path = tmp_path / "combined.md"
    render_combined(case_dirs, out_path, name="divergence-test")
    md = out_path.read_text()

    assert "## Cross-Evidence Divergence" in md
    assert "wkstn05" in md
    # The aligned pair (quiet) must NOT be listed in the divergence table
    # (we check by scanning only the divergence section).
    divsec = md.split("## Cross-Evidence Divergence", 1)[1]
    divsec = divsec.split("\n## ", 1)[0]  # next H2
    # Check only the table rows (case ids are backticked).
    table_rows = [line for line in divsec.splitlines() if "`srl-" in line]
    assert all("wkstn05" in row for row in table_rows), (
        "divergence table must contain only the divergent host, not quiet"
    )
