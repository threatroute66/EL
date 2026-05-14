"""FOR508 ex 3.1b — VSS cross-snapshot artifact diff tests.

The detector ships in two layers:
1. Pure-function diff (parse_vshadowinfo / fingerprint / diff_fingerprints)
   — tested here against tmp_path fixtures, no subprocess / sudo.
2. Subprocess wrappers (vshadowinfo / vshadowmount) + agent integration
   — exercised when the wrappers run on real VSS-bearing images
   (covered indirectly in real-case investigation runs).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.intel.ach import score_findings
from el.schemas.finding import EvidenceItem, Finding
from el.skills.vss_diff import (
    ArtifactDiff,
    ArtifactState,
    DEFAULT_TARGETS,
    diff_fingerprints,
    fingerprint,
    parse_vshadowinfo,
)


# ---------------------------------------------------------------------------
# parse_vshadowinfo
# ---------------------------------------------------------------------------

VSHADOWINFO_OK = """\
vshadowinfo 20240504

Volume Shadow Snapshots information:
\tNumber of snapshots:\t2

Snapshot: 1
\tIdentifier\t\t: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
\tCreation time\t\t: Apr 04, 2012 17:30:11.000000000 UTC
\tVolume size\t\t: 64 GiB (68719476736 bytes)

Snapshot: 2
\tIdentifier\t\t: ffffffff-1111-2222-3333-444444444444
\tCreation time\t\t: Apr 05, 2012 02:11:33.000000000 UTC
\tVolume size\t\t: 64 GiB (68719476736 bytes)
"""


def test_parse_vshadowinfo_two_snapshots():
    snaps = parse_vshadowinfo(VSHADOWINFO_OK)
    assert len(snaps) == 2
    assert snaps[0].number == 1
    assert snaps[0].identifier == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert snaps[0].volume_size_bytes == 68719476736
    assert "Apr 04, 2012" in snaps[0].creation_utc
    assert snaps[1].number == 2


def test_parse_vshadowinfo_empty():
    assert parse_vshadowinfo("Number of snapshots: 0\n") == []
    assert parse_vshadowinfo("") == []


def test_parse_vshadowinfo_skips_unknown_fields():
    """Future libvshadow versions may add or rename fields. Parser
    must not blow up on unrecognised keys."""
    text = """\
Snapshot: 1
\tIdentifier\t: xxxxxxxx-yyyy-zzzz
\tNew Future Field\t: some-value
\tVolume size\t: 1 GiB (1073741824 bytes)
"""
    snaps = parse_vshadowinfo(text)
    assert len(snaps) == 1
    assert snaps[0].identifier == "xxxxxxxx-yyyy-zzzz"


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------

def _build_mount(root: Path, files: dict[str, bytes]) -> None:
    """Materialise a fake NTFS mount tree at root with the given
    {relpath: content} files."""
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)


def test_fingerprint_hashes_existing_files(tmp_path):
    mount = tmp_path / "live"
    _build_mount(mount, {
        "Windows/AppCompat/Programs/RecentFileCache.bcf": b"A" * 200,
        "Windows/System32/winevt/Logs/Security.evtx": b"B" * 5000,
    })
    fp = fingerprint(mount, side="live")
    sec = fp["Windows/System32/winevt/Logs/Security.evtx"]
    assert sec.size == 5000
    assert sec.sha256 is not None
    rfc = fp["Windows/AppCompat/Programs/RecentFileCache.bcf"]
    assert rfc.size == 200


def test_fingerprint_records_absent_targets(tmp_path):
    """A target that doesn't exist on this mount must be recorded as
    absent (size=None, sha=None) rather than silently dropped — the
    diff function joins live + snapshot fingerprints by path, and
    a missing key on either side breaks the deleted-in-live detection."""
    mount = tmp_path / "live"; mount.mkdir()
    fp = fingerprint(mount, side="live")
    # Every literal target should appear with size=None
    for t in DEFAULT_TARGETS:
        if "*" not in t and "?" not in t:
            assert t in fp
            assert fp[t].size is None
            assert fp[t].sha256 is None


def test_fingerprint_expands_glob_targets(tmp_path):
    """At*.job is a glob; multiple matches must all hash. Per-file
    visibility on scheduled-task additions/deletions is the whole
    point of including the glob target."""
    mount = tmp_path / "live"
    _build_mount(mount, {
        "Windows/Tasks/At1.job": b"task1",
        "Windows/Tasks/At2.job": b"task2",
        "Windows/Tasks/At5.job": b"task5",
    })
    fp = fingerprint(mount, side="live")
    job_paths = [k for k in fp if k.startswith("Windows/Tasks/At")]
    assert len(job_paths) >= 3


# ---------------------------------------------------------------------------
# diff_fingerprints
# ---------------------------------------------------------------------------

def test_diff_flags_deleted_in_live(tmp_path):
    """The smoking-gun case: file present in shadow, absent on live FS."""
    live = tmp_path / "live"; live.mkdir()
    snap = tmp_path / "snap"
    _build_mount(snap, {
        "Windows/AppCompat/Programs/RecentFileCache.bcf": b"X" * 100,
    })
    live_fp = fingerprint(live, side="live")
    snap_fp = fingerprint(snap, side="snapshot:1")
    diffs = diff_fingerprints(live_fp, snap_fp, snapshot_number=1)
    assert any(d.severity == "deleted_in_live"
               and "RecentFileCache.bcf" in d.relpath
               for d in diffs)


def test_diff_flags_shrunk_in_live(tmp_path):
    """Live size < snapshot size = log truncation / clearing."""
    live = tmp_path / "live"
    snap = tmp_path / "snap"
    _build_mount(live, {
        "Windows/System32/winevt/Logs/Security.evtx": b"X" * 1000,
    })
    _build_mount(snap, {
        "Windows/System32/winevt/Logs/Security.evtx": b"X" * 50000,
    })
    live_fp = fingerprint(live, side="live")
    snap_fp = fingerprint(snap, side="snapshot:1")
    diffs = diff_fingerprints(live_fp, snap_fp, snapshot_number=1)
    shrunk = [d for d in diffs if d.severity == "shrunk_in_live"]
    assert shrunk
    assert shrunk[0].delta_bytes == 49000   # snap - live, positive = shrunk


def test_diff_flags_content_changed_same_size(tmp_path):
    """Same size, different content = timestomp / in-place rewrite."""
    live = tmp_path / "live"
    snap = tmp_path / "snap"
    _build_mount(live, {
        "Windows/AppCompat/Programs/Amcache.hve": b"L" * 4096,
    })
    _build_mount(snap, {
        "Windows/AppCompat/Programs/Amcache.hve": b"S" * 4096,
    })
    live_fp = fingerprint(live, side="live")
    snap_fp = fingerprint(snap, side="snapshot:1")
    diffs = diff_fingerprints(live_fp, snap_fp, snapshot_number=1)
    assert any(d.severity == "changed" and "Amcache.hve" in d.relpath
               for d in diffs)


def test_diff_drops_identical_and_absent_both(tmp_path):
    """Identical and absent-on-both must NOT appear in the diff output —
    those are the boring cases that would flood the ledger."""
    live = tmp_path / "live"
    snap = tmp_path / "snap"
    _build_mount(live, {
        "Windows/System32/winevt/Logs/Application.evtx": b"X" * 1024,
    })
    _build_mount(snap, {
        "Windows/System32/winevt/Logs/Application.evtx": b"X" * 1024,
    })
    live_fp = fingerprint(live, side="live")
    snap_fp = fingerprint(snap, side="snapshot:1")
    diffs = diff_fingerprints(live_fp, snap_fp, snapshot_number=1)
    # Identical Application.evtx → not in diff.
    # Other targets absent on both → not in diff.
    assert all(d.severity not in ("identical", "absent_both")
               for d in diffs)


# ---------------------------------------------------------------------------
# Hypothesis lift — H_SHADOW_COPY_ARTIFACT_DELETED
# ---------------------------------------------------------------------------

def test_shadow_copy_deletion_lifts_hypothesis(tmp_path):
    """An H_SHADOW_COPY_ARTIFACT_DELETED-tagged finding must score the
    new hypothesis at +3 — single-tag lift, stands alone."""
    ev = EvidenceItem(tool="vss", version="0", command="x",
                      output_sha256="0"*64, output_path="/x")
    f = Finding(
        case_id="c", agent="disk_forensicator", confidence="high",
        claim=("VSS diff on partition0: "
               "`Windows/AppCompat/Programs/RecentFileCache.bcf` — "
               "PRESENT in shadow, ABSENT on live FS (snapshot #2)"),
        evidence=[ev],
        hypotheses_supported=["H_SHADOW_COPY_ARTIFACT_DELETED",
                               "H_ANTI_FORENSICS"])
    ranked, _ = score_findings([f])
    sc_anti = next(r for r in ranked
                   if r.hyp_id == "H_SHADOW_COPY_ARTIFACT_DELETED")
    af = next(r for r in ranked if r.hyp_id == "H_ANTI_FORENSICS")
    assert sc_anti.score == 3
    # Anti-forensics also lifts (corroboration), expected behaviour.
    assert af.score >= 3


def test_unrelated_finding_does_not_lift_shadow_copy_hypothesis():
    """Only the explicit tag lifts the hypothesis. A generic
    'no non-baseline items observed' or random anti-forensics finding
    must NOT score H_SHADOW_COPY_ARTIFACT_DELETED."""
    ev = EvidenceItem(tool="x", version="0", command="x",
                      output_sha256="0"*64, output_path="/x")
    f = Finding(case_id="c", agent="x", confidence="high",
                claim="random anti-forensic claim",
                evidence=[ev],
                hypotheses_supported=["H_ANTI_FORENSICS"])
    ranked, _ = score_findings([f])
    sc = next(r for r in ranked
              if r.hyp_id == "H_SHADOW_COPY_ARTIFACT_DELETED")
    assert sc.score == 0
