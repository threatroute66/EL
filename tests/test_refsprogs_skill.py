"""Tests for el.skills.refsprogs — ReFS filesystem walk via the
userspace refsprogs toolset.

Two layers:

  1. Pure-function helpers — signature detection, refsls listing
    parser — run without refsprogs being installed.

  2. Live integration — only runs when the refsprogs binaries are
    on PATH AND a real ReFS image is staged at the canonical
    operator path. Skipped on CI / dev hosts that don't have it.

The Linux + Sleuth Kit ecosystem has no ReFS reader, so refsprogs
is the only path EL has to walk Windows 11 Dev Drives + Server
2016+ ReFS volumes. Coverage is best-effort per the upstream
README — these tests pin what we DO support, not what's
theoretically reachable in ReFS.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from el.skills import refsprogs as rp


_REAL_IMAGE = Path("/mnt/hgfs/hackathon/refs.vhdx")
_HAS_REFSPROGS = (shutil.which("refsinfo") is not None
                   and shutil.which("refsls") is not None
                   and shutil.which("refscat") is not None)


# ---------------------------------------------------------------------------
# is_refs_signature — pure byte-level check, no binaries needed
# ---------------------------------------------------------------------------

def test_is_refs_signature_detects_valid_volume(tmp_path):
    """Real ReFS volume header: 3 bytes (zero JMP) + `ReFS` + 9
    bytes filler + `FSRS` sub-signature. Both must be present."""
    p = tmp_path / "vol.bin"
    p.write_bytes(b"\x00\x00\x00ReFS\x00\x00\x00\x00\x00\x00\x00\x00\x00FSRS"
                   + b"\x00" * 100)
    assert rp.is_refs_signature(p)


def test_is_refs_signature_requires_both_signatures(tmp_path):
    """`ReFS` at offset 0x03 but no `FSRS` at 0x10 — must NOT
    fire. The combo guards against false positives on stray
    ASCII data that happens to contain 'ReFS' as a substring."""
    p = tmp_path / "partial.bin"
    p.write_bytes(b"\x00\x00\x00ReFS\x00\x00\x00\x00\x00\x00\x00\x00\x00XXXX"
                   + b"\x00" * 100)
    assert not rp.is_refs_signature(p)


def test_is_refs_signature_rejects_ntfs(tmp_path):
    """NTFS volume header carries `NTFS    ` at offset 0x03 —
    must NOT fire."""
    p = tmp_path / "ntfs.bin"
    p.write_bytes(b"\xeb\x52\x90NTFS    " + b"\x00" * 100)
    assert not rp.is_refs_signature(p)


def test_is_refs_signature_supports_offset(tmp_path):
    """Disk image with the ReFS partition at offset N (after a
    partition table). Caller passes the partition's byte offset;
    detector seeks there."""
    p = tmp_path / "diskimg.bin"
    pad = b"\x00" * 1024
    refs_header = (b"\x00\x00\x00ReFS\x00\x00\x00\x00\x00\x00\x00\x00\x00FSRS"
                   + b"\x00" * 100)
    p.write_bytes(pad + refs_header)
    assert rp.is_refs_signature(p, offset=1024)
    # And the same detector at offset 0 (where there's no ReFS) fails
    assert not rp.is_refs_signature(p, offset=0)


def test_is_refs_signature_missing_file_returns_false(tmp_path):
    assert not rp.is_refs_signature(tmp_path / "absent")


def test_is_refs_signature_too_short(tmp_path):
    """File shorter than 0x14 bytes can't carry both signatures."""
    p = tmp_path / "tiny.bin"
    p.write_bytes(b"\x00\x00\x00ReFS\x00\x00\x00\x00")
    assert not rp.is_refs_signature(p)


# ---------------------------------------------------------------------------
# refsls long-format line parser
# ---------------------------------------------------------------------------

def test_refsls_parser_handles_real_line():
    """The exact shape refsls -l emits on the operator's image."""
    line = "           31 A---- 2026-05-18 17:43 test_refs.txt"
    rec = rp._parse_refsls_long(line)
    assert rec == {
        "name": "test_refs.txt",
        "size_bytes": 31,
        "attrs": "A----",
        "mtime": "2026-05-18 17:43",
    }


def test_refsls_parser_handles_directory_entry():
    """Directories have attribute `D` (and Windows housekeeping
    items add `S` + `H`). The parser must accept whatever
    refsprogs emits, not assume a specific attr set."""
    line = "            0 -DSH- 2026-05-18 17:43 $RECYCLE.BIN"
    rec = rp._parse_refsls_long(line)
    assert rec["name"] == "$RECYCLE.BIN"
    assert rec["size_bytes"] == 0
    assert "D" in rec["attrs"]


def test_refsls_parser_skips_warning_lines():
    """`[WARNING]` lines must be filtered out — they're
    operational diagnostics, not entries."""
    assert rp._parse_refsls_long(
        "[WARNING] Mismatching level 2 block data in level 1 blocks.") is None


def test_refsls_parser_skips_blank_lines():
    assert rp._parse_refsls_long("") is None
    assert rp._parse_refsls_long("   \n  ") is None


def test_refsls_parser_handles_filename_with_spaces():
    """ReFS allows spaces in filenames; refsls puts the name
    last. Parser must not split on whitespace inside the name."""
    line = "         1024 A---- 2026-05-18 17:43 my docs file.txt"
    rec = rp._parse_refsls_long(line)
    assert rec is not None
    assert rec["name"] == "my docs file.txt"


def test_refsls_parser_rejects_malformed_size():
    """A line where the first column isn't a number isn't a data
    row — drop it."""
    assert rp._parse_refsls_long("abc def ghi jkl mno") is None


# ---------------------------------------------------------------------------
# Evidence shaping
# ---------------------------------------------------------------------------

def test_volume_info_evidence_shape(tmp_path):
    stdout = tmp_path / "refsinfo.out"
    stdout.write_text("Volume information:\n\tReFS version: 3.14\n")
    info = rp.RefsVolumeInfo(
        refs_version="3.14", sector_size=512, cluster_size=4096,
        raw_stdout_path=stdout)
    ev = info.as_evidence(extra={"label": "test"})
    assert ev.tool == "refsinfo"
    assert ev.extracted_facts["refs_version"] == "3.14"
    assert ev.extracted_facts["sector_size"] == 512
    assert ev.extracted_facts["cluster_size"] == 4096
    assert ev.extracted_facts["phase"] == "refs_probe"
    assert ev.extracted_facts["label"] == "test"


def test_listing_evidence_shape(tmp_path):
    stdout = tmp_path / "refsls.out"
    stdout.write_text("listing\n")
    listing = rp.RefsListing(
        entries=[{"name": "a.txt", "size_bytes": 10,
                   "attrs": "A----", "mtime": "2026-01-01 00:00"}],
        raw_stdout_path=stdout, rc=0)
    ev = listing.as_evidence()
    assert ev.tool == "refsls"
    assert ev.extracted_facts["entry_count"] == 1


# ---------------------------------------------------------------------------
# carve_partition — Python-level copy with hole-friendly sparse handling
# ---------------------------------------------------------------------------

def test_carve_partition_writes_expected_size(tmp_path):
    """Carve a 1 MB region starting at sector 8 of a synthetic
    image. Output size must exactly match
    `partition_length_sectors × sector_size`."""
    src = tmp_path / "disk.raw"
    src.write_bytes(b"\xAA" * (8 * 512)        # leading padding (not in part)
                     + b"\xBB" * (2048 * 512))  # 1 MB of partition payload
    dst = tmp_path / "part.raw"
    rp.carve_partition(src, partition_start_sector=8,
                        partition_length_sectors=2048,
                        sector_size=512, out_path=dst)
    assert dst.stat().st_size == 2048 * 512
    # Content should be entirely 0xBB (the partition payload region)
    assert dst.read_bytes()[:16] == b"\xBB" * 16


def test_carve_partition_handles_short_source(tmp_path):
    """When the source file ends before the partition's declared
    length, we still write up to EOF (no padding)."""
    src = tmp_path / "short.raw"
    src.write_bytes(b"\xCC" * 1024)  # 2 sectors
    dst = tmp_path / "part.raw"
    rp.carve_partition(src, partition_start_sector=0,
                        partition_length_sectors=10,
                        sector_size=512, out_path=dst)
    # Only 2 sectors of actual data; we read until EOF + stop
    assert 0 < dst.stat().st_size <= 10 * 512


# ---------------------------------------------------------------------------
# Live integration — skipped without refsprogs AND real image
# ---------------------------------------------------------------------------

_LIVE_PARTITION_CACHE = Path("/var/tmp/el-refs-test-partition.raw")


@pytest.fixture(scope="session")
def real_partition():
    """Provide a carved ReFS partition for the live tests. Cached
    at a session-stable path under /var/tmp so successive pytest
    runs reuse the 50 GB file instead of re-carving (the carve is
    expensive AND pytest's per-test tmp_path adds rmtree cleanup
    that fills disk during the run).

    Skip the live tests entirely when:
      - refsprogs binaries aren't on PATH (CI / minimal SIFT)
      - the operator's reference image isn't staged
      - free disk space at /var/tmp is less than the partition
        size (don't blow up the host)
    """
    if not (_HAS_REFSPROGS and _REAL_IMAGE.exists()):
        pytest.skip("refsprogs not installed or real image absent")
    # Cache hit — partition already carved on a previous run
    if (_LIVE_PARTITION_CACHE.is_file()
            and rp.is_refs_signature(_LIVE_PARTITION_CACHE)):
        return _LIVE_PARTITION_CACHE
    import shutil as _sh
    # qemu-img convert writes the raw output sparsely by default and
    # our carve_partition is also sparse-aware. For a 50 GiB ReFS
    # volume that's only ~300 MB populated, the ACTUAL on-disk
    # allocation is well under 1 GB across both files. The check is
    # against allocated headroom, not declared length.
    avail = _sh.disk_usage(_LIVE_PARTITION_CACHE.parent).free
    if avail < 2_000_000_000:    # 2 GB minimum free
        pytest.skip(
            f"insufficient free space at /var/tmp for sparse carve "
            f"(<2 GB free)")
    import subprocess
    raw = _LIVE_PARTITION_CACHE.with_name("el-refs-test-disk.raw")
    proc = subprocess.run(
        ["qemu-img", "convert", "-O", "raw", "-f", "vhdx",
         str(_REAL_IMAGE), str(raw)],
        capture_output=True, timeout=600)
    if proc.returncode != 0:
        pytest.skip(f"qemu-img convert failed: {proc.stderr!r}")
    try:
        rp.carve_partition(raw, partition_start_sector=32768,
                            partition_length_sectors=104857600,
                            sector_size=512,
                            out_path=_LIVE_PARTITION_CACHE)
    finally:
        # Drop the intermediate raw — we only need the partition
        try:
            raw.unlink()
        except OSError:
            pass
    return _LIVE_PARTITION_CACHE


@pytest.mark.skipif(not (_HAS_REFSPROGS and _REAL_IMAGE.exists()),
                     reason="refsprogs not installed or real image absent")
def test_live_probe_volume_returns_real_metadata(tmp_path, real_partition):
    """Probe the operator's actual ReFS image. Pins the full
    plumbing (subprocess + stdout capture + line parse) against
    real refsinfo output."""
    info = rp.probe_volume(real_partition, tmp_path, timeout=60)
    assert info.refs_version == "3.14"
    assert info.sector_size == 512
    assert info.cluster_size == 4096
    assert info.sector_count > 0
    assert info.volume_serial != ""


@pytest.mark.skipif(not (_HAS_REFSPROGS and _REAL_IMAGE.exists()),
                     reason="refsprogs not installed or real image absent")
def test_live_read_label_returns_label(real_partition):
    label = rp.read_label(real_partition)
    assert label == "refs"


@pytest.mark.skipif(not (_HAS_REFSPROGS and _REAL_IMAGE.exists()),
                     reason="refsprogs not installed or real image absent")
def test_live_walk_finds_planted_file(tmp_path, real_partition):
    """The operator's image carries a `test_refs.txt` at the
    volume root with content "test document for refs dev disk".
    The walk must surface it alongside Windows housekeeping
    entries ($RECYCLE.BIN, System Volume Information)."""
    listing = rp.walk(real_partition, tmp_path)
    names = [e["name"] for e in listing.entries]
    assert "test_refs.txt" in names
    # Windows housekeeping survives the walk too
    assert any("$RECYCLE.BIN" in n for n in names)
    assert any("System Volume Information" in n for n in names)


@pytest.mark.skipif(not (_HAS_REFSPROGS and _REAL_IMAGE.exists()),
                     reason="refsprogs not installed or real image absent")
def test_live_cat_file_returns_planted_content(tmp_path, real_partition):
    out = rp.cat_file(real_partition, "/test_refs.txt",
                       tmp_path / "test_refs.txt.bin")
    assert out.read_text().strip() == "test document for refs dev disk"


@pytest.mark.skipif(not (_HAS_REFSPROGS and _REAL_IMAGE.exists()),
                     reason="refsprogs not installed or real image absent")
def test_live_cat_file_unknown_path_raises(tmp_path, real_partition):
    """A file that doesn't exist on the volume must raise — not
    silently write an empty output. Pin so a future bug that
    swallows the rc != 0 path gets caught."""
    with pytest.raises(rp.RefsprogsError):
        rp.cat_file(real_partition, "/does-not-exist.txt",
                     tmp_path / "out.bin")
