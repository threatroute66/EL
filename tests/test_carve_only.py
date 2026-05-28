"""Contract tests for carve-only / unallocated-space routing.

Ashemery's "Unallocated01" exercise: the only evidence is a ~24 GiB headerless
export of a Windows host's UNALLOCATED disk space. It has no container magic, no
partition table and no filesystem at offset 0, so triage used to misroute it to
MemoryForensicator (vol3 → no kernel → no carving). These lock in:
  * a large headerless blob dense with NTFS/Windows artifact signatures is
    classified "unallocated (carve-only)" and routed to DiskForensicator;
  * small files / signature-poor blobs are NOT (memory images still fall
    through to the memory path).
"""
from __future__ import annotations

from el.agents.triage import _detect_carvable_blob
from el.orchestrator.coordinator import KIND_TO_AGENT
from el.agents.disk_forensicator import DiskForensicatorAgent


def _blob(path, size, *, sigs=()):
    """Write a sparse file of *size* bytes, embedding each signature at three
    offsets the detector definitely samples (it reads 1 MiB windows at fixed
    fractions), so each placed signature is seen at >=2 sampled windows."""
    path.write_bytes(b"")  # truncate
    with path.open("wb") as f:
        f.truncate(size)
        for sig in sigs:
            for frac in (0.2, 0.5, 0.7):     # all in the detector's sample set
                f.seek(int(size * frac))
                f.write(sig)
    return path


# 300 MiB clears the 256 MiB floor while staying a sparse file on disk.
SZ = 300 * 1024 * 1024


def test_unallocated_blob_with_two_signatures_detected(tmp_path):
    img = _blob(tmp_path / "unalloc.bin", SZ,
                sigs=(b"FILE0", b"regf"))      # MFT records + registry hive
    assert _detect_carvable_blob(img) == "unallocated (carve-only)"


def test_single_signature_seen_twice_detected(tmp_path):
    img = _blob(tmp_path / "pf.bin", SZ, sigs=(b"MAM\x04",))  # placed at 2 offsets
    assert _detect_carvable_blob(img) == "unallocated (carve-only)"


def test_signature_poor_blob_not_carve_only(tmp_path):
    """A large blob with no filesystem-artifact signatures (e.g. a memory
    image's generic content) must NOT be classified carve-only — it falls
    through to the memory path."""
    img = tmp_path / "mem.bin"
    img.write_bytes(b"")
    with img.open("wb") as f:
        f.truncate(SZ)
        f.seek(0)
        f.write(b"MZ" * 1000)   # PE-ish noise, but none of the disk sigs
    assert _detect_carvable_blob(img) is None


def test_small_file_below_floor_ignored(tmp_path):
    img = _blob(tmp_path / "small.bin", 4 * 1024 * 1024, sigs=(b"FILE0", b"regf"))
    assert _detect_carvable_blob(img) is None


def test_carve_only_routes_to_disk_forensicator():
    assert KIND_TO_AGENT["unallocated (carve-only)"] is DiskForensicatorAgent
