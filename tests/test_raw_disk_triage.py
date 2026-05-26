"""Contract tests for raw (dd) disk-image detection + routing.

EL routed E01 / VHDX / VMDK / BitLocker but NOT plain raw dd images —
the single most common forensic disk format. A raw disk has no
container magic at byte 0, so triage's byte-0 loop missed it and the
image fell through to "opaque memory candidate", misrouting to
MemoryForensicator. Discovered on the 2019 Narcos corpus (split-raw
GPT Windows disks, reassembled via affuse).

Locks in:
  * _detect_raw_disk recognises GPT ("EFI PART" @ 512) + MBR (0x55AA
    + a plausible partition entry)
  * the 0x55AA-alone false positive is rejected (needs real geometry)
  * tiny files are rejected (< 1 MiB is not a disk)
  * single-file routing sets evidence_kind = "raw-disk (…)" and does
    NOT fall through to the memory path
  * KIND_TO_AGENT routes both raw-disk labels to DiskForensicator
  * the disk+memory bundle detector pairs a raw disk with a memory
    image, excluding the disk from memory candidates
"""
from __future__ import annotations

import struct
from pathlib import Path

from el.agents.base import AgentContext
from el.agents.triage import TriageAgent, _detect_raw_disk


_MIB = 1024 * 1024


def _gpt_image(path: Path, size_mib: int = 2) -> Path:
    """Minimal GPT-shaped raw image: protective MBR + 'EFI PART' at
    offset 512 (LBA 1), padded to size."""
    buf = bytearray(size_mib * _MIB)
    buf[510:512] = b"\x55\xaa"          # protective-MBR boot sig
    buf[512:520] = b"EFI PART"          # GPT header at LBA 1
    path.write_bytes(buf)
    return path


def _mbr_image(path: Path, size_mib: int = 2) -> Path:
    """Minimal MBR-shaped raw image: 0x55AA + one real partition
    entry (type 0x07 NTFS, LBA start 2048)."""
    buf = bytearray(size_mib * _MIB)
    entry = bytearray(16)
    entry[4] = 0x07                      # partition type (NTFS/exFAT)
    entry[8:12] = struct.pack("<I", 2048)  # LBA start
    buf[446:462] = entry
    buf[510:512] = b"\x55\xaa"
    path.write_bytes(buf)
    return path


def _ctx(case_dir: Path, input_path: Path) -> AgentContext:
    (case_dir / "analysis" / "triage").mkdir(parents=True, exist_ok=True)
    return AgentContext(case_id="rd-test", case_dir=case_dir,
                        input_path=input_path,
                        manifest={"input_path": str(input_path)})


# ---------------------------------------------------------------------------
# _detect_raw_disk
# ---------------------------------------------------------------------------

def test_detects_gpt(tmp_path):
    assert _detect_raw_disk(_gpt_image(tmp_path / "d.raw")) == "raw-disk (GPT)"


def test_detects_mbr(tmp_path):
    assert _detect_raw_disk(_mbr_image(tmp_path / "d.raw")) == "raw-disk (MBR)"


def test_rejects_bare_55aa_without_partition_entry(tmp_path):
    """0x55AA at 510 with an all-zero partition table is NOT a disk —
    countless unrelated files end in those two bytes."""
    buf = bytearray(2 * _MIB)
    buf[510:512] = b"\x55\xaa"           # boot sig but no partition entries
    p = tmp_path / "notdisk.bin"
    p.write_bytes(buf)
    assert _detect_raw_disk(p) is None


def test_rejects_small_file(tmp_path):
    """A < 1 MiB file with GPT-looking bytes is below the disk-size
    floor — guards against tiny fixtures / fragments."""
    buf = bytearray(4096)
    buf[510:512] = b"\x55\xaa"
    buf[512:520] = b"EFI PART"
    p = tmp_path / "tiny.raw"
    p.write_bytes(buf)
    assert _detect_raw_disk(p) is None


def test_rejects_memory_dump_shape(tmp_path):
    """A raw memory dump (no partition structure) must not be
    mistaken for a disk."""
    buf = bytearray(2 * _MIB)            # zeros, no 0x55AA, no EFI PART
    buf[:8] = b"\x00" * 8
    p = tmp_path / "mem.raw"
    p.write_bytes(buf)
    assert _detect_raw_disk(p) is None


# ---------------------------------------------------------------------------
# Single-file routing
# ---------------------------------------------------------------------------

def test_single_gpt_file_routes_to_raw_disk_kind(tmp_path):
    img = _gpt_image(tmp_path / "Narcos-1.raw")
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, img)
    TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "raw-disk (GPT)"
    # Must NOT have been treated as a memory candidate / run vol3
    assert ctx.shared.get("mem_os") is None


def test_raw_disk_kinds_route_to_disk_forensicator():
    from el.orchestrator.coordinator import KIND_TO_AGENT
    from el.agents.disk_forensicator import DiskForensicatorAgent
    assert KIND_TO_AGENT["raw-disk (GPT)"] is DiskForensicatorAgent
    assert KIND_TO_AGENT["raw-disk (MBR)"] is DiskForensicatorAgent


# ---------------------------------------------------------------------------
# Raw-disk + memory bundle
# ---------------------------------------------------------------------------

def test_raw_disk_plus_memory_bundle(tmp_path):
    """A directory with a raw GPT disk + a raw memory image is a
    disk+memory bundle: disk routes to DiskForensicator, memory is
    paired. The disk .raw must be EXCLUDED from memory candidates
    even though it shares the .raw extension."""
    d = tmp_path / "Narcos-1"
    d.mkdir()
    _gpt_image(d / "Narcos-1-disk.raw")
    # raw memory dump — .raw ext, stem contains "memory"
    (d / "Narcos-1-memory.raw").write_bytes(b"\x00" * (2 * _MIB))
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, d)

    TriageAgent().run(ctx)

    assert ctx.shared.get("evidence_kind") == "raw-disk (GPT)"
    assert ctx.shared.get("paired_memory_image", "").endswith(
        "Narcos-1-memory.raw")
    # input rewritten to the disk, not the memory
    assert str(ctx.input_path).endswith("Narcos-1-disk.raw")


def test_raw_disk_without_memory_is_not_a_bundle(tmp_path):
    """A directory with only a raw disk (no memory) must not set a
    paired_memory_image — single-disk dirs aren't bundles."""
    d = tmp_path / "disk-only"
    d.mkdir()
    _gpt_image(d / "image.raw")
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, d)
    TriageAgent().run(ctx)
    assert "paired_memory_image" not in ctx.shared
