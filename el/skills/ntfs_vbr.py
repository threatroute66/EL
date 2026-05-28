"""Skill: NTFS Volume Boot Record (VBR) recovery from the backup boot sector.

When a disk wipe zeroes the START of an NTFS partition, the primary VBR is
destroyed and the Sleuth Kit reports "Cannot determine file system type" — even
though NTFS keeps an exact COPY of the boot sector in the LAST sector of the
volume. This skill detects that surviving backup VBR and, read-only, splices it
to the front of a DERIVED working image in the case workspace (the evidence is
never modified), so the normal `fls`/extraction pipeline can walk the volume.

Forensically this is the read-only analogue of the classic `dd
if=backup of=front` repair — but applied to a derived copy, leaving the
original image byte-for-byte intact and hashed.

If no valid backup VBR survives (the wipe took the whole volume), recovery
returns None and the caller reports that the volume is unrecoverable — which
itself corroborates a deliberate disk wipe.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem

_NTFS_OEM = b"NTFS    "
_MBR_SIG = b"\x55\xaa"
# Default: don't auto-build a derived image larger than this (bytes).
_DEFAULT_SIZE_CAP = 8 * 1024 * 1024 * 1024  # 8 GiB


class NtfsVbrError(RuntimeError):
    pass


@dataclass
class RecoveredVolume:
    image: Path
    derived_path: Path
    vbr_source_sector: int
    volume_bytes: int

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        try:
            sha = _sha256_file(self.derived_path)
        except OSError:
            sha = ""
        f = {
            "recovered_via": "ntfs_backup_vbr",
            "vbr_source_sector": self.vbr_source_sector,
            "derived_path": str(self.derived_path),
            "volume_bytes": self.volume_bytes,
        }
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.ntfs_vbr", version="0.1.0",
            command=(f"ntfs_vbr.recover({Path(self.image).name} "
                     f"@sector{self.vbr_source_sector})"),
            output_sha256=sha, output_path=str(self.derived_path),
            extracted_facts=f,
        )


def is_ntfs_vbr(sector: bytes) -> bool:
    """True if *sector* (>=512 bytes) looks like an NTFS Volume Boot Record:
    x86 jump (0xEB/0xE9) + 'NTFS    ' OEM id + 0x55AA end signature."""
    if len(sector) < 512:
        return False
    if sector[0] not in (0xEB, 0xE9):
        return False
    if sector[3:11] != _NTFS_OEM:
        return False
    return sector[510:512] == _MBR_SIG


def find_backup_vbr(image: Path, start_sector: int, end_sector: int,
                    sector_size: int = 512) -> int | None:
    """Locate the NTFS backup boot sector for a partition. NTFS stores it in
    the volume's LAST sector; return that sector index if it holds a valid
    NTFS VBR, else None. *end_sector* is the partition's inclusive last sector
    (as reported by mmls)."""
    image = Path(image)
    candidates = [end_sector]
    # tolerate off-by-one (some tools report the trailing alignment sector)
    if end_sector - 1 > start_sector:
        candidates.append(end_sector - 1)
    try:
        with image.open("rb") as f:
            for sec in candidates:
                f.seek(sec * sector_size)
                if is_ntfs_vbr(f.read(512)):
                    return sec
    except OSError:
        return None
    return None


def _sha256_file(p: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for blk in iter(lambda: f.read(chunk), b""):
            h.update(blk)
    return h.hexdigest()


def recover(image: Path, start_sector: int, end_sector: int, out_dir: Path,
            sector_size: int = 512,
            size_cap_bytes: int = _DEFAULT_SIZE_CAP,
            chunk: int = 1 << 20) -> RecoveredVolume | None:
    """If a backup VBR survives, build a read-only derived working image with
    the recovered VBR at offset 0, so TSK can walk the volume. Returns None when
    no backup VBR is found. Raises NtfsVbrError when recovery is possible but the
    volume exceeds *size_cap_bytes* (caller should surface that to the analyst).
    """
    image = Path(image)
    vbr_sec = find_backup_vbr(image, start_sector, end_sector, sector_size)
    if vbr_sec is None:
        return None
    volume_bytes = (end_sector - start_sector + 1) * sector_size
    if volume_bytes > size_cap_bytes:
        raise NtfsVbrError(
            f"NTFS backup VBR found at sector {vbr_sec}, but volume is "
            f"{volume_bytes} bytes (> cap {size_cap_bytes}); skipping automatic "
            f"derived-image rebuild — re-run with a larger cap to recover.")
    out_dir.mkdir(parents=True, exist_ok=True)
    derived = out_dir / f"recovered_ntfs_off{start_sector}.raw"
    with image.open("rb") as src, derived.open("wb") as dst:
        # 1) recovered VBR (the surviving backup) at offset 0
        src.seek(vbr_sec * sector_size)
        dst.write(src.read(sector_size))
        # 2) the remainder of the volume verbatim, from sector start+1
        src.seek((start_sector + 1) * sector_size)
        remaining = volume_bytes - sector_size
        while remaining > 0:
            blk = src.read(min(chunk, remaining))
            if not blk:
                break
            dst.write(blk)
            remaining -= len(blk)
    return RecoveredVolume(image=image, derived_path=derived,
                           vbr_source_sector=vbr_sec, volume_bytes=volume_bytes)
