"""Skill: read-only GPT/MBR integrity inspector — interrupted-wipe detector.

Motivation: the CIRCL "Recovering data from a wiped disk" exercise. An insider
was interrupted while wiping his disk: the protective MBR (LBA 0), the primary
GPT header (LBA 1) and the primary partition-entry array (LBA 2-33) were all
zeroed, but the **backup GPT** at the end of the disk survived. The Sleuth Kit's
`mmls` silently recovers the partition layout from that backup and reports
partitions normally — so the destruction is *invisible* in EL's output even
though it is the single most important forensic signal (deliberate device /
evidence destruction by the subject).

This skill is the detector mmls doesn't give us. It is a PURE, read-only byte
inspector (no external tool — sgdisk refuses to enumerate in this state and
gdisk -l goes interactive on a wiped MBR; neither fits a non-destructive
"report the wipe state" need, so per EL's wrap-don't-reimplement rule this is
one of the few hand-written parsers, like the utmp/IIS ones). It NEVER writes.

It reports the state of each front-of-disk structure and whether the
"primary destroyed / backup intact" interrupted-wipe condition holds, so
disk_forensicator can raise an H_ANTI_FORENSICS + H_INSIDER_DEVICE_DESTRUCTION
finding. Partition *enumeration* still comes from mmls — this only classifies
the integrity state.
"""
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem

_GPT_SIG = b"EFI PART"
_MBR_SIG = b"\x55\xaa"
# GPT protective-MBR partition type (0xEE) lives in the type byte of the
# single MBR partition entry that spans the whole disk.
_PROTECTIVE_TYPE = 0xEE


@dataclass
class GptState:
    image: Path
    sector_size: int
    protective_mbr_status: str          # ok | wiped | absent
    primary_gpt_status: str             # ok | wiped | corrupt
    primary_entries_status: str         # ok | wiped | unknown
    backup_gpt_status: str              # ok | absent
    front_zero_sectors: int             # leading all-zero 512B sectors (capped)
    notes: list[str] = field(default_factory=list)

    @property
    def interrupted_wipe(self) -> bool:
        """True when the front-of-disk GPT structures were destroyed
        (primary header wiped/corrupt) but the backup GPT survived — the
        signature of an interrupted or structure-only disk wipe from which
        mmls silently recovers via the backup."""
        return (self.primary_gpt_status in ("wiped", "corrupt")
                and self.backup_gpt_status == "ok")

    @property
    def full_wipe(self) -> bool:
        """Both primary AND backup GPT destroyed — unrecoverable layout."""
        return (self.primary_gpt_status in ("wiped", "corrupt")
                and self.backup_gpt_status == "absent")

    def as_dict(self) -> dict:
        return {
            "protective_mbr_status": self.protective_mbr_status,
            "primary_gpt_status": self.primary_gpt_status,
            "primary_entries_status": self.primary_entries_status,
            "backup_gpt_status": self.backup_gpt_status,
            "front_zero_sectors": self.front_zero_sectors,
            "interrupted_wipe": self.interrupted_wipe,
            "full_wipe": self.full_wipe,
            "sector_size": self.sector_size,
            "notes": self.notes,
        }

    def as_evidence(self, out_dir: Path, facts: dict | None = None) -> EvidenceItem:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "gpt_state.json"
        payload = json.dumps(self.as_dict(), indent=2, sort_keys=True)
        out_path.write_text(payload)
        sha = hashlib.sha256(payload.encode()).hexdigest()
        f = dict(self.as_dict())
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.gpt_state", version="0.1.0",
            command=f"gpt_state.inspect({Path(self.image).name})",
            output_sha256=sha, output_path=str(out_path),
            extracted_facts=f,
        )


def _is_zero(b: bytes) -> bool:
    return b == b"\x00" * len(b)


def _gpt_header_valid_crc(hdr: bytes) -> bool:
    """Validate a GPT header's self CRC32 (offset 16, len 4) computed over
    HeaderSize (offset 12) bytes with the CRC field zeroed."""
    if len(hdr) < 92 or hdr[0:8] != _GPT_SIG:
        return False
    header_size = struct.unpack_from("<I", hdr, 12)[0]
    stored_crc = struct.unpack_from("<I", hdr, 16)[0]
    if header_size < 92 or header_size > len(hdr):
        return False
    buf = bytearray(hdr[:header_size])
    buf[16:20] = b"\x00\x00\x00\x00"
    return (zlib.crc32(bytes(buf)) & 0xFFFFFFFF) == stored_crc


def _classify_primary_gpt(hdr: bytes) -> str:
    if _is_zero(hdr[:512]):
        return "wiped"
    if hdr[0:8] != _GPT_SIG:
        return "corrupt"
    return "ok" if _gpt_header_valid_crc(hdr) else "corrupt"


def _classify_protective_mbr(mbr: bytes) -> str:
    if _is_zero(mbr[:512]):
        return "wiped"
    if mbr[510:512] != _MBR_SIG:
        return "absent"
    # any partition entry with the 0xEE protective type?
    for i in range(4):
        e = mbr[446 + i * 16: 446 + i * 16 + 16]
        if len(e) == 16 and e[4] == _PROTECTIVE_TYPE:
            return "ok"
    return "absent"


def inspect(image: Path, sector_size: int = 512,
            front_scan_sectors: int = 4096) -> GptState:
    """Read-only inspection of the front-of-disk + backup GPT structures.

    *image* is a raw disk stream (e.g. the ewfmount ewf1 file). Reads only a
    handful of sectors at the front and the final sector; never writes.
    """
    image = Path(image)
    size = image.stat().st_size
    notes: list[str] = []
    with image.open("rb") as f:
        mbr = f.read(512)
        f.seek(sector_size)
        primary_hdr = f.read(512)
        f.seek(sector_size * 2)
        primary_entries = f.read(512)
        # backup GPT header occupies the final sector of the device
        backup_off = max(0, size - sector_size)
        f.seek(backup_off)
        backup_hdr = f.read(512)
        # count leading all-zero sectors (capped) — the "front-of-disk wipe"
        # extent the operator zeroed before being interrupted
        f.seek(0)
        front_zero = 0
        for _ in range(front_scan_sectors):
            chunk = f.read(sector_size)
            if not chunk or not _is_zero(chunk):
                break
            front_zero += 1

    protective_mbr_status = _classify_protective_mbr(mbr)
    primary_gpt_status = _classify_primary_gpt(primary_hdr)
    primary_entries_status = "wiped" if _is_zero(primary_entries) else "ok"
    backup_gpt_status = "ok" if backup_hdr[0:8] == _GPT_SIG else "absent"

    if primary_gpt_status == "wiped" and backup_gpt_status == "ok":
        notes.append("primary GPT header zeroed; backup GPT intact at last "
                     "sector — partition table recoverable only from backup")
    if front_zero:
        notes.append(f"{front_zero} leading sector(s) zero-filled "
                     f"({front_zero * sector_size} bytes)")

    return GptState(
        image=image, sector_size=sector_size,
        protective_mbr_status=protective_mbr_status,
        primary_gpt_status=primary_gpt_status,
        primary_entries_status=primary_entries_status,
        backup_gpt_status=backup_gpt_status,
        front_zero_sectors=front_zero, notes=notes,
    )
