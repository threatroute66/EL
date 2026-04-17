"""Skill: dumped-region triage (strings + IOC + structural clues).

Pure Python — no external `strings` binary needed (the regex matches what
GNU strings would extract). Used by MalwareTriageAgent to attribute the
.dmp files vol3's `windows.malfind --dump` produces.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


# ASCII printable strings of length >= 6 (matches GNU strings -n 6 default)
_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
# UTF-16LE printable strings of length >= 4 chars (8 bytes)
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


@dataclass
class DumpScan:
    path: Path
    size_bytes: int
    ascii_strings: set[str] = field(default_factory=set)
    wide_strings: set[str] = field(default_factory=set)
    sha256: str = ""
    has_mz_header: bool = False
    has_pe_signature: bool = False
    nop_sled_runs: int = 0

    @property
    def all_strings(self) -> set[str]:
        return self.ascii_strings | self.wide_strings


def scan_dump(path: Path,
              min_ascii: int = 6, min_wide: int = 4,
              max_strings: int = 5000) -> DumpScan:
    """Read a binary dump and extract structural + string fingerprints."""
    try:
        data = path.read_bytes()
    except Exception:
        return DumpScan(path=path, size_bytes=0)

    sha = hashlib.sha256(data).hexdigest()
    has_mz = data[:2] == b"MZ"
    has_pe = b"PE\x00\x00" in data[:1024]
    nop_runs = sum(1 for _ in re.finditer(rb"\x90{16,}", data))

    ascii_set: set[str] = set()
    for m in _ASCII.findall(data):
        if len(ascii_set) >= max_strings:
            break
        ascii_set.add(m.decode("ascii", errors="ignore"))

    wide_set: set[str] = set()
    for m in _WIDE.findall(data):
        if len(wide_set) >= max_strings:
            break
        try:
            wide_set.add(m.decode("utf-16le", errors="ignore"))
        except Exception:
            continue

    return DumpScan(
        path=path, size_bytes=len(data), sha256=sha,
        ascii_strings=ascii_set, wide_strings=wide_set,
        has_mz_header=has_mz, has_pe_signature=has_pe,
        nop_sled_runs=nop_runs,
    )


def evidence_for_dump(scan: DumpScan, facts: dict | None = None) -> EvidenceItem:
    extra = {
        "dump_size_bytes": scan.size_bytes,
        "dump_sha256": scan.sha256,
        "ascii_string_count": len(scan.ascii_strings),
        "wide_string_count": len(scan.wide_strings),
        "has_mz_header": scan.has_mz_header,
        "has_pe_signature": scan.has_pe_signature,
        "nop_sled_runs": scan.nop_sled_runs,
    }
    if facts:
        extra.update(facts)
    return EvidenceItem(
        tool="el.dump_analysis", version="0.1.0",
        command=f"el.dump_analysis.scan_dump({scan.path.name})",
        output_sha256=scan.sha256 or "0" * 64,
        output_path=str(scan.path),
        extracted_facts=extra,
    )
