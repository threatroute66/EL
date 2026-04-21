"""Skill: Background / Desktop Activity Moderator (BAM/DAM) parser.

BAM/DAM is Windows 10 (1709+) and 11's per-user last-run ledger. The
SYSTEM hive stores every executable a user launched and when they
launched it, keyed by the user's SID. Defender and the scheduler use
it for background-task budgeting; for DFIR purposes it's one of the
cleanest "who ran what, when" artifacts available — persistent across
reboots, populated without any opt-in telemetry, and keyed by the exe
path as the user invoked it (so `\\Device\\HarddiskVolume4\\Users\\...
\\AppData\\Local\\Temp\\x.exe` shows up in raw form).

Registry layout differs across Windows builds:
  1709 – 1803: SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings\\<SID>
  1809+ :      SYSTEM\\ControlSet001\\Services\\bam\\UserSettings\\<SID>
and separate `dam\\` subtree on some builds.

Each <SID> key has:
  - A few metadata REG_DWORDs (Version, SequenceNumber) we skip.
  - Everything else: ValueName is the executable path, ValueData is
    REG_BINARY whose first 8 bytes are the FILETIME last-run.

Pure-function skill built on regipy (MIT, pure Python). No subprocess.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class BamEntry:
    sid: str
    executable: str
    last_run_utc: str       # ISO-8601
    source_key: str         # which subtree we saw it in


# Metadata value names we skip when iterating a user's subkey
_METADATA_VALUE_NAMES = frozenset({
    "Version", "SequenceNumber",
})

# Candidate registry paths to probe, in order. Both BAM and DAM live at
# the same shape so we try each with and without the "State" level.
_SUBTREES: tuple[tuple[str, str], ...] = (
    ("bam", r"\ControlSet001\Services\bam\UserSettings"),
    ("bam", r"\ControlSet001\Services\bam\State\UserSettings"),
    ("dam", r"\ControlSet001\Services\dam\UserSettings"),
    ("dam", r"\ControlSet001\Services\dam\State\UserSettings"),
    # Some recovered hives are exposed as ControlSet002; try that too
    ("bam", r"\ControlSet002\Services\bam\UserSettings"),
    ("bam", r"\ControlSet002\Services\bam\State\UserSettings"),
)


def _filetime_to_iso(raw: bytes | str) -> str:
    """First 8 bytes of the REG_BINARY are the FILETIME (100-ns ticks
    since 1601-01-01 UTC). regipy sometimes hands us the buffer as a
    hex string; accept both."""
    if isinstance(raw, str):
        try:
            raw = bytes.fromhex(raw)
        except ValueError:
            return ""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
        return ""
    ft = struct.unpack("<Q", bytes(raw[:8]))[0]
    if ft == 0:
        return ""
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) \
             + timedelta(microseconds=ft / 10)
        return dt.isoformat()
    except OverflowError:
        return ""


def parse_system_hive(system_hive: Path) -> list[BamEntry]:
    """Walk every known BAM/DAM subtree in the SYSTEM hive, return
    BamEntry rows. Uses regipy — import is local so callers that
    never invoke this don't pay the import cost."""
    try:
        from regipy.registry import RegistryHive
    except ImportError:
        return []

    p = Path(system_hive)
    if not p.is_file():
        return []
    try:
        hive = RegistryHive(str(p))
    except Exception:
        return []

    entries: list[BamEntry] = []
    for subtree_kind, root_path in _SUBTREES:
        try:
            root = hive.get_key(root_path)
        except Exception:
            continue
        for sid_key in _safe_iter_subkeys(root):
            sid = sid_key.name
            # Skip the metadata subkeys that sometimes appear at this
            # level on older builds (ShipOverride, RebootCountdown, etc.)
            if not sid.startswith("S-1-"):
                continue
            for value in _safe_iter_values(sid_key):
                if value.name in _METADATA_VALUE_NAMES:
                    continue
                if (value.value_type or "").upper() != "REG_BINARY":
                    continue
                iso = _filetime_to_iso(value.value)
                if not iso:
                    continue
                entries.append(BamEntry(
                    sid=sid,
                    executable=value.name,
                    last_run_utc=iso,
                    source_key=f"{subtree_kind}:{root_path}",
                ))
    return entries


def _safe_iter_subkeys(key):
    try:
        return list(key.iter_subkeys())
    except Exception:
        return []


def _safe_iter_values(key):
    try:
        return list(key.iter_values())
    except Exception:
        return []


# --- Suspicion scoring ---------------------------------------------------

_USER_WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\recycle.bin\\",
)


def is_suspicious_path(executable: str) -> bool:
    """Same heuristic as `execution_corroboration.is_user_writable_path`,
    applied directly to a BAM value-name since BAM captures the
    invocation path verbatim.

    Kept per-skill rather than shared so the two surfaces can drift
    without coupling — BAM sees the attacker-invocation path, while
    execution_corroboration sees what shimcache / amcache recorded.
    """
    lp = (executable or "").lower()
    return any(m in lp for m in _USER_WRITABLE_MARKERS)


@dataclass
class BamSummary:
    total_entries: int = 0
    per_sid: dict[str, int] = field(default_factory=dict)
    suspicious: list[BamEntry] = field(default_factory=list)


def summarise(entries: list[BamEntry]) -> BamSummary:
    s = BamSummary(total_entries=len(entries))
    for e in entries:
        s.per_sid[e.sid] = s.per_sid.get(e.sid, 0) + 1
        if is_suspicious_path(e.executable):
            s.suspicious.append(e)
    # Sort suspicious newest-first so the top N in any finding are the
    # most-recently-run suspicious paths.
    s.suspicious.sort(key=lambda e: e.last_run_utc, reverse=True)
    return s


__all__ = [
    "BamEntry", "BamSummary",
    "parse_system_hive", "summarise", "is_suspicious_path",
]
