"""Skill: RecentDocs / OpenSave-MRU registry parser.

Two per-user artifact keys that record file-path activity whose signal
survives Windows Timeline / Jump-List clearing:

  RecentDocs:
    NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\<ext>
    Each <ext> subkey (".docx", ".pdf", …) holds a MRUListEx binary
    value + numbered values (0,1,2,…) each a UTF-16LE NUL-terminated
    filename (+ IDL suffix on Vista+). Captures every file the user
    double-clicked from Explorer, regardless of app.

  OpenSavePidlMRU:
    NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\
    ComDlg32\\OpenSavePidlMRU\\<ext>
    Same shape, but scoped to GetOpenFileName / GetSaveFileName
    common-dialog operations. Typically captures attachments a user
    opened from the file-picker.

Outputs a `RecentDocEntry` per recovered filename with the registry
key's LastWriteTimestamp as the best timestamp available (per-value
timestamps aren't recorded, unlike EVTX).

Pure-function skill using regipy. Suspicious-path marker set matches
BAM/DAM + win_timeline so the three surfaces stay consistent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_RECENTDOCS_KEY = (
    r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
_OPENSAVE_KEY = (
    r"\Software\Microsoft\Windows\CurrentVersion\Explorer"
    r"\ComDlg32\OpenSavePidlMRU")

_USER_WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
    "\\programdata\\", "\\users\\public\\",
    "\\temp\\", "\\downloads\\", "\\recycle.bin\\",
)


@dataclass
class RecentDocEntry:
    source: str                      # "recentdocs" or "opensave"
    extension: str                   # subkey name (".docx", ".pdf", …)
    filename: str                    # decoded filename
    position: int                    # MRU position (0 = most recent)
    last_write_utc: str = ""         # registry key LastWriteTimestamp


def _decode_mru_value(raw: bytes | str) -> str:
    """Values are UTF-16LE NUL-terminated strings with trailing shell
    binary (IDL) on Vista+. Strip at the first NUL pair."""
    if isinstance(raw, str):
        # regipy sometimes returns REG_BINARY as hex. Convert.
        try:
            raw = bytes.fromhex(raw)
        except ValueError:
            return raw            # already a string — keep as-is
    if not isinstance(raw, (bytes, bytearray)):
        return ""
    # Find the first UTF-16 NUL pair
    nul = b"\x00\x00"
    idx = 0
    while idx + 1 < len(raw):
        if raw[idx:idx+2] == nul and idx % 2 == 0:
            break
        idx += 2
    prefix = bytes(raw[:idx])
    try:
        return prefix.decode("utf-16-le", errors="ignore").strip()
    except Exception:
        return ""


def _walk_subtree(hive_path: Path, key_path: str,
                   source_label: str) -> list[RecentDocEntry]:
    try:
        from regipy.registry import RegistryHive
    except ImportError:
        return []
    try:
        hive = RegistryHive(str(hive_path))
    except Exception:
        return []
    try:
        root = hive.get_key(key_path)
    except Exception:
        return []
    entries: list[RecentDocEntry] = []
    for ext_key in _safe_iter_subkeys(root):
        ext = ext_key.name
        last_write = _last_write_utc(ext_key)
        for v in _safe_iter_values(ext_key):
            if not v.name or v.name.lower() in ("mrulistex", "mrulist"):
                continue
            if (v.value_type or "").upper() != "REG_BINARY":
                continue
            fname = _decode_mru_value(v.value)
            if not fname:
                continue
            try:
                pos = int(v.name)
            except ValueError:
                pos = -1
            entries.append(RecentDocEntry(
                source=source_label, extension=ext,
                filename=fname, position=pos,
                last_write_utc=last_write,
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


def _last_write_utc(key) -> str:
    """regipy exposes LastWriteTimestamp either on the key object or
    via header.last_modified. Both map to an ISO-8601 string."""
    raw = getattr(key, "header", None)
    if raw is not None:
        for attr in ("last_modified", "last_write", "timestamp"):
            val = getattr(raw, attr, None)
            if val:
                return str(val)
    for attr in ("last_modified", "timestamp"):
        val = getattr(key, attr, None)
        if val:
            return str(val)
    return ""


def parse_recentdocs(ntuser_path: Path) -> list[RecentDocEntry]:
    """Parse both RecentDocs and OpenSavePidlMRU trees out of a single
    NTUSER.DAT. Silent on regipy-missing or invalid-hive inputs."""
    if not Path(ntuser_path).is_file():
        return []
    out: list[RecentDocEntry] = []
    out.extend(_walk_subtree(ntuser_path, _RECENTDOCS_KEY, "recentdocs"))
    out.extend(_walk_subtree(ntuser_path, _OPENSAVE_KEY, "opensave"))
    return out


def is_suspicious_path(filename: str) -> bool:
    if not filename:
        return False
    lp = filename.lower()
    return any(m in lp for m in _USER_WRITABLE_MARKERS)


@dataclass
class RecentDocsSummary:
    total_entries: int = 0
    per_extension: dict[str, int] = field(default_factory=dict)
    per_source: dict[str, int] = field(default_factory=dict)
    suspicious: list[RecentDocEntry] = field(default_factory=list)


def summarise(entries: list[RecentDocEntry]) -> RecentDocsSummary:
    s = RecentDocsSummary(total_entries=len(entries))
    for e in entries:
        s.per_extension[e.extension] = s.per_extension.get(e.extension, 0) + 1
        s.per_source[e.source] = s.per_source.get(e.source, 0) + 1
        if is_suspicious_path(e.filename):
            s.suspicious.append(e)
    s.suspicious.sort(key=lambda e: e.last_write_utc, reverse=True)
    return s


__all__ = [
    "RecentDocEntry", "RecentDocsSummary",
    "parse_recentdocs", "summarise", "is_suspicious_path",
    "_decode_mru_value",
]
