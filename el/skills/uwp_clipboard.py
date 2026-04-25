"""Skill: parse Windows Cloud-Clipboard / UWP-Clipboard items.

Windows 10 (1809+) introduced Cloud-Clipboard — a multi-device sync
service where copied items survive past a single application
session. Two on-disk locations carry forensic value:

- Pinned items (kept until the user un-pins them):
  ``%LOCALAPPDATA%\\Microsoft\\Windows\\Clipboard\\Pinned\\<GUID>\\``
  Each pin is a directory containing one or more format files
  (``Plain text.txt``, ``HTML Format.txt``, ``image.png``, …) whose
  contents ARE the clipboard data; the directory mtime is when the
  user pinned it.

- Recent items (rolled off after a few days unless pinned):
  ``%LOCALAPPDATA%\\Microsoft\\Windows\\Clipboard\\<GUID>\\<id>\\``
  Same per-format file layout.

Plus the broader UCD store:
- ``%LOCALAPPDATA%\\ConnectedDevicesPlatform\\<account-hash>\\``
  Holds ``ActivitiesCache.db`` (already covered by `el.skills.win_timeline`)
  and the cloud-clipboard sync key store.

This skill walks an extracted clipboard subtree (a copy of the
Windows ``Clipboard`` directory from a user profile) and returns
one ``ClipboardItem`` per format-file-on-disk, capped on read so a
multi-MB image doesn't bloat the ledger.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ClipboardItem:
    pin_dir: Path                      # the per-item GUID subdir
    format_file: Path                  # the actual content file
    user: str                          # which user profile
    pinned: bool                       # under Pinned/?
    format_label: str                  # e.g. "Plain text.txt"
    size: int = 0
    mtime_utc: str = ""
    sample: str = ""                   # first ≤200 chars (text-decodable)


def _utc(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(
            epoch, tz=timezone.utc
        ).isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return ""


def _read_sample(path: Path, max_chars: int = 200) -> str:
    """Best-effort UTF-8 / UTF-16-LE sample of a clipboard format
    file. Returns "" for non-text formats (image / RTF binary).

    Encoding picker:
      1. UTF-16 BOM (FF FE) → UTF-16-LE
      2. ≥25% NUL bytes in the sample → likely UTF-16-LE Latin text
      3. Otherwise UTF-8 (with errors=ignore)

    The straight UTF-16-LE-first path was wrong: ASCII text decodes
    to garbled CJK because every two ASCII bytes form a high-plane
    code point. UTF-8 is the safer default; UTF-16 is the special
    case to detect.
    """
    try:
        raw = path.read_bytes()[:max_chars * 4]
    except OSError:
        return ""
    if not raw:
        return ""
    # Short-circuit: known binary magics → no point decoding.
    # PNG / JPEG / GIF / BMP / RIFF (WebP, AVI) / RTF binary blob /
    # PE (clipboard sometimes carries embedded EXEs in malware cases).
    _BINARY_MAGICS = (
        b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
        b"BM", b"RIFF", b"%PDF", b"PK\x03\x04", b"MZ",
        b"{\\rtf",
    )
    if any(raw.startswith(m) for m in _BINARY_MAGICS):
        return ""
    # Detect encoding
    enc = "utf-8"
    if raw[:2] == b"\xff\xfe":
        enc = "utf-16-le"
        raw = raw[2:]
    elif raw[:2] == b"\xfe\xff":
        enc = "utf-16-be"
        raw = raw[2:]
    elif raw.count(b"\x00") * 4 > len(raw):  # >25% nulls
        enc = "utf-16-le"
    try:
        s = raw.decode(enc, errors="ignore")
    except (UnicodeDecodeError, LookupError):
        return ""
    s = "".join(c for c in s if c.isprintable() or c in " \t\n")
    if not s.strip():
        return ""
    return s[:max_chars]


def parse_clipboard_subtree(root: Path, user: str = "?") -> list[ClipboardItem]:
    """Walk a copied Windows ``Clipboard`` subtree and return every
    format-file as a ``ClipboardItem``. ``root`` is expected to point
    at the ``Clipboard`` dir itself (sibling of ``Pinned/``)."""
    out: list[ClipboardItem] = []
    if not root.is_dir():
        return out
    for pin_dir in sorted(root.rglob("*")):
        if not pin_dir.is_dir():
            continue
        for f in sorted(pin_dir.iterdir()):
            if not f.is_file():
                continue
            try:
                st = f.stat()
            except OSError:
                continue
            pinned = "Pinned" in str(pin_dir.relative_to(root)).split("/")
            out.append(ClipboardItem(
                pin_dir=pin_dir, format_file=f, user=user,
                pinned=pinned, format_label=f.name,
                size=st.st_size, mtime_utc=_utc(st.st_mtime),
                sample=_read_sample(f),
            ))
    return out


def walk_extracted_clipboard(exports_root: Path) -> list[ClipboardItem]:
    """Walk every copied per-user clipboard subtree under
    ``<case_dir>/exports/windows-artifacts/uwp-clipboard/`` and
    aggregate. Each user profile's clipboard is staged under
    ``<user>/Clipboard/`` by `extract_windows_artifacts`."""
    exports_root = Path(exports_root)
    items: list[ClipboardItem] = []
    if not exports_root.is_dir():
        return items
    for user_dir in sorted(exports_root.iterdir()):
        if not user_dir.is_dir():
            continue
        cb_root = user_dir / "Clipboard"
        if cb_root.is_dir():
            items.extend(parse_clipboard_subtree(cb_root, user=user_dir.name))
    items.sort(key=lambda x: (not x.pinned, x.mtime_utc))
    return items


__all__ = [
    "ClipboardItem", "parse_clipboard_subtree", "walk_extracted_clipboard",
]
