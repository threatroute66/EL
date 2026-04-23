"""Skill: detect file extension vs. actual magic-byte MIME type mismatch.

Extension mangling is the user-illicit-activity anti-forensic move that
BelkaCTF Kidnapper surfaced — Ivan renamed PDFs (and other content) to
`.txt` so they would not catch the eye of the investigator. The fix is
to compare the file's declared extension against what `file(1)` says its
MIME type actually is.

Implementation uses the `file` CLI directly (zero new pip deps —
`file` is pre-installed on SIFT / Ubuntu). A `python-magic` wrapper
would also work, but adds a dependency for no gain here.

Emits a hit only for a curated allow-list of MIME families (office,
archives, PDFs, executables, media) — that keeps the detector quiet on
the many legitimate files whose `file` output is ambiguous
(`application/octet-stream` / `text/plain`).
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class MagicError(RuntimeError):
    pass


# MIME family → (canonical extensions for that MIME). If the file's
# extension is outside the set, we raise a hit.
_MIME_FAMILY_EXTS: dict[str, frozenset[str]] = {
    "application/pdf": frozenset({".pdf"}),
    "application/zip": frozenset({".zip", ".odt", ".ods", ".odp",
                                    ".docx", ".xlsx", ".pptx",
                                    ".jar", ".apk", ".ipa"}),
    "application/x-rar": frozenset({".rar"}),
    "application/x-7z-compressed": frozenset({".7z"}),
    "application/x-tar": frozenset({".tar"}),
    "application/gzip": frozenset({".gz", ".tgz"}),
    "application/x-bzip2": frozenset({".bz2", ".tbz2"}),
    "application/x-xz": frozenset({".xz"}),
    "application/x-dosexec": frozenset({".exe", ".dll", ".scr", ".com"}),
    "application/x-mach-binary": frozenset({".bin", ".o", ".dylib", ""}),
    "application/x-executable": frozenset({".elf", ".bin", ""}),
    "application/x-sharedlib": frozenset({".so"}),
    "image/jpeg": frozenset({".jpg", ".jpeg"}),
    "image/png": frozenset({".png"}),
    "image/gif": frozenset({".gif"}),
    "image/bmp": frozenset({".bmp"}),
    "image/webp": frozenset({".webp"}),
    "image/tiff": frozenset({".tif", ".tiff"}),
    "audio/x-wav": frozenset({".wav"}),
    "audio/mpeg": frozenset({".mp3"}),
    "audio/flac": frozenset({".flac"}),
    "audio/ogg": frozenset({".ogg", ".oga"}),
    "video/mp4": frozenset({".mp4", ".m4v"}),
    "video/x-matroska": frozenset({".mkv"}),
    "video/quicktime": frozenset({".mov"}),
    "application/vnd.ms-excel": frozenset({".xls"}),
    "application/msword": frozenset({".doc"}),
    "application/vnd.ms-powerpoint": frozenset({".ppt"}),
    "application/vnd.sqlite3": frozenset({".sqlite", ".sqlite3", ".db", ".db3"}),
    "application/x-sqlite3": frozenset({".sqlite", ".sqlite3", ".db", ".db3"}),
}


@dataclass
class MismatchHit:
    path: Path
    declared_ext: str
    detected_mime: str
    detected_ext_family: tuple[str, ...] = field(default_factory=tuple)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        try:
            sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        except OSError:
            sha = "0" * 64
        f = {"path": str(self.path),
             "declared_ext": self.declared_ext,
             "detected_mime": self.detected_mime,
             "expected_exts": list(self.detected_ext_family)}
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="file(1)", version=_file_version(),
            command=f"file --mime-type {self.path.name}",
            output_sha256=sha, output_path=str(self.path),
            extracted_facts=f,
        )


def _which_file() -> str:
    p = shutil.which("file")
    if not p:
        raise MagicError("`file` CLI not on PATH")
    return p


def _file_version() -> str:
    try:
        r = subprocess.run([_which_file(), "--version"],
                            capture_output=True, text=True, check=False)
        return (r.stdout or r.stderr).splitlines()[0] if (r.stdout or r.stderr) else "unknown"
    except Exception:
        return "unknown"


def _mime_of(path: Path) -> str | None:
    try:
        r = subprocess.run([_which_file(), "--mime-type", "-b", str(path)],
                            capture_output=True, text=True, check=False, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0:
        return None
    return (r.stdout or "").strip().lower() or None


def scan_file(path: Path) -> MismatchHit | None:
    mime = _mime_of(path)
    if not mime:
        return None
    family = _MIME_FAMILY_EXTS.get(mime)
    if family is None:
        return None
    declared = path.suffix.lower()
    if declared in family:
        return None
    return MismatchHit(
        path=path, declared_ext=declared or "<no ext>",
        detected_mime=mime, detected_ext_family=tuple(sorted(family)),
    )


def walk(root: Path, max_files: int = 2000) -> list[MismatchHit]:
    """Walk *root* and emit a hit per declared-vs-detected mismatch."""
    hits: list[MismatchHit] = []
    scanned = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        scanned += 1
        if scanned > max_files:
            break
        h = scan_file(p)
        if h is not None:
            hits.append(h)
    return hits
