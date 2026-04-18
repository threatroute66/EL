"""Skill: exiftool — file metadata extraction.

ExifTool reads metadata from images, Office documents, PDFs, audio,
video. Useful on carved files (foremost output, dumpfiles from vol3,
disk-extracted attachments) for: original author, creation timestamps
(often from a different machine — attribution clue), GPS, camera serial,
PDF producer software, document version history.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


class ExifError(RuntimeError):
    pass


def _bin() -> str:
    p = shutil.which("exiftool")
    if not p:
        raise ExifError("exiftool not on PATH")
    return p


def metadata(target: Path, timeout: int = 60) -> dict:
    """Run exiftool -j on a single file. Returns the metadata dict (or {})."""
    target = Path(target)
    if not target.is_file():
        raise ExifError(f"not a file: {target}")
    cmd = [_bin(), "-j", "-q", "-q", str(target)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise ExifError(f"exiftool timeout") from e
    if proc.returncode != 0 or not proc.stdout:
        return {}
    try:
        data = json.loads(proc.stdout)
        return data[0] if isinstance(data, list) and data else {}
    except json.JSONDecodeError:
        return {}


def metadata_dir(d: Path, max_files: int = 500, timeout: int = 600) -> dict[str, dict]:
    """Bulk metadata extraction. Returns {relative_path: meta_dict}."""
    d = Path(d)
    if not d.is_dir():
        raise ExifError(f"not a dir: {d}")
    cmd = [_bin(), "-j", "-q", "-q", "-r", str(d)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise ExifError(f"exiftool timeout") from e
    if not proc.stdout:
        return {}
    try:
        rows = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    out: dict[str, dict] = {}
    for r in rows[:max_files]:
        path = r.get("SourceFile") or r.get("FileName")
        if path:
            out[path] = r
    return out
