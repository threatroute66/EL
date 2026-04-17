from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from ulid import ULID

CASE_ROOT = Path("/opt/EL/cases")
CHUNK = 1024 * 1024


@dataclass
class CaseManifest:
    case_id: str
    intake_utc: str
    input_path: str
    input_size_bytes: int
    input_sha256: str
    input_sha1: str
    input_md5: str
    input_magic: str
    case_dir: str


def _hash_file(path: Path) -> tuple[str, str, str]:
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()


def _hash_directory(path: Path) -> tuple[str, str, str, int]:
    """Stable Merkle-style hash over file contents in path-sorted order.
    Returns (sha256, sha1, md5, total_bytes)."""
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    total = 0
    files = sorted(p for p in path.rglob("*") if p.is_file())
    for f in files:
        rel = str(f.relative_to(path)).encode() + b"\x00"
        sha256.update(rel); sha1.update(rel); md5.update(rel)
        try:
            with f.open("rb") as fh:
                while chunk := fh.read(CHUNK):
                    sha256.update(chunk); sha1.update(chunk); md5.update(chunk)
                    total += len(chunk)
        except Exception:
            continue
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), total


def _peek_magic(path: Path, n: int = 16) -> str:
    with path.open("rb") as f:
        return f.read(n).hex()


def _evidence_is_protected(path: Path) -> bool:
    parts = path.resolve().parts
    protected = ("/cases/", "/mnt/", "/media/", "/evidence/")
    p = str(path.resolve())
    return any(seg.strip("/") in parts for seg in protected) or any(
        marker in p for marker in protected
    )


def intake(input_path: str | Path, case_id: str | None = None) -> CaseManifest:
    src = Path(input_path)
    if not src.exists():
        raise FileNotFoundError(f"input does not exist: {src}")

    cid = case_id or f"case-{ULID()}"
    cdir = CASE_ROOT / cid
    for sub in ("analysis", "exports", "reports", "raw"):
        (cdir / sub).mkdir(parents=True, exist_ok=True)

    if src.is_file():
        mode = src.stat().st_mode
        if mode & stat.S_IWUSR and _evidence_is_protected(src):
            os.chmod(src, mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
        sha256, sha1, md5 = _hash_file(src)
        size = src.stat().st_size
        magic = _peek_magic(src)
    elif src.is_dir():
        sha256, sha1, md5, size = _hash_directory(src)
        magic = "directory"
    else:
        raise ValueError(f"input is neither file nor directory: {src}")

    manifest = CaseManifest(
        case_id=cid,
        intake_utc=datetime.now(timezone.utc).isoformat(),
        input_path=str(src.resolve()),
        input_size_bytes=size,
        input_sha256=sha256,
        input_sha1=sha1,
        input_md5=md5,
        input_magic=magic,
        case_dir=str(cdir.resolve()),
    )
    (cdir / "manifest.json").write_text(json.dumps(asdict(manifest), indent=2))
    return manifest
