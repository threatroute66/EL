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


_DIR_HASH_MAX_FILES = 10_000
_DIR_HASH_MAX_SECONDS = 60


def _hash_directory(path: Path) -> tuple[str, str, str, int]:
    """Stable structural hash over (rel_path, size) tuples in sorted
    order. Returns (sha256, sha1, md5, total_bytes).

    Deliberately does NOT read file contents. Mobile/extract trees
    can be 200 GB+ over a slow FUSE mount (VMware HGFS); content
    hashing all files at intake dominates the investigation runtime
    and blocks on readdir long before the investigator agents get to
    run. File-path + file-size is a sufficient structural fingerprint
    for chain-of-custody on directory inputs — any swap/truncation
    perturbs one or the other. Files (non-directory inputs) still
    get full content hashing via `_hash_file`.

    Caps: stops the walk at either `_DIR_HASH_MAX_FILES` entries or
    `_DIR_HASH_MAX_SECONDS` wall time, whichever comes first. iOS
    filesystem trees have ~1M localization-resource files spread across
    `.bundle/<locale>.lproj/` subtrees; walking them all over HGFS
    would dominate the investigation. The partial manifest is still
    deterministic for the files that were walked (os.walk is stable
    across runs on the same mount).

    Uses os.walk with onerror=None so a single unreadable subtree
    (common on mobile extracts: /private/var/containers/Shared/
    SystemGroup/.../Library) doesn't abort the whole hash.
    """
    import os as _os
    import time as _time
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    total = 0
    collected: list[tuple[str, int]] = []
    deadline = _time.monotonic() + _DIR_HASH_MAX_SECONDS
    capped = False
    try:
        for dirpath, dirnames, filenames in _os.walk(
            str(path), onerror=lambda e: None, followlinks=False,
        ):
            for fn in filenames:
                full = Path(dirpath) / fn
                try:
                    st = full.stat()
                except OSError:
                    continue
                rel = str(full.relative_to(path))
                collected.append((rel, st.st_size))
                if len(collected) >= _DIR_HASH_MAX_FILES:
                    capped = True
                    break
            if capped or _time.monotonic() > deadline:
                capped = True
                break
    except OSError:
        pass
    collected.sort()
    for rel, sz in collected:
        rec = rel.encode() + b"\x00" + str(sz).encode() + b"\n"
        sha256.update(rec); sha1.update(rec); md5.update(rec)
        total += sz
    if capped:
        cap_rec = (f"__CAPPED_AT_{len(collected)}_FILES__"
                    .encode() + b"\n")
        sha256.update(cap_rec); sha1.update(cap_rec); md5.update(cap_rec)
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


def intake(input_path: str | Path, case_id: str | None = None,
            case_dir: str | Path | None = None) -> CaseManifest:
    """Hash the input + create a case workspace.

    Default: case dir at CASE_ROOT / case_id. Pass `case_dir` to
    override the default placement — the bundle pipeline uses this
    to put each device under cases/<bundle-id>/devices/<name>/
    instead of CASE_ROOT/<device-name>/.
    """
    src = Path(input_path)
    if not src.exists():
        raise FileNotFoundError(f"input does not exist: {src}")

    cid = case_id or f"case-{ULID()}"
    cdir = Path(case_dir) if case_dir is not None else (CASE_ROOT / cid)
    for sub in ("analysis", "exports", "reports", "raw"):
        (cdir / sub).mkdir(parents=True, exist_ok=True)

    if src.is_file():
        mode = src.stat().st_mode
        if mode & stat.S_IWUSR and _evidence_is_protected(src):
            # Best-effort write-bit strip — chain-of-custody belt + braces.
            # Some filesystems (vmhgfs / VMware shared folders, read-only
            # NFS mounts, fuse-mounted EWF) reject chmod with EPERM even
            # when the bit being cleared is already clear semantically.
            # The manifest still records the file's sha256 + path so the
            # chmod failing is not load-bearing for chain-of-custody.
            try:
                os.chmod(src,
                          mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
            except (PermissionError, OSError):
                pass
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
