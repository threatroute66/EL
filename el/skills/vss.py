"""Skill: enumerate Volume Shadow Copies via libvshadow's `vshadowinfo`.

Windows VSS snapshots are first-class forensic anchors: each preserves
a point-in-time view of the disk, including registry hives, EVTXs, and
user files that may have been modified or deleted between then and
acquisition. SIFT ships `vshadowinfo` + `vshadowmount` (libvshadow,
SIFT default) that read the VSS metadata directly off an ewfmounted
or losetup'd raw image without booting Windows.

This skill calls `vshadowinfo` and parses the per-store output into a
list of ``ShadowStore`` records — creation timestamp, identifier, and
volume-size — that the analyst can pivot on. Mounting each store via
`vshadowmount` and re-running the disk pipeline against the snapshot
is a future enhancement.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


class VssError(RuntimeError):
    pass


@dataclass
class ShadowStore:
    index: int                          # 1-based position in the volume
    identifier: str = ""                # GUID
    set_identifier: str = ""            # GUID of the snapshot set
    creation_time_utc: str = ""
    volume_size_bytes: int = 0
    raw_block: str = ""                 # the full vshadowinfo block


_SECTION_RE = re.compile(r"^Store:\s*(\d+)\s*$")
_KV_RE = re.compile(r"^\s+([A-Za-z][A-Za-z _-]*?)\s*:\s+(.+?)\s*$")


def _vshadowinfo() -> str:
    p = shutil.which("vshadowinfo")
    if not p:
        raise VssError("vshadowinfo not on PATH (libvshadow-tools)")
    return p


def list_shadows(source: str | Path, *, offset: int = 0,
                  timeout: int = 60) -> list[ShadowStore]:
    """Run `vshadowinfo [-o <bytes>] <source>` and parse the output.
    Empty list when there are no VSS snapshots — `vshadowinfo` prints
    "No Volume Shadow Snapshots Found" and exits 0 in that case."""
    cmd = [_vshadowinfo()]
    if offset:
        cmd += ["-o", str(offset)]
    cmd += [str(source)]
    try:
        r = subprocess.run(cmd, check=False, capture_output=True,
                            text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise VssError(f"vshadowinfo invocation failed: {e}") from e
    if r.returncode != 0 and "No Volume Shadow" not in (r.stderr + r.stdout):
        raise VssError(
            f"vshadowinfo rc={r.returncode}: "
            f"{(r.stderr or '').strip()[-300:]}"
        )
    return _parse(r.stdout or "")


def _parse(text: str) -> list[ShadowStore]:
    stores: list[ShadowStore] = []
    current: ShadowStore | None = None
    block_lines: list[str] = []
    for line in text.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            if current is not None:
                current.raw_block = "\n".join(block_lines)
                stores.append(current)
            current = ShadowStore(index=int(m.group(1)))
            block_lines = [line]
            continue
        if current is None:
            continue
        block_lines.append(line)
        kv = _KV_RE.match(line)
        if not kv:
            continue
        key, val = kv.group(1).strip().lower(), kv.group(2).strip()
        if key == "identifier":
            current.identifier = val
        elif key in ("set identifier", "set-identifier"):
            current.set_identifier = val
        elif key in ("creation time", "creation_time"):
            # vshadowinfo emits e.g. "Apr 25, 2026 12:34:56.789012 UTC"
            current.creation_time_utc = val
        elif key in ("volume size", "volume_size"):
            # Format: "65536 MiB (68719476736 bytes)"
            mb = re.search(r"\((\d+)\s+bytes\)", val)
            if mb:
                current.volume_size_bytes = int(mb.group(1))
    if current is not None:
        current.raw_block = "\n".join(block_lines)
        stores.append(current)
    return stores


def is_vss_available() -> bool:
    return bool(shutil.which("vshadowinfo"))


__all__ = [
    "ShadowStore", "VssError",
    "list_shadows", "is_vss_available",
]
