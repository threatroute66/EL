"""Skill: mount Apple File System (APFS) containers read-only via
`fsapfsmount` (libfsapfs).

Usage from DiskForensicator: after `mmls` exposes the APFS partition
in an ewfmount'd or losetup'd image, call:

    info = apfs_info(raw, offset_sectors)        # enumerate volumes
    mounts = mount_apfs_ro(raw, offset_sectors,  # FUSE-mount each
                            mount_root, info)
    # mounts[volume_index] -> Path of the FS root

The Data volume (typically index 1, name "Macintosh HD - Data" on
modern BigSur+ images) carries `/Users/`, `/private/var/db/`, the
KnowledgeC.db, FSEvents, Quarantine plists — i.e. everything the
MacOSForensicatorAgent's detectors expect under an exports dir.

Pure subprocess wrapping `fsapfsinfo` + `fsapfsmount` (both in SIFT
defaults, libyal). No Python kernel-module deps.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class ApfsError(RuntimeError):
    """Raised on any failure invoking the fsapfs* tools."""


@dataclass
class ApfsVolume:
    index: int                          # 1-based, matches fsapfsinfo
    identifier: str                     # UUID
    name: str                           # e.g. "Macintosh HD - Data"
    role: str = ""                      # e.g. "Data" / "System" / "Recovery"
    mount_path: Path | None = None      # set by mount_apfs_ro


@dataclass
class ApfsContainerInfo:
    container_uuid: str
    volumes: list[ApfsVolume] = field(default_factory=list)
    raw_text: str = ""

    @property
    def data_volume(self) -> ApfsVolume | None:
        """The user-data volume (where Users/ + KnowledgeC.db live).
        Modern BigSur+ images split System/Data; the Data volume is
        what the analyst wants. Falls back to the largest non-Recovery
        / non-Preboot / non-Update volume."""
        for v in self.volumes:
            n = (v.name or "").lower()
            if n.endswith("- data") or v.role.lower() == "data":
                return v
        for v in self.volumes:
            n = (v.name or "").lower()
            if "recovery" not in n and "preboot" not in n and "update" not in n:
                return v
        return self.volumes[0] if self.volumes else None


_VOLUME_HEADER_RE = re.compile(r"^Volume:\s*(\d+)\s+information:\s*$")
_KV_RE = re.compile(r"^\s+([A-Za-z][A-Za-z _-]*?)\s*:\s+(.+?)\s*$")


def _which_fsapfs() -> tuple[str, str]:
    info = shutil.which("fsapfsinfo")
    mount = shutil.which("fsapfsmount")
    if not info or not mount:
        raise ApfsError("fsapfsinfo / fsapfsmount not on PATH "
                        "(install libfsapfs-tools — SIFT default)")
    return info, mount


def apfs_info(source: str | Path, offset: int = 0,
              timeout: int = 60) -> ApfsContainerInfo:
    """Run `fsapfsinfo -o <bytes>` against the source block device or
    image and parse out the per-volume table.

    `offset` is the byte offset of the APFS container within `source`
    (zero when source is already the carved partition; non-zero when
    source is a multi-partition disk and we're using the offset to
    skip ahead — same semantics as `mmls` slot offsets × sector size)."""
    info_bin, _ = _which_fsapfs()
    cmd = [info_bin]
    if offset:
        cmd += ["-o", str(offset)]
    cmd += [str(source)]
    try:
        r = subprocess.run(cmd, check=False, capture_output=True,
                            text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ApfsError(f"fsapfsinfo failed: {e}") from e
    if r.returncode != 0:
        raise ApfsError(
            f"fsapfsinfo rc={r.returncode}: "
            f"{(r.stderr or '').strip()[-300:]}"
        )

    container_uuid = ""
    volumes: list[ApfsVolume] = []
    current: ApfsVolume | None = None
    for line in (r.stdout or "").splitlines():
        m = _VOLUME_HEADER_RE.match(line)
        if m:
            if current is not None:
                volumes.append(current)
            current = ApfsVolume(index=int(m.group(1)),
                                  identifier="", name="")
            continue
        kv = _KV_RE.match(line)
        if not kv:
            continue
        key, val = kv.group(1).strip().lower(), kv.group(2).strip()
        if current is None:
            if key == "identifier" and not container_uuid:
                container_uuid = val
        else:
            if key == "identifier":
                current.identifier = val
            elif key == "name":
                current.name = val
            elif key == "role" or key == "volume role":
                current.role = val
    if current is not None:
        volumes.append(current)

    return ApfsContainerInfo(container_uuid=container_uuid,
                              volumes=volumes,
                              raw_text=r.stdout or "")


def mount_apfs_ro(source: str | Path, offset: int,
                   mount_root: Path,
                   info: ApfsContainerInfo,
                   timeout: int = 60) -> dict[int, Path]:
    """FUSE-mount every volume in the container under
    `<mount_root>/vol<N>/`. Each is a separate `fsapfsmount`
    invocation because libfsapfs only mounts one volume per call.

    Returns a {volume_index: Path} map. Caller is responsible for
    unmounting via `umount_apfs(mount_paths)` when done — left
    mounted on success so the chained agent can walk the FS.
    """
    _, mount_bin = _which_fsapfs()
    mount_root = Path(mount_root)
    mount_root.mkdir(parents=True, exist_ok=True)
    mounts: dict[int, Path] = {}
    for vol in info.volumes:
        m = mount_root / f"vol{vol.index}"
        m.mkdir(parents=True, exist_ok=True)
        cmd = [mount_bin, "-X", "allow_other",
               "-f", str(vol.index), str(source), str(m)]
        if offset:
            cmd[2:2] = ["-o", str(offset)]
        # `fsapfsmount -X allow_other -f <vol_index> [-o <byte_off>]
        # <source> <mount>` — the `-f` flag selects the volume
        # number (1-based, matches fsapfsinfo's table).
        try:
            r = subprocess.run(cmd, check=False, capture_output=True,
                                text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            continue
        # Some libfsapfs versions return rc=1 even on successful mount
        # because they background-daemonise. Probe the mount point
        # for a child entry to confirm.
        for _ in range(20):
            try:
                if any(m.iterdir()):
                    mounts[vol.index] = m
                    vol.mount_path = m
                    break
            except OSError:
                pass
            time.sleep(0.1)
    if not mounts:
        raise ApfsError("fsapfsmount did not surface any mounted volume")
    return mounts


def umount_apfs(mounts: dict[int, Path] | list[Path] | Path,
                  timeout: int = 30) -> None:
    """Unmount one or many FUSE mounts. Tolerates already-unmounted
    paths."""
    if isinstance(mounts, Path):
        paths = [mounts]
    elif isinstance(mounts, dict):
        paths = list(mounts.values())
    else:
        paths = list(mounts)
    for p in paths:
        for cmd in (["fusermount", "-u", str(p)],
                     ["umount", str(p)]):
            try:
                subprocess.run(cmd, check=False, capture_output=True,
                                timeout=timeout)
                break
            except (OSError, subprocess.TimeoutExpired):
                continue


def is_apfs_available() -> bool:
    return bool(shutil.which("fsapfsinfo")
                 and shutil.which("fsapfsmount"))


__all__ = [
    "ApfsContainerInfo", "ApfsError", "ApfsVolume",
    "apfs_info", "mount_apfs_ro", "umount_apfs", "is_apfs_available",
]
