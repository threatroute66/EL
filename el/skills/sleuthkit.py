"""Skill: Sleuth Kit wrapper.

Subprocess wrappers for fls, mactime, mmls. Each function captures stdout
to disk, hashes the output, and returns an EvidenceItem-compatible record.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem


class SleuthkitError(RuntimeError):
    pass


@dataclass
class TskRun:
    tool: str
    image: Path
    rc: int
    stdout_path: Path
    stderr_path: Path
    command: list[str]

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = hashlib.sha256(self.stdout_path.read_bytes()).hexdigest()
        return EvidenceItem(
            tool=f"sleuthkit/{self.tool}", version=_version(self.tool),
            command=" ".join(self.command),
            output_sha256=sha, output_path=str(self.stdout_path),
            extracted_facts={"rc": self.rc, **(facts or {})},
        )


def _which(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        raise SleuthkitError(f"{tool} not on PATH")
    return p


def _version(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        return "unknown"
    try:
        r = subprocess.run([p, "-V"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "present"
    except Exception:
        return "present"


def _run(tool: str, image: Path, args: list[str], out_dir: Path, label: str, timeout: int) -> TskRun:
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"{label}.txt"
    stderr_path = out_dir / f"{label}.stderr"
    cmd = [_which(tool), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise SleuthkitError(f"timeout running {tool}") from e
    stdout_path.write_text(proc.stdout or "")
    stderr_path.write_text(proc.stderr or "")
    return TskRun(tool=tool, image=image, rc=proc.returncode,
                  stdout_path=stdout_path, stderr_path=stderr_path, command=cmd)


def mmls(image: Path, out_dir: Path, timeout: int = 120) -> TskRun:
    return _run("mmls", image, [str(image)], out_dir, "mmls", timeout)


def fls(image: Path, out_dir: Path, offset: int | None = None,
        recursive: bool = True, timeout: int = 1800) -> TskRun:
    args: list[str] = []
    if offset is not None:
        args += ["-o", str(offset)]
    if recursive:
        args += ["-r"]
    args += ["-m", "/", str(image)]  # mactime body output
    return _run("fls", image, args, out_dir, f"fls{('_o'+str(offset)) if offset else ''}", timeout)


def mactime(body_file: Path, out_dir: Path, timeout: int = 600) -> TskRun:
    """SKILL: always pass -z UTC. Default is local tz which corrupts cross-tz analysis."""
    args = ["-d", "-z", "UTC", "-b", str(body_file)]  # -d csv, -z tz, -b body
    return _run("mactime", body_file, args, out_dir, "mactime", timeout)


def ewfinfo(image: Path, out_dir: Path, timeout: int = 60) -> TskRun:
    """SKILL: surfaces acquisition MD5/SHA1 + metadata; record in case notes."""
    return _run("ewfinfo", image, [str(image)], out_dir, "ewfinfo", timeout)


def ewfverify(image: Path, out_dir: Path, timeout: int = 7200) -> TskRun:
    """SKILL: must complete without errors before any analysis proceeds."""
    return _run("ewfverify", image, [str(image)], out_dir, "ewfverify", timeout)


def img_stat(image: Path, out_dir: Path, timeout: int = 60) -> TskRun:
    """SKILL: catches 4K-sector drives. Wrong sector size = wrong byte offset."""
    return _run("img_stat", image, [str(image)], out_dir, "img_stat", timeout)


def fsstat(image: Path, out_dir: Path, offset: int | None = None,
           timeout: int = 120) -> TskRun:
    args: list[str] = []
    if offset is not None:
        args += ["-o", str(offset)]
    args += [str(image)]
    return _run("fsstat", image, args, out_dir, "fsstat", timeout)


def ewfmount(image: Path, mount_point: Path, timeout: int = 60) -> Path:
    """Mount an E01/EWF image to expose the raw disk stream.

    Per sleuthkit SKILL: ewfmount creates a raw device file (typically named
    'ewf1') inside the mount point. For multi-segment images, point this at
    the first segment only — ewfmount auto-joins the rest.

    Requires sudo. Returns the path to the raw device.
    Caller is responsible for unmount via ewfumount().
    """
    mount_point.mkdir(parents=True, exist_ok=True)
    # -X allow_other lets the unprivileged user read the FUSE-exposed raw
    # device. Requires `user_allow_other` in /etc/fuse.conf (install.sh
    # ensures this). Without it, non-root processes get ENOENT trying to
    # access the mount even when permissions look right.
    cmd = ["sudo", "ewfmount", "-X", "allow_other", str(image), str(mount_point)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SleuthkitError(f"ewfmount timeout: {e}") from e
    if proc.returncode != 0:
        raise SleuthkitError(f"ewfmount failed (rc={proc.returncode}): {proc.stderr or proc.stdout}")
    raw = mount_point / "ewf1"
    if not raw.exists():
        existing = list(mount_point.iterdir())
        raise SleuthkitError(f"ewfmount succeeded but no ewf1 device found; got: {existing}")
    return raw


def mount_ntfs(raw_image: Path, offset_sectors: int, mount_point: Path,
               sector_size: int = 512, timeout: int = 60) -> None:
    """Read-only loopback-mount an NTFS partition from a raw disk stream.

    Per sleuthkit SKILL: always pass ro,loop,offset,norecovery. norecovery
    prevents NTFS journal replay (which would alter the on-disk state).
    Requires sudo and ntfs-3g (present on SIFT).
    """
    mount_point.mkdir(parents=True, exist_ok=True)
    offset_bytes = offset_sectors * sector_size
    cmd = ["sudo", "mount", "-o",
           f"ro,loop,offset={offset_bytes},norecovery",
           str(raw_image), str(mount_point)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SleuthkitError(f"mount timeout: {e}") from e
    if proc.returncode != 0:
        raise SleuthkitError(f"NTFS mount failed (rc={proc.returncode}): "
                             f"{(proc.stderr or proc.stdout).strip()[:300]}")


def umount(mount_point: Path, timeout: int = 30) -> None:
    """Unmount a kernel mount + clean up empty mount-point dir.
    Idempotent — silent on already-unmounted."""
    try:
        subprocess.run(["sudo", "umount", str(mount_point)],
                       capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    try:
        if mount_point.exists() and not any(mount_point.iterdir()):
            mount_point.rmdir()
    except Exception:
        pass


def _sudo_cp(src: Path, dst: Path) -> bool:
    """Copy a file from a root-owned mount + chown back to current user.
    Returns True on success, False otherwise. Silent on failure (caller
    decides what to emit)."""
    import os
    try:
        r1 = subprocess.run(["sudo", "cp", "--preserve=timestamps",
                             str(src), str(dst)],
                            capture_output=True, text=True, timeout=120)
        if r1.returncode != 0:
            return False
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}",
                        str(dst)], capture_output=True, text=True, timeout=30)
        return True
    except Exception:
        return False


def extract_windows_artifacts(mount_point: Path, exports_dir: Path) -> dict:
    """Copy known Windows forensic artifacts from a read-only NTFS mount
    into a structured exports directory ready for WindowsArtifactAgent.

    Returns a dict of artifact_class → count for the caller to summarise.
    """
    out: dict[str, int] = {}

    # Registry hives — Windows/System32/config/
    config = mount_point / "Windows" / "System32" / "config"
    if config.is_dir():
        reg_dir = exports_dir / "registry"
        reg_dir.mkdir(parents=True, exist_ok=True)
        for hive_name in ("SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"):
            src = config / hive_name
            if src.is_file() and _sudo_cp(src, reg_dir / hive_name):
                pass
        out["registry_hives"] = sum(1 for _ in reg_dir.iterdir() if _.is_file())

    # Amcache.hve — Windows/AppCompat/Programs/
    amcache = mount_point / "Windows" / "AppCompat" / "Programs" / "Amcache.hve"
    if amcache.is_file():
        reg_dir = exports_dir / "registry"
        reg_dir.mkdir(parents=True, exist_ok=True)
        if _sudo_cp(amcache, reg_dir / "Amcache.hve"):
            out["amcache"] = 1

    # Prefetch — Windows/Prefetch/*.pf
    pf_src = mount_point / "Windows" / "Prefetch"
    if pf_src.is_dir():
        pf_dir = exports_dir / "Prefetch"
        pf_dir.mkdir(parents=True, exist_ok=True)
        for pf in pf_src.glob("*.pf"):
            _sudo_cp(pf, pf_dir / pf.name)
        out["prefetch_files"] = sum(1 for _ in pf_dir.glob("*.pf"))

    # EVTX — Windows/System32/winevt/Logs/*.evtx
    ev_src = mount_point / "Windows" / "System32" / "winevt" / "Logs"
    if ev_src.is_dir():
        ev_dir = exports_dir / "evtx"
        ev_dir.mkdir(parents=True, exist_ok=True)
        for ev in ev_src.glob("*.evtx"):
            _sudo_cp(ev, ev_dir / ev.name)
        out["evtx_files"] = sum(1 for _ in ev_dir.glob("*.evtx"))

    # SRUM — Windows/System32/sru/SRUDB.dat
    srudb = mount_point / "Windows" / "System32" / "sru" / "SRUDB.dat"
    if srudb.is_file():
        srum_dir = exports_dir / "srum"
        srum_dir.mkdir(parents=True, exist_ok=True)
        if _sudo_cp(srudb, srum_dir / "SRUDB.dat"):
            out["srum"] = 1

    # Per-user NTUSER.DAT — Users/<name>/NTUSER.DAT
    users_dir = mount_point / "Users"
    if users_dir.is_dir():
        ntuser_dir = exports_dir / "registry"
        ntuser_dir.mkdir(parents=True, exist_ok=True)
        n = 0
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            if user_dir.name in ("All Users", "Default", "Default User", "Public"):
                continue
            ntuser = user_dir / "NTUSER.DAT"
            if ntuser.is_file():
                if _sudo_cp(ntuser, ntuser_dir / f"NTUSER-{user_dir.name}.DAT"):
                    n += 1
        if n:
            out["ntuser_hives"] = n

    return out


def ewfumount(mount_point: Path, timeout: int = 30) -> None:
    """Unmount an ewfmount-mounted image. Idempotent — silent on already-unmounted.
    Also removes the (now-empty) mount directory."""
    cmd = ["sudo", "fusermount", "-u", str(mount_point)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    try:
        if mount_point.exists() and not any(mount_point.iterdir()):
            mount_point.rmdir()
    except Exception:
        pass


def parse_mmls(mmls_output: str) -> list[dict]:
    """Parse mmls stdout into list of {slot, start, end, length, description}.
    Skips meta/unallocated rows. Returns dicts with int byte_offset assuming
    512-byte sectors (caller should adjust for 4K via img_stat)."""
    rows: list[dict] = []
    for line in mmls_output.splitlines():
        line = line.strip()
        if not line or line.startswith("DOS Partition") or line.startswith("Units") \
                or line.startswith("GPT Partition") or line.startswith("Slot") \
                or line.startswith("Sector Size") or line.startswith("---"):
            continue
        parts = line.split(maxsplit=5)
        if len(parts) < 6:
            continue
        slot, start, end, length = parts[1], parts[2], parts[3], parts[4]
        desc = parts[5]
        if "Unallocated" in desc or "Meta" in desc or "Primary Table" in desc:
            continue
        try:
            start_sector = int(start)
        except ValueError:
            continue
        rows.append({"slot": slot, "start_sector": start_sector,
                     "end_sector": int(end) if end.isdigit() else 0,
                     "length_sectors": int(length) if length.isdigit() else 0,
                     "description": desc})
    return rows


def tsk_recover(image: Path, out_subdir: Path, mode: str = "alloc",
                offset: int | None = None, timeout: int = 7200) -> TskRun:
    """SKILL: -a allocated only (default), -e everything (incl. unallocated)."""
    args: list[str] = []
    if mode == "all":
        args += ["-e"]
    elif mode == "alloc":
        args += ["-a"]
    if offset is not None:
        args += ["-o", str(offset)]
    args += [str(image), str(out_subdir)]
    out_subdir.mkdir(parents=True, exist_ok=True)
    return _run("tsk_recover", image, args, out_subdir.parent, f"tsk_recover_{mode}", timeout)
