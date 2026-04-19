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


def _child_ci(parent: Path, name: str) -> Path | None:
    """Case-insensitive child lookup. NTFS images preserve the case that
    Windows wrote (XP wrote `WINDOWS/`, Win7+ writes `Windows/`), and
    Linux NTFS-3g exposes that literal case. Python `Path / "Windows"` is
    case-sensitive on Linux, so we iterdir and match by lowercase name.
    Returns the actual Path (preserving real case) or None.
    """
    if not parent.is_dir():
        return None
    target = name.lower()
    try:
        for entry in parent.iterdir():
            if entry.name.lower() == target:
                return entry
    except (PermissionError, OSError):
        return None
    return None


def _resolve_ci(root: Path, *segments: str) -> Path | None:
    """Walk a path case-insensitively. Returns the resolved path (preserving
    the filesystem's actual case) or None if any segment is missing."""
    cur = root
    for seg in segments:
        cur = _child_ci(cur, seg)
        if cur is None:
            return None
    return cur


def extract_windows_artifacts(mount_point: Path, exports_dir: Path) -> dict:
    """Copy known Windows forensic artifacts from a read-only NTFS mount
    into a structured exports directory ready for WindowsArtifactAgent.

    Handles XP (`WINDOWS/`, `Documents and Settings/`, classic `.evt`) and
    Vista+/Win7/10/11 (`Windows/`, `Users/`, `.evtx`) layouts via
    case-insensitive path resolution. Artifacts that only exist on post-XP
    Windows (Amcache.hve, SRUDB.dat) are probed and silently skipped when
    absent rather than short-circuiting the whole extraction.

    Returns a dict of artifact_class → count for the caller to summarise.
    """
    out: dict[str, int] = {}
    reg_dir = exports_dir / "registry"

    # Find the Windows root: XP-style WINDOWS, modern Windows, or NT4/2000 winnt.
    win_root = (_child_ci(mount_point, "Windows")
                or _child_ci(mount_point, "WINNT"))
    sys32 = _child_ci(win_root, "System32") if win_root else None

    # Registry hives — <win>/System32/config/{SYSTEM,SOFTWARE,SECURITY,SAM,DEFAULT}
    config = _child_ci(sys32, "config") if sys32 else None
    if config and config.is_dir():
        reg_dir.mkdir(parents=True, exist_ok=True)
        for hive_name in ("SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"):
            src = _child_ci(config, hive_name)
            if src and src.is_file():
                _sudo_cp(src, reg_dir / hive_name)
        out["registry_hives"] = sum(1 for _ in reg_dir.iterdir() if _.is_file())

    # Amcache.hve — Win7+ only, lives at <win>/AppCompat/Programs/Amcache.hve
    amcache = _resolve_ci(win_root, "AppCompat", "Programs", "Amcache.hve") if win_root else None
    if amcache and amcache.is_file():
        reg_dir.mkdir(parents=True, exist_ok=True)
        if _sudo_cp(amcache, reg_dir / "Amcache.hve"):
            out["amcache"] = 1

    # Prefetch — <win>/Prefetch/*.pf (both XP and post-XP, disabled by default on servers)
    pf_src = _child_ci(win_root, "Prefetch") if win_root else None
    if pf_src and pf_src.is_dir():
        pf_dir = exports_dir / "Prefetch"
        pf_dir.mkdir(parents=True, exist_ok=True)
        for pf in pf_src.iterdir():
            if pf.is_file() and pf.suffix.lower() == ".pf":
                _sudo_cp(pf, pf_dir / pf.name)
        out["prefetch_files"] = sum(1 for p in pf_dir.iterdir() if p.suffix.lower() == ".pf")

    # Event logs:
    #   XP/2003: <win>/system32/config/{AppEvent,SecEvent,SysEvent}.Evt  (classic)
    #   Vista+ : <win>/System32/winevt/Logs/*.evtx
    # Keep them in separate dirs so the downstream parser can pick the
    # right tool (EvtxECmd for .evtx; evtparser/python-evtx for .evt).
    ev_modern = _resolve_ci(sys32, "winevt", "Logs") if sys32 else None
    if ev_modern and ev_modern.is_dir():
        ev_dir = exports_dir / "evtx"
        ev_dir.mkdir(parents=True, exist_ok=True)
        for ev in ev_modern.iterdir():
            if ev.is_file() and ev.suffix.lower() == ".evtx":
                _sudo_cp(ev, ev_dir / ev.name)
        out["evtx_files"] = sum(1 for p in ev_dir.iterdir() if p.suffix.lower() == ".evtx")
    if config and config.is_dir():
        evt_dir = exports_dir / "evt"
        copied = 0
        for ev in config.iterdir():
            if ev.is_file() and ev.suffix.lower() == ".evt":
                evt_dir.mkdir(parents=True, exist_ok=True)
                if _sudo_cp(ev, evt_dir / ev.name):
                    copied += 1
        if copied:
            out["evt_files"] = copied

    # SRUM — Win8+ only, at <win>/System32/sru/SRUDB.dat
    srudb = _resolve_ci(sys32, "sru", "SRUDB.dat") if sys32 else None
    if srudb and srudb.is_file():
        srum_dir = exports_dir / "srum"
        srum_dir.mkdir(parents=True, exist_ok=True)
        if _sudo_cp(srudb, srum_dir / "SRUDB.dat"):
            out["srum"] = 1

    # Per-user artifacts: NTUSER.DAT + Outlook PSTs + Firefox profiles.
    # Profile root:
    #   XP/2003: <mount>/Documents and Settings/<name>/...
    #   Vista+ : <mount>/Users/<name>/...
    # Outlook PST search paths (case-insensitive):
    #   XP    : <user>/Local Settings/Application Data/Microsoft/Outlook/*.pst
    #   Win7+ : <user>/AppData/Local/Microsoft/Outlook/*.pst
    #           <user>/Documents/Outlook Files/*.pst
    # Firefox profile search paths:
    #   XP    : <user>/Application Data/Mozilla/Firefox/Profiles/<prof>/places.sqlite
    #   Win7+ : <user>/AppData/Roaming/Mozilla/Firefox/Profiles/<prof>/places.sqlite
    users_root = (_child_ci(mount_point, "Users")
                  or _child_ci(mount_point, "Documents and Settings"))
    skip_profiles = {"all users", "default", "default user", "public",
                     "localservice", "networkservice", "systemprofile"}
    if users_root and users_root.is_dir():
        reg_dir.mkdir(parents=True, exist_ok=True)
        pst_dir = exports_dir / "mail"
        firefox_dir = exports_dir / "browser" / "firefox"
        n_ntuser = 0
        n_pst = 0
        n_firefox = 0
        for user_dir in users_root.iterdir():
            if not user_dir.is_dir():
                continue
            if user_dir.name.lower() in skip_profiles:
                continue
            ntuser = _child_ci(user_dir, "NTUSER.DAT")
            if ntuser and ntuser.is_file():
                if _sudo_cp(ntuser, reg_dir / f"NTUSER-{user_dir.name}.DAT"):
                    n_ntuser += 1
            # PST hunt — try each of the three known Outlook data paths
            outlook_dirs = [
                _resolve_ci(user_dir, "Local Settings", "Application Data",
                            "Microsoft", "Outlook"),
                _resolve_ci(user_dir, "AppData", "Local", "Microsoft", "Outlook"),
                _resolve_ci(user_dir, "Documents", "Outlook Files"),
            ]
            for od in outlook_dirs:
                if not (od and od.is_dir()):
                    continue
                for item in od.iterdir():
                    if not item.is_file():
                        continue
                    if item.suffix.lower() not in (".pst", ".ost"):
                        continue
                    pst_dir.mkdir(parents=True, exist_ok=True)
                    dst = pst_dir / f"{user_dir.name}--{item.name}"
                    if _sudo_cp(item, dst):
                        n_pst += 1
            # Firefox Profiles/*/places.sqlite hunt
            ff_root_candidates = [
                _resolve_ci(user_dir, "Application Data", "Mozilla",
                            "Firefox", "Profiles"),
                _resolve_ci(user_dir, "AppData", "Roaming", "Mozilla",
                            "Firefox", "Profiles"),
            ]
            for ff_root in ff_root_candidates:
                if not (ff_root and ff_root.is_dir()):
                    continue
                for prof in ff_root.iterdir():
                    if not prof.is_dir():
                        continue
                    places = _child_ci(prof, "places.sqlite")
                    if places and places.is_file():
                        dst_dir = firefox_dir / f"{user_dir.name}--{prof.name}"
                        dst_dir.mkdir(parents=True, exist_ok=True)
                        if _sudo_cp(places, dst_dir / "places.sqlite"):
                            n_firefox += 1
        if n_ntuser:
            out["ntuser_hives"] = n_ntuser
        if n_pst:
            out["outlook_pst"] = n_pst
        if n_firefox:
            out["firefox_profiles"] = n_firefox

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
