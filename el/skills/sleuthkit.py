"""Skill: Sleuth Kit wrapper.

Subprocess wrappers for fls, mactime, mmls. Each function captures stdout
to disk, hashes the output, and returns an EvidenceItem-compatible record.
"""
from __future__ import annotations

import hashlib
import re
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
        # Capture as bytes — fls on non-Windows filesystems can emit
        # filenames with non-UTF-8 bytes (Latin-1 accented chars,
        # mojibake from broken encodings, etc). Decode with errors=
        # replace when writing the stdout file so the pipeline
        # doesn't crash on a single bad byte.
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise SleuthkitError(f"timeout running {tool}") from e
    stdout_bytes = proc.stdout or b""
    stderr_bytes = proc.stderr or b""
    stdout_path.write_text(stdout_bytes.decode("utf-8", errors="replace"))
    stderr_path.write_text(stderr_bytes.decode("utf-8", errors="replace"))
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


_SPLIT_SEG_RE = re.compile(r"\.(\d{3,})$")


def is_split_raw(image: Path) -> bool:
    """True when `image` is the FIRST segment of a split-raw (dd / FTK
    Imager) image — its extension is a numeric segment (``.001`` / ``.000``)
    and the next-numbered sibling exists.

    Why this matters: The Sleuth Kit spans split-raw segments natively
    (``img_stat``/``mmls``/``fls``/``tsk_recover`` given the first segment
    auto-join the rest). But a kernel/ntfs-3g mount and ``bulk_extractor``
    see ONLY the first segment — so on a 30 GB disk split into 1.5 GB pieces,
    NTFS artifact extraction fails ("signature missing" / truncated volume)
    and carving covers ~5% of the disk. The caller bridges via ``affuse``
    first (see :func:`affuse_mount`)."""
    image = Path(image)
    m = _SPLIT_SEG_RE.search(image.name)
    if not m:
        return False
    width = len(m.group(1))
    nxt = str(int(m.group(1)) + 1).zfill(width)
    sibling = image.with_name(image.name[:m.start()] + "." + nxt)
    return sibling.exists()


def affuse_mount(image: Path, mount_point: Path, timeout: int = 120) -> Path:
    """Bridge a split-raw image into ONE contiguous raw stream via affuse
    (AFFLIB). affuse exposes ``<mount_point>/<firstsegment>.raw`` spanning
    ALL segments, so a kernel/ntfs-3g mount + bulk_extractor cover the whole
    disk instead of just the first segment.

    Mounts as the current user with ``allow_other`` so a later
    ``sudo mount_ntfs`` (root) can read the FUSE-exposed stream — mirrors the
    ``ewfmount -X allow_other`` pattern. Returns the unified ``.raw`` path;
    caller unmounts via :func:`affuse_umount`."""
    image = Path(image)
    mount_point = Path(mount_point)
    mount_point.mkdir(parents=True, exist_ok=True)
    cmd = ["affuse", "-o", "allow_other", str(image), str(mount_point)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError as e:
        raise SleuthkitError("affuse not installed (apt install afflib-tools)") from e
    except subprocess.TimeoutExpired as e:
        raise SleuthkitError(f"affuse timeout: {e}") from e
    if proc.returncode != 0:
        raise SleuthkitError(
            f"affuse failed (rc={proc.returncode}): {proc.stderr or proc.stdout}")
    raw = mount_point / (image.name + ".raw")
    if not raw.exists():
        # affuse names the virtual file <firstsegment>.raw; fall back to the
        # single entry it exposed if the naming convention ever differs.
        entries = [p for p in mount_point.iterdir()]
        if len(entries) == 1:
            raw = entries[0]
        else:
            raise SleuthkitError(
                f"affuse succeeded but no unified .raw found; got: {entries}")
    return raw


def affuse_umount(mount_point: Path, timeout: int = 30) -> None:
    """Unmount an affuse FUSE mount + clean up the empty dir. Idempotent."""
    try:
        subprocess.run(["fusermount", "-u", str(mount_point)],
                       capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    try:
        if mount_point.exists() and not any(mount_point.iterdir()):
            mount_point.rmdir()
    except Exception:
        pass


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
    """Read-only mount an NTFS partition from a raw disk stream.

    Per sleuthkit SKILL: always pass ro,offset,norecovery. norecovery
    prevents NTFS journal replay (which would alter the on-disk state).

    Two-stage strategy:

      1. **ntfs-3g direct mount** — works against any file shape
         including FUSE-exposed virtual files (`dislocker-file`,
         `ewfmount` exports, anything backed by a userspace fuse
         driver). ntfs-3g handles its own block I/O internally and
         doesn't need a kernel loop device. Tried FIRST.

      2. **Kernel `mount -o loop,offset=...`** — fallback for the
         rare case where ntfs-3g is unavailable or the image has
         a quirk ntfs-3g rejects. Cannot stack on FUSE files (loop
         device requires a real backing inode), so this path is
         only useful for plain raw files.

    The order matters: dislocker-fuse exposed `dislocker-file` is
    a FUSE virtual file; the kernel loop path rc=32 there even
    when the underlying NTFS is healthy. ntfs-3g works against it
    directly.
    """
    mount_point.mkdir(parents=True, exist_ok=True)
    offset_bytes = offset_sectors * sector_size
    errors: list[str] = []

    # Path 1: ntfs-3g direct mount. -o option list mirrors kernel
    # mount's; ntfs-3g understands offset= the same way.
    ntfs3g = shutil.which("ntfs-3g")
    if ntfs3g:
        cmd = ["sudo", ntfs3g, "-o",
               f"ro,offset={offset_bytes},norecovery",
               str(raw_image), str(mount_point)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout)
            if proc.returncode == 0:
                return
            errors.append(
                f"ntfs-3g rc={proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()[:200]}")
        except subprocess.TimeoutExpired as e:
            raise SleuthkitError(f"ntfs-3g mount timeout: {e}") from e

    # Path 2: kernel loop mount. Won't work on FUSE files but covers
    # the case where ntfs-3g is missing or rejected the image.
    cmd = ["sudo", "mount", "-o",
           f"ro,loop,offset={offset_bytes},norecovery",
           str(raw_image), str(mount_point)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SleuthkitError(f"mount timeout: {e}") from e
    if proc.returncode != 0:
        errors.append(
            f"kernel mount rc={proc.returncode}: "
            f"{(proc.stderr or proc.stdout).strip()[:200]}")
        raise SleuthkitError(
            "NTFS mount failed via all attempted strategies: "
            + " | ".join(errors))


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


# Registry transaction-log suffixes. On Vista+ the kernel maintains
# HIVE.LOG1 / HIVE.LOG2 dual logs; older Windows (XP/2003) uses a
# single HIVE.LOG. A hive that was in use at image time is "dirty" —
# EZ Tools' AmcacheParser / AppCompatCacheParser / RECmd refuse to
# parse it without the matching LOG files sitting next to it. Copying
# the logs turns a "hive is dirty and no transaction logs were found"
# abort into a successful parse (SRL-2018 wkstn-01 + base-file were
# both live-imaged and both previously failed for this reason).
_HIVE_LOG_SUFFIXES: tuple[str, ...] = (".LOG", ".LOG1", ".LOG2")


def _copy_hive_with_logs(src_hive: Path, dst_hive: Path) -> bool:
    """Copy a registry hive and any sibling transaction-log files.

    `src_hive.parent` is scanned (case-insensitively) for every
    `<hive_name><suffix>` in `_HIVE_LOG_SUFFIXES`. Each found file is
    copied to `dst_hive.parent / (dst_hive.name + suffix)` so that when
    the destination is later renamed (e.g. NTUSER.DAT → NTUSER-alice.DAT)
    the logs follow the rename. Returns True iff the hive copy
    succeeded; log-copy failures are silent (missing logs are normal
    for cleanly-shutdown boxes)."""
    ok = _sudo_cp(src_hive, dst_hive)
    if not ok:
        return False
    src_name = src_hive.name
    parent = src_hive.parent
    for suffix in _HIVE_LOG_SUFFIXES:
        log_src = _child_ci(parent, src_name + suffix)
        if log_src and log_src.is_file():
            _sudo_cp(log_src, dst_hive.parent / (dst_hive.name + suffix))
    return True


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
                _copy_hive_with_logs(src, reg_dir / hive_name)
        # Only count the hives themselves, not the LOG siblings, so the
        # return value remains comparable across clean / dirty cases.
        out["registry_hives"] = sum(
            1 for p in reg_dir.iterdir()
            if p.is_file() and not any(
                p.name.upper().endswith(s) for s in _HIVE_LOG_SUFFIXES))

    # Amcache.hve — Win7+ only, lives at <win>/AppCompat/Programs/Amcache.hve
    amcache = _resolve_ci(win_root, "AppCompat", "Programs", "Amcache.hve") if win_root else None
    if amcache and amcache.is_file():
        reg_dir.mkdir(parents=True, exist_ok=True)
        if _copy_hive_with_logs(amcache, reg_dir / "Amcache.hve"):
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

    # T3-3: TeamViewer — system-wide install, logs live in
    # Program Files[ (x86)]\TeamViewer\. Connection log is
    # connections_incoming.txt (inbound sessions) + TeamViewer*_Logfile.log.
    teamviewer_dir = exports_dir / "remote_access" / "teamviewer"
    for pf_name in ("Program Files", "Program Files (x86)"):
        pf = _child_ci(mount_point, pf_name)
        tv = _child_ci(pf, "TeamViewer") if pf else None
        if not tv or not tv.is_dir():
            continue
        for entry in tv.iterdir():
            if not entry.is_file():
                continue
            name_lc = entry.name.lower()
            if (name_lc == "connections_incoming.txt"
                    or (name_lc.startswith("teamviewer") and
                        name_lc.endswith("_logfile.log"))):
                teamviewer_dir.mkdir(parents=True, exist_ok=True)
                if _sudo_cp(entry, teamviewer_dir / entry.name):
                    out["teamviewer_log_files"] = (
                        out.get("teamviewer_log_files", 0) + 1
                    )

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
                if _copy_hive_with_logs(
                        ntuser, reg_dir / f"NTUSER-{user_dir.name}.DAT"):
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
                        # Saved-login vault: logins.json holds the encrypted
                        # credentials, key4.db the NSS key that decrypts them
                        # (browser_credentials skill). cert9.db completes the
                        # profile for NSS; signedInUser.json carries the FxA
                        # identity. Copy alongside places.sqlite so the
                        # credential decryptor runs offline.
                        for cred in ("logins.json", "key4.db", "cert9.db",
                                     "logins-backup.json", "signedInUser.json"):
                            src = _child_ci(prof, cred)
                            if src and src.is_file():
                                _sudo_cp(src, dst_dir / cred)
            # Windows 10/11 Timeline (ActivitiesCache.db) — per-user
            # SQLite under AppData\Local\ConnectedDevicesPlatform\L.<user>\.
            # One user can have multiple L.* subdirs (profile migrations,
            # Microsoft-account roaming); we walk every one we find.
            timeline_dir = exports_dir / "timeline"
            cdp_root = _resolve_ci(user_dir, "AppData", "Local",
                                     "ConnectedDevicesPlatform")
            if cdp_root and cdp_root.is_dir():
                for sub in cdp_root.iterdir():
                    if not sub.is_dir() or not sub.name.lower().startswith("l."):
                        continue
                    for fname in ("ActivitiesCache.db",
                                   "ActivitiesCache.db-wal",
                                   "ActivitiesCache.db-shm"):
                        src = _child_ci(sub, fname)
                        if src and src.is_file():
                            timeline_dir.mkdir(parents=True, exist_ok=True)
                            dst = (timeline_dir /
                                   f"{user_dir.name}--{sub.name}--{fname}")
                            if _sudo_cp(src, dst):
                                out["activities_cache_files"] = (
                                    out.get("activities_cache_files", 0) + 1
                                )
            # iCloud for Windows account config — com.apple.AOSKit.plist
            # (Apple ID) + iCloudWinPref.plist (DSID + quota). Store build
            # buries them under AppData\Local\Packages\AppleInc.iCloud_*\
            # LocalCache\Roaming\Apple Computer\Preferences; classic
            # installer uses AppData\Roaming\Apple Computer\Preferences.
            icloud_dir = exports_dir / "icloud"
            icloud_pref_dirs: list[Path] = []
            classic_pref = _resolve_ci(user_dir, "AppData", "Roaming",
                                       "Apple Computer", "Preferences")
            if classic_pref and classic_pref.is_dir():
                icloud_pref_dirs.append(classic_pref)
            pkgs = _resolve_ci(user_dir, "AppData", "Local", "Packages")
            if pkgs and pkgs.is_dir():
                for pkg in pkgs.iterdir():
                    if (pkg.is_dir()
                            and pkg.name.lower().startswith("appleinc.icloud")):
                        pref = _resolve_ci(pkg, "LocalCache", "Roaming",
                                           "Apple Computer", "Preferences")
                        if pref and pref.is_dir():
                            icloud_pref_dirs.append(pref)
            for pref in icloud_pref_dirs:
                for fname in ("com.apple.AOSKit.plist", "iCloudWinPref.plist",
                               "com.apple.AOSKit.RegInfo.plist"):
                    src = _child_ci(pref, fname)
                    if src and src.is_file():
                        dst_dir = icloud_dir / user_dir.name
                        dst_dir.mkdir(parents=True, exist_ok=True)
                        if _sudo_cp(src, dst_dir / fname):
                            out["icloud_config_files"] = (
                                out.get("icloud_config_files", 0) + 1)
            # IE5 Content.IE5 index.dat + cached files — XP + legacy Vista/7
            # profiles. The directory tree is:
            #   XP    : <user>/Local Settings/Temporary Internet Files/
            #           Content.IE5/index.dat  +
            #           Content.IE5/<8char>/<cached>
            #   Vista+: <user>/AppData/Local/Microsoft/Windows/
            #           Temporary Internet Files/Content.IE5/index.dat
            # Plus parallel History.IE5/index.dat + Cookies/index.dat.
            # We copy only the index.dat records (the structured metadata)
            # — not every cached file, which would balloon the export.
            ie_dir = exports_dir / "ie_cache"
            for ie_root_candidate in (
                _resolve_ci(user_dir, "Local Settings",
                             "Temporary Internet Files", "Content.IE5"),
                _resolve_ci(user_dir, "AppData", "Local", "Microsoft",
                             "Windows", "Temporary Internet Files",
                             "Content.IE5"),
                _resolve_ci(user_dir, "Local Settings", "History",
                             "History.IE5"),
                _resolve_ci(user_dir, "Cookies"),
            ):
                if not (ie_root_candidate and ie_root_candidate.is_dir()):
                    continue
                idx = _child_ci(ie_root_candidate, "index.dat")
                if idx and idx.is_file():
                    ie_dir.mkdir(parents=True, exist_ok=True)
                    kind = ie_root_candidate.name.lower()
                    dst = (ie_dir /
                           f"{user_dir.name}--{kind}--index.dat")
                    if _sudo_cp(idx, dst):
                        out["ie_index_dat"] = (
                            out.get("ie_index_dat", 0) + 1)

            # T3-3: AnyDesk per-user connection traces. TeamViewer is
            # system-wide and handled below.
            anydesk_dir = exports_dir / "remote_access" / "anydesk"
            ad_root = _resolve_ci(user_dir, "AppData", "Roaming", "AnyDesk")
            if ad_root and ad_root.is_dir():
                for fname in ("connection_trace.txt", "ad.trace",
                               "ad_svc.trace"):
                    src = _child_ci(ad_root, fname)
                    if src and src.is_file():
                        anydesk_dir.mkdir(parents=True, exist_ok=True)
                        if _sudo_cp(src, anydesk_dir /
                                    f"{user_dir.name}--{fname}"):
                            out["anydesk_trace_files"] = (
                                out.get("anydesk_trace_files", 0) + 1
                            )

            # PowerShell breadth: PSReadline console history.
            # File lists every command the user typed at a PS prompt —
            # persists across sessions, defeats `$HistoryPath = $null`
            # in-process clearing. Same fallback order as the rest:
            # Win7+ AppData\Roaming path first.
            ps_history = _resolve_ci(
                user_dir, "AppData", "Roaming", "Microsoft", "Windows",
                "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
            if ps_history and ps_history.is_file():
                ps_dir = exports_dir / "powershell" / "psreadline"
                ps_dir.mkdir(parents=True, exist_ok=True)
                if _sudo_cp(ps_history,
                            ps_dir / f"{user_dir.name}--ConsoleHost_history.txt"):
                    out["psreadline_history_files"] = (
                        out.get("psreadline_history_files", 0) + 1
                    )

            # PowerShell transcription logs (when enabled via
            # Start-Transcript or GPO). Default path is Documents\;
            # some orgs redirect via OutputDirectory registry setting
            # to \\fileserver\share\PSTranscripts — we only pull the
            # local default here.
            docs_root = _child_ci(user_dir, "Documents")
            if docs_root and docs_root.is_dir():
                ts_dir = exports_dir / "powershell" / "transcripts"
                for entry in docs_root.iterdir():
                    if not entry.is_file():
                        continue
                    name_lc = entry.name.lower()
                    if (name_lc.startswith("powershell_transcript")
                            and name_lc.endswith(".txt")):
                        ts_dir.mkdir(parents=True, exist_ok=True)
                        if _sudo_cp(entry, ts_dir /
                                    f"{user_dir.name}--{entry.name}"):
                            out["ps_transcript_files"] = (
                                out.get("ps_transcript_files", 0) + 1
                            )
            # Thumb caches — `thumbcache_*.db` files under Explorer/.
            # Tiny binary blobs holding embedded JPEG thumbnails of
            # files the user opened. Useful when a file was deleted
            # but its thumbnail survives.
            tc_src = _resolve_ci(
                user_dir, "AppData", "Local", "Microsoft", "Windows",
                "Explorer")
            if tc_src and tc_src.is_dir():
                tc_dst = (exports_dir / "windows-artifacts"
                          / "thumbcache" / user_dir.name)
                n_tc = 0
                for f in tc_src.iterdir():
                    if not f.is_file():
                        continue
                    nm = f.name.lower()
                    if not (nm.startswith("thumbcache_")
                             or nm.startswith("iconcache_")):
                        continue
                    if not nm.endswith(".db"):
                        continue
                    tc_dst.mkdir(parents=True, exist_ok=True)
                    if _sudo_cp(f, tc_dst / f.name):
                        n_tc += 1
                if n_tc:
                    out["thumbcache_files"] = (
                        out.get("thumbcache_files", 0) + n_tc
                    )

            # SmartScreen application cache —
            # `AppData\Local\Microsoft\Windows\AppCache\AppCache*.db`
            # records SmartScreen-vetted downloads + reputation hits.
            ss_src = _resolve_ci(
                user_dir, "AppData", "Local", "Microsoft", "Windows",
                "AppCache")
            if ss_src and ss_src.is_dir():
                ss_dst = (exports_dir / "windows-artifacts"
                          / "smartscreen" / user_dir.name)
                n_ss = 0
                for f in ss_src.iterdir():
                    if not f.is_file():
                        continue
                    if not f.name.lower().endswith(".db"):
                        continue
                    ss_dst.mkdir(parents=True, exist_ok=True)
                    if _sudo_cp(f, ss_dst / f.name):
                        n_ss += 1
                if n_ss:
                    out["smartscreen_files"] = (
                        out.get("smartscreen_files", 0) + n_ss
                    )

            # UWP / Cloud-Clipboard items (Windows 1809+). Pinned items
            # live forever; recent items roll off after a few days. The
            # whole tree is small (<10 MB typically) so we copy it all.
            cb_src = _resolve_ci(
                user_dir, "AppData", "Local", "Microsoft", "Windows",
                "Clipboard")
            if cb_src and cb_src.is_dir():
                cb_dst = (exports_dir / "windows-artifacts"
                          / "uwp-clipboard" / user_dir.name / "Clipboard")
                cb_dst.mkdir(parents=True, exist_ok=True)
                n_cb = 0
                for sub in cb_src.rglob("*"):
                    if not sub.is_file():
                        continue
                    rel = sub.relative_to(cb_src)
                    dst_file = cb_dst / rel
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    if _sudo_cp(sub, dst_file):
                        n_cb += 1
                if n_cb:
                    out["uwp_clipboard_files"] = (
                        out.get("uwp_clipboard_files", 0) + n_cb
                    )
        if n_ntuser:
            out["ntuser_hives"] = n_ntuser
        if n_pst:
            out["outlook_pst"] = n_pst
        if n_firefox:
            out["firefox_profiles"] = n_firefox

    # Windows Error Reporting (WER) report queue under
    # %ProgramData%\Microsoft\Windows\WER\ReportQueue\. Each per-crash
    # subdir holds a Report.wer text file with the crashing executable
    # name + reason. Crashes often coincide with exploitation attempts
    # (DoubleAgent / DLL hijack / unhandled exceptions in shellcode).
    wer_root = None
    pd_dir = _child_ci(mount_point, "ProgramData")
    if pd_dir:
        ms_dir = _child_ci(pd_dir, "Microsoft")
        if ms_dir:
            win_dir = _child_ci(ms_dir, "Windows")
            if win_dir:
                wer_root = _child_ci(win_dir, "WER")
    if wer_root and wer_root.is_dir():
        wer_dst = exports_dir / "wer"
        wer_dst.mkdir(parents=True, exist_ok=True)
        n_wer = 0
        for queue in ("ReportQueue", "ReportArchive"):
            qd = _child_ci(wer_root, queue)
            if not (qd and qd.is_dir()):
                continue
            for sub in qd.iterdir():
                if not sub.is_dir():
                    continue
                # Each subdir is one crash; copy any Report.wer / .txt
                # / .xml files (small, dozens KB).
                for f in sub.iterdir():
                    if not f.is_file():
                        continue
                    if f.suffix.lower() not in (".wer", ".txt", ".xml"):
                        continue
                    dst = wer_dst / queue / sub.name
                    dst.mkdir(parents=True, exist_ok=True)
                    if _sudo_cp(f, dst / f.name):
                        n_wer += 1
        if n_wer:
            out["wer_files"] = n_wer

    # User Access Logging (UAL) — Windows Server 2012+ ESE databases
    # at C:\Windows\System32\LogFiles\Sum\<GUID>.mdb. Per-user / per-IP
    # access counts to server roles. Tiny DBs (<50 MB), copy whole.
    # Chain via per-step None-guards so a missing intermediate dir
    # (e.g. non-Server image without /Windows/System32/LogFiles/) doesn't
    # propagate None into the next _child_ci call (regression caught
    # by the existing test_extract_windows_artifacts_xp tests).
    sum_dir = None
    win_dir = _child_ci(mount_point, "Windows")
    if win_dir:
        sys32 = _child_ci(win_dir, "System32")
        if sys32:
            logfiles = _child_ci(sys32, "LogFiles")
            if logfiles:
                sum_dir = _child_ci(logfiles, "Sum")
    if sum_dir and sum_dir.is_dir():
        ual_dst = exports_dir / "ual"
        ual_dst.mkdir(parents=True, exist_ok=True)
        n_ual = 0
        for f in sum_dir.iterdir():
            if not f.is_file():
                continue
            if not f.name.lower().endswith(".mdb"):
                continue
            if _sudo_cp(f, ual_dst / f.name):
                n_ual += 1
        if n_ual:
            out["ual_mdb_files"] = n_ual

    # IIS W3C extended logs under C:\inetpub\logs\LogFiles\W3SVC*\.
    # Copy the whole W3SVC tree so subsequent analyst passes can use
    # Log Parser Studio / manual review; iis_w3c skill walks the
    # exports dir.
    inetpub_dir = _child_ci(mount_point, "inetpub")
    inetpub_logs = None
    if inetpub_dir:
        logs_dir = _child_ci(inetpub_dir, "logs")
        if logs_dir:
            inetpub_logs = _child_ci(logs_dir, "LogFiles")
    if inetpub_logs and inetpub_logs.is_dir():
        iis_dst = exports_dir / "iis_logs"
        iis_dst.mkdir(parents=True, exist_ok=True)
        n_iis = 0
        for w3svc in inetpub_logs.iterdir():
            if not w3svc.is_dir() or not w3svc.name.lower().startswith("w3svc"):
                continue
            site_dst = iis_dst / w3svc.name
            site_dst.mkdir(parents=True, exist_ok=True)
            for log in w3svc.glob("u_ex*.log"):
                if _sudo_cp(log, site_dst / log.name):
                    n_iis += 1
        if n_iis:
            out["iis_w3c_files"] = n_iis

    return out


def mount_linux_ro(raw_image: Path, start_sector: int,
                    mount_point: Path, sector_size: int = 512,
                    timeout: int = 60) -> None:
    """Loop-mount an ext2/ext3/ext4/xfs partition read-only. Accepts a
    byte offset in sectors (from mmls) and the disk sector size.
    Leaves the filesystem open for `extract_linux_artifacts`; caller
    invokes `umount` when done.

    ext-family filesystems auto-detect via blkid; for other Linux
    filesystems the caller can pass `fstype` via kwargs once we need
    that (e.g. xfs images).

    Raises SleuthkitError with a hint pointing at `mount_luks_ro` when
    the target partition turns out to be a LUKS container.
    """
    mount_point = Path(mount_point)
    mount_point.mkdir(parents=True, exist_ok=True)
    offset = start_sector * sector_size
    if _peek_luks_magic(raw_image, offset):
        raise SleuthkitError(
            "target partition is a LUKS container — use "
            "`mount_luks_ro(raw_image, start_sector, mount_point, "
            "passphrase=...)` to unlock first")
    cmd = ["sudo", "mount", "-o",
           f"ro,noexec,loop,offset={offset}",
           str(raw_image), str(mount_point)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SleuthkitError(f"mount timeout after {timeout}s") from e
    if r.returncode != 0:
        raise SleuthkitError(
            f"Linux mount failed (rc={r.returncode}): {r.stderr[:500]}")


# LUKS-v1 magic `LUKS\xba\xbe` lives at offset 0 of the LUKS header;
# LUKS2 magic is `LUKS\xba\xbe` at offset 0 too (version distinguishes
# them via the 16-bit version field). Detecting v1 magic is enough to
# route to cryptsetup.
_LUKS_MAGIC = b"LUKS\xba\xbe"


def _peek_luks_magic(raw_image: Path, byte_offset: int) -> bool:
    """True when the first 6 bytes at `byte_offset` into `raw_image`
    are the LUKS magic. Used by mount_linux_ro to fail with a
    targeted error instead of the kernel's generic `wrong fs type`."""
    try:
        with open(raw_image, "rb") as f:
            f.seek(byte_offset)
            return f.read(6) == _LUKS_MAGIC
    except OSError:
        return False


def mount_luks_ro(raw_image: Path, start_sector: int,
                   mount_point: Path,
                   passphrase: str | None = None,
                   key_file: Path | None = None,
                   sector_size: int = 512,
                   mapper_name: str | None = None,
                   timeout: int = 120) -> dict:
    """Unlock a LUKS-encrypted partition and mount its decrypted
    mapper read-only. Flow:

      1. losetup --read-only --offset N --find --show <raw>  →  /dev/loopN
      2. cryptsetup open --type luks --readonly --key-file|<pw-stdin>
         /dev/loopN <mapper>
      3. mount -o ro /dev/mapper/<mapper> <mount_point>

    Returns a dict of {'loop', 'mapper', 'mount_point'} so the caller
    can tear the stack down in reverse via `umount_luks`.

    Raises SleuthkitError with a clear message when:
      - cryptsetup is not installed (`apt install cryptsetup-bin`)
      - neither `passphrase` nor `key_file` is supplied
      - the partition isn't actually a LUKS container
      - any step of the losetup/cryptsetup/mount chain fails.
    """
    import shutil as _shutil
    if not _shutil.which("cryptsetup"):
        raise SleuthkitError(
            "cryptsetup not on PATH — apt install cryptsetup-bin")
    if not _shutil.which("losetup"):
        raise SleuthkitError("losetup not on PATH — kernel-util package missing")
    if passphrase is None and key_file is None:
        raise SleuthkitError(
            "LUKS unlock needs a passphrase (str) or key_file (path); both None")
    if key_file is not None and not Path(key_file).is_file():
        raise SleuthkitError(f"LUKS key_file not found: {key_file}")

    mount_point = Path(mount_point)
    mount_point.mkdir(parents=True, exist_ok=True)
    offset_bytes = start_sector * sector_size
    if not _peek_luks_magic(raw_image, offset_bytes):
        raise SleuthkitError(
            f"partition at sector {start_sector} is not a LUKS container "
            f"(no LUKS magic at byte {offset_bytes})")

    # 1. losetup the image as a read-only loop device at the partition offset
    loop_cmd = ["sudo", "losetup", "--read-only",
                "--offset", str(offset_bytes),
                "--find", "--show", str(raw_image)]
    try:
        r = subprocess.run(loop_cmd, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SleuthkitError("losetup timeout") from e
    if r.returncode != 0:
        raise SleuthkitError(
            f"losetup failed (rc={r.returncode}): {r.stderr[:500]}")
    loop_dev = r.stdout.strip()
    if not loop_dev.startswith("/dev/"):
        raise SleuthkitError(f"losetup returned unexpected stdout: {loop_dev!r}")

    # 2. cryptsetup open
    if not mapper_name:
        mapper_name = f"el_luks_{mount_point.name}"
    cs_cmd = ["sudo", "cryptsetup", "open", "--type", "luks",
              "--readonly", loop_dev, mapper_name]
    stdin_data = None
    if key_file is not None:
        cs_cmd[2:2] = ["--key-file", str(key_file)]
    else:
        stdin_data = (passphrase or "").encode() + b"\n"
    try:
        r = subprocess.run(cs_cmd, input=stdin_data,
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # Best-effort loop-device cleanup
        subprocess.run(["sudo", "losetup", "-d", loop_dev],
                        capture_output=True)
        raise SleuthkitError("cryptsetup timeout") from e
    if r.returncode != 0:
        subprocess.run(["sudo", "losetup", "-d", loop_dev],
                        capture_output=True)
        err = (r.stderr or b"").decode("utf-8", errors="replace")[:500]
        raise SleuthkitError(
            f"cryptsetup open failed (rc={r.returncode}): {err}")

    # 3. mount the decrypted mapper read-only
    mapper_dev = f"/dev/mapper/{mapper_name}"
    mount_cmd = ["sudo", "mount", "-o", "ro,noexec",
                 mapper_dev, str(mount_point)]
    try:
        r = subprocess.run(mount_cmd, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired as e:
        subprocess.run(["sudo", "cryptsetup", "close", mapper_name],
                        capture_output=True)
        subprocess.run(["sudo", "losetup", "-d", loop_dev],
                        capture_output=True)
        raise SleuthkitError("mount timeout") from e
    if r.returncode != 0:
        subprocess.run(["sudo", "cryptsetup", "close", mapper_name],
                        capture_output=True)
        subprocess.run(["sudo", "losetup", "-d", loop_dev],
                        capture_output=True)
        raise SleuthkitError(
            f"mount of decrypted mapper failed (rc={r.returncode}): "
            f"{r.stderr[:500]}")
    return {"loop": loop_dev, "mapper": mapper_name,
            "mount_point": str(mount_point)}


def umount_luks(state: dict, timeout: int = 60) -> None:
    """Reverse of `mount_luks_ro`: umount, cryptsetup close, losetup -d.
    Best-effort — logs but does not re-raise if a step fails (tear-down
    should never block a run even when the OS has already reclaimed
    pieces of the stack). `state` is the dict mount_luks_ro returned."""
    mp = state.get("mount_point")
    mapper = state.get("mapper")
    loop = state.get("loop")
    if mp:
        subprocess.run(["sudo", "umount", str(mp)],
                        capture_output=True, timeout=timeout)
    if mapper:
        subprocess.run(["sudo", "cryptsetup", "close", mapper],
                        capture_output=True, timeout=timeout)
    if loop:
        subprocess.run(["sudo", "losetup", "-d", loop],
                        capture_output=True, timeout=timeout)


def mount_apfs_ro(raw_image: Path, start_sector: int,
                    mount_point: Path, volume_index: int = 1,
                    sector_size: int = 512,
                    timeout: int = 60) -> None:
    """Mount an APFS volume read-only via `fsapfsmount`. Requires the
    `libfsapfs-tools` apt package. Accepts a byte offset in sectors
    (from mmls) and a 1-based `volume_index` — an APFS container
    typically holds 6 volumes in Big Sur+ (Data, Preboot, Recovery,
    VM, Update, System). Volume 1 = 'Macintosh HD - Data' on a
    standard install and is where user data + most forensic
    artifacts live.
    """
    mount_point = Path(mount_point)
    mount_point.mkdir(parents=True, exist_ok=True)
    offset = start_sector * sector_size
    cmd = ["sudo", "fsapfsmount", "-X", "allow_other",
           "-o", str(offset), "-f", str(volume_index),
           str(raw_image), str(mount_point)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SleuthkitError(f"fsapfsmount timeout after {timeout}s") from e
    if r.returncode != 0:
        raise SleuthkitError(
            f"APFS mount failed (rc={r.returncode}): {r.stderr[:500]}")


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
    512-byte sectors (caller should adjust for 4K via img_stat).

    The description column is OPTIONAL — Sleuth Kit leaves it blank
    for partition-type GUIDs it doesn't recognise (ReFS / Storage
    Spaces / vendor-specific). Previously the >=6-field check
    silently dropped those rows, which meant ReFS partitions were
    invisible to the per-partition walker. Now we accept rows with
    no description and let downstream signature-detection handle
    the FS classification.
    """
    rows: list[dict] = []
    for line in mmls_output.splitlines():
        line = line.strip()
        if not line or line.startswith("DOS Partition") or line.startswith("Units") \
                or line.startswith("GPT Partition") or line.startswith("Slot") \
                or line.startswith("Sector Size") or line.startswith("---"):
            continue
        parts = line.split(maxsplit=5)
        # The first 5 fields (slot:, slot_index, start, end, length)
        # are mandatory. The 6th (description) is optional — present
        # when Sleuth Kit recognises the partition-type GUID, absent
        # for ReFS / Storage Spaces / vendor-specific.
        if len(parts) < 5:
            continue
        slot, start, end, length = parts[1], parts[2], parts[3], parts[4]
        desc = parts[5] if len(parts) >= 6 else ""
        # mmls's first column is the slot indicator ("Meta", "---"
        # for Unallocated, or a slot index like "000"). The Meta /
        # Unallocated rows describe GPT housekeeping (Safety Table,
        # GPT Header, Partition Table, free-space gaps) — not real
        # partitions an analyst would want to walk. The legacy desc-
        # substring filter ("Meta in desc") never matched because
        # those words only appear in the SLOT column; relocate the
        # check there.
        if slot.startswith(("Meta", "---")) \
                or "Unallocated" in desc \
                or "Primary Table" in desc:
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


def _inode_arg(inode: str | int) -> str:
    """Normalise an inode token. fls bodyfiles carry the full
    ``<entry>-<type>-<id>`` address (e.g. ``124086-128-4``); TSK tools
    accept that verbatim, so we pass it through — preserving the
    attribute id matters for files with multiple $DATA streams (ADS)."""
    return str(inode).strip()


def istat(image: Path, inode: str | int, out_dir: Path,
          offset: int | None = None, label: str | None = None,
          timeout: int = 120) -> TskRun:
    """Dump an MFT entry's metadata (``istat``). Output is captured to disk so
    it can ground a Finding's EvidenceItem. ``offset`` is the partition start
    sector when ``image`` is a whole-disk stream."""
    inode_s = _inode_arg(inode)
    args: list[str] = []
    if offset is not None:
        args += ["-o", str(offset)]
    args += [str(image), inode_s]
    lbl = label or f"istat_{inode_s.replace('-', '_')}"
    return _run("istat", image, args, out_dir, lbl, timeout)


def icat_extract(image: Path, inode: str | int, out_path: Path,
                 offset: int | None = None, timeout: int = 900) -> int:
    """Extract a file's content stream (``icat``) to ``out_path``. Streams to
    disk so multi-GB recoveries stay bounded in memory. Returns the number of
    bytes written. Raises SleuthkitError on tool failure."""
    inode_s = _inode_arg(inode)
    cmd = [_which("icat")]
    if offset is not None:
        cmd += ["-o", str(offset)]
    cmd += [str(image), inode_s]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        with out_path.open("wb") as fh:
            proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE,
                                  timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SleuthkitError(f"icat timeout after {timeout}s") from e
    if proc.returncode != 0:
        raise SleuthkitError(
            f"icat failed (rc={proc.returncode}) for inode {inode_s}: "
            f"{(proc.stderr or b'').decode('utf-8', 'replace')[:200]}")
    try:
        written = out_path.stat().st_size
    except OSError:
        written = 0
    return written


def content_is_zero(image: Path, inode: str | int, offset: int | None = None,
                    max_bytes: int = 64 * 1024 * 1024,
                    timeout: int = 600) -> bool | None:
    """Stream ``icat`` for an inode and report whether every byte read (up to
    ``max_bytes``) is zero. Returns True (all-zero), False (real data found),
    or None when icat could not run. Reads via a pipe so a wiped multi-GB
    file is judged without writing it to disk — the cheap detection probe
    behind wipe_detect.classify()."""
    inode_s = _inode_arg(inode)
    cmd = [_which("icat")]
    if offset is not None:
        cmd += ["-o", str(offset)]
    cmd += [str(image), inode_s]
    read = 0
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
    except OSError:
        return None
    try:
        assert proc.stdout is not None
        while read < max_bytes:
            buf = proc.stdout.read(min(1 << 20, max_bytes - read))
            if not buf:
                break
            read += len(buf)
            if buf.count(0) != len(buf):
                return False          # a non-zero byte ⇒ real content
    finally:
        try:
            proc.stdout.close()  # type: ignore[union-attr]
        except OSError:
            pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
    if read == 0:
        return None                   # nothing came back — can't judge
    return True
