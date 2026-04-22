"""Skill: Android filesystem-tree artifact extraction.

Unlike the NTFS / ext4 / APFS paths where EL mounts a disk image,
Android cases typically arrive as already-extracted file-system
trees (Belkasoft / UFED / adb-pull output). `extract_android_artifacts`
walks that tree and sudo-cp's the IR-relevant files into
exports/android-artifacts/ so the analyst has a sealed,
deterministic subset regardless of whether the original collection
is on a read-only share.

Coverage (V1):

  /data/system/           packages.xml, packages.list, appops.xml,
                          locksettings.db, device_policies.xml,
                          users/*/accounts.db
  /data/adb/              magisk.db (presence = rooted device),
                          magisk/ (module tree), modules/
  /data/local/tmp/        attacker-staging classic; any file copied
  /data/anr/              traces.txt* (ANR = app-not-responding,
                          includes per-process stack at crash)
  /data/tombstones/       native-process crash dumps (attacker
                          footprints often land here)
  Per-app (/data/data/<pkg>/):
    com.whatsapp/databases/msgstore.db + axolotl.db
    com.android.chrome/app_chrome/Default/History
    com.android.browser/databases/browser2.db
    com.android.providers.contacts/databases/contacts2.db
    com.android.providers.telephony/databases/mmssms.db
    com.google.android.gm/databases/*.db  (Gmail)
    org.thoughtcrime.securesms/databases/*  (Signal)
    org.telegram.messenger/files/  (Telegram — no SQLite, tgs/sqlite)

Pure function. No parsing — that lives in `android_triage`.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _sudo_cp(src: Path, dst: Path) -> bool:
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        r1 = subprocess.run(["sudo", "cp", "--preserve=timestamps",
                              str(src), str(dst)],
                             capture_output=True, text=True, timeout=120)
        if r1.returncode != 0:
            return False
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}",
                         str(dst)],
                        capture_output=True, text=True, timeout=30)
        return True
    except Exception:
        return False


def _cp_glob(src_dir: Path, dst_dir: Path, pattern: str) -> int:
    if not src_dir.is_dir():
        return 0
    import fnmatch
    n = 0
    try:
        for entry in src_dir.iterdir():
            if not entry.is_file():
                continue
            if pattern == "*" or fnmatch.fnmatch(entry.name, pattern):
                if _sudo_cp(entry, dst_dir / entry.name):
                    n += 1
    except (PermissionError, OSError):
        pass
    return n


def _cp_tree(src_dir: Path, dst_dir: Path, max_files: int = 500) -> int:
    """Copy every file under src_dir into dst_dir (same layout). Caps
    total files to avoid blowing up on a /data/data/<app>/cache tree."""
    if not src_dir.is_dir():
        return 0
    n = 0
    for p in src_dir.rglob("*"):
        if not p.is_file():
            continue
        if n >= max_files:
            break
        rel = p.relative_to(src_dir)
        if _sudo_cp(p, dst_dir / rel):
            n += 1
    return n


# Per-app artifacts to pull. Key = package name; value = list of
# (source_subpath, dest_subpath_or_None) relative to the package dir.
_APP_FILES: dict[str, tuple[str, ...]] = {
    "com.whatsapp": (
        "databases/msgstore.db",
        "databases/axolotl.db",
        "databases/chatsettings.db",
        "databases/commerce.db",
    ),
    "com.android.chrome": (
        "app_chrome/Default/History",
        "app_chrome/Default/Login Data",
        "app_chrome/Default/Cookies",
    ),
    "com.android.browser": (
        "databases/browser2.db",
    ),
    "com.android.providers.contacts": (
        "databases/contacts2.db",
    ),
    "com.android.providers.telephony": (
        "databases/mmssms.db",
        "databases/telephony.db",
    ),
    "com.google.android.gm": (
        "databases/bigtopandroidstorage.db",
    ),
    "org.thoughtcrime.securesms": (
        "databases/signal.db",
    ),
    "org.telegram.messenger": (
        "files/cache4.db",
    ),
    "com.wickr.pro": (
        "databases/wickr.db",
    ),
    "org.mozilla.firefox": (
        "files/places.sqlite",
    ),
}


def extract_android_artifacts(input_dir: Path,
                                exports_dir: Path) -> dict:
    """Walk an Android filesystem-tree input, copy IR artifacts.
    Returns artifact-class → count dict."""
    out: dict[str, int] = {}
    input_dir = Path(input_dir)
    exports_dir = Path(exports_dir)

    # /data/system/* core config
    sysdir = input_dir / "data" / "system"
    if sysdir.is_dir():
        sys_out = exports_dir / "data" / "system"
        for fname in ("packages.xml", "packages.list", "appops.xml",
                       "locksettings.db", "device_policies.xml",
                       "netpolicy.xml", "notification_log.db",
                       "users.xml", "log-files.xml"):
            src = sysdir / fname
            if src.is_file():
                if _sudo_cp(src, sys_out / fname):
                    out["system_config_files"] = (
                        out.get("system_config_files", 0) + 1)
        # Per-user accounts DBs
        users_dir = sysdir / "users"
        if users_dir.is_dir():
            for user_dir in users_dir.iterdir():
                if not user_dir.is_dir():
                    continue
                for db_name in ("accounts.db", "settings_secure.xml",
                                 "settings_system.xml"):
                    src = user_dir / db_name
                    if src.is_file():
                        if _sudo_cp(src, sys_out / "users" /
                                    user_dir.name / db_name):
                            out["system_user_files"] = (
                                out.get("system_user_files", 0) + 1)

    # /data/adb/ — root indicators + Magisk module tree
    adb_dir = input_dir / "data" / "adb"
    if adb_dir.is_dir():
        adb_out = exports_dir / "data" / "adb"
        for fname in ("magisk.db", "magisk.db-journal", "magisk"):
            src = adb_dir / fname
            if src.is_file():
                if _sudo_cp(src, adb_out / fname):
                    out["adb_files"] = out.get("adb_files", 0) + 1
        # /data/adb/modules/* — Magisk module directory names as evidence
        modules_dir = adb_dir / "modules"
        if modules_dir.is_dir():
            for m in modules_dir.iterdir():
                if m.is_dir():
                    placeholder = adb_out / "modules" / m.name / ".keep"
                    placeholder.parent.mkdir(parents=True, exist_ok=True)
                    placeholder.write_text(f"Magisk module: {m.name}\n")
                    out["magisk_modules"] = (
                        out.get("magisk_modules", 0) + 1)

    # /data/local/tmp — classic attacker staging dir
    tmp_dir = input_dir / "data" / "local" / "tmp"
    if tmp_dir.is_dir():
        tmp_out = exports_dir / "data" / "local" / "tmp"
        n = _cp_tree(tmp_dir, tmp_out, max_files=200)
        if n:
            out["data_local_tmp_files"] = n

    # /data/anr and /data/tombstones
    for subname, bucket in (("anr", "anr_traces"),
                              ("tombstones", "tombstones")):
        src_dir = input_dir / "data" / subname
        if src_dir.is_dir():
            dst_dir = exports_dir / "data" / subname
            n = _cp_glob(src_dir, dst_dir, "*")
            if n:
                out[bucket] = n

    # Per-app databases
    data_data = input_dir / "data" / "data"
    if data_data.is_dir():
        for pkg, files in _APP_FILES.items():
            pkg_src = data_data / pkg
            if not pkg_src.is_dir():
                continue
            pkg_dst = exports_dir / "data" / "data" / pkg
            for rel in files:
                src = pkg_src / rel
                if src.is_file():
                    if _sudo_cp(src, pkg_dst / rel):
                        out[f"app_{pkg.split('.')[-1]}_files"] = (
                            out.get(f"app_{pkg.split('.')[-1]}_files", 0) + 1)

    # /storage/emulated/0/Download — user-downloaded files (pulled as
    # listing only; some CTFs have 100s of downloaded items and we
    # don't want to copy gigabytes of photos into the case dir)
    downloads = input_dir / "storage" / "emulated" / "0" / "Download"
    if downloads.is_dir():
        listing = sorted(p.name for p in downloads.iterdir()
                         if p.is_file())[:500]
        if listing:
            out_listing = (exports_dir / "storage" / "emulated" / "0"
                           / "Download.listing.txt")
            out_listing.parent.mkdir(parents=True, exist_ok=True)
            out_listing.write_text("\n".join(listing))
            out["download_listing_entries"] = len(listing)

    return out


__all__ = ["extract_android_artifacts"]
