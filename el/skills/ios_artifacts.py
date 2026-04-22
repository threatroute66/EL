"""Skill: iOS filesystem-tree artifact extraction.

iOS cases arrive as already-extracted filesystem trees (checkm8 / GrayKey
/ Cellebrite / adv-logical extraction output). `extract_ios_artifacts`
walks that tree and sudo-cp's the IR-relevant files into
exports/ios-artifacts/ so the analyst has a sealed, deterministic subset.

Coverage (V1):

  /System/Library/CoreServices/     SystemVersion.plist (iOS version)
  /private/var/mobile/Library/SMS/                     sms.db (iMessage+SMS)
  /private/var/mobile/Library/AddressBook/             AddressBook.sqlitedb
  /private/var/mobile/Library/CallHistoryDB/           CallHistory.storedata
  /private/var/mobile/Library/CoreDuet/Knowledge/      knowledgeC.db
  /private/var/mobile/Library/CoreDuet/People/         interactionC.db
  /private/var/mobile/Library/Safari/                  History.db, Bookmarks.db
  /private/var/mobile/Library/Mail/                    Envelope Index
  /private/var/mobile/Library/Notes/                   notes.sqlite / NoteStore.sqlite
  /private/var/mobile/Library/Health/                  healthdb_secure.sqlite
  /private/var/installd/Library/MobileInstallation/    LastLaunchServicesMap.plist
                                                        LastBuildInfo.plist
  /private/var/MobileDevice/ProvisioningProfiles/      *.mobileprovision
                                                        (enterprise/dev signing)
  /private/var/containers/Bundle/Application/<GUID>/   iTunesMetadata.plist +
                                                        BundleMetadata.plist +
                                                        *.app/Info.plist
                                                        (app-install lineage)

Pure function. No parsing — that lives in `ios_triage`.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _sudo_cp(src: Path, dst: Path) -> bool:
    """Copy src→dst. Try plain shutil first (zero fork overhead); only
    pay the sudo+chown cost when the file is not readable as the current
    user. On mobile extract trees this is the hot path for hundreds of
    Info.plist files — skipping sudo saves ~500ms/file on slow FUSE
    mounts like VMware HGFS."""
    import shutil
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if os.access(src, os.R_OK):
            try:
                shutil.copy2(str(src), str(dst))
                return True
            except (PermissionError, OSError):
                pass
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


# Native iOS Library/ DBs — all live under /private/var/mobile/Library/
_MOBILE_LIBRARY_FILES: tuple[tuple[str, str], ...] = (
    # (source_subpath_relative_to_mobile_Library, bucket_name)
    ("SMS/sms.db",                                   "sms_db"),
    ("AddressBook/AddressBook.sqlitedb",             "addressbook_db"),
    ("AddressBook/AddressBookImages.sqlitedb",       "addressbook_db"),
    ("CallHistoryDB/CallHistory.storedata",          "callhistory_db"),
    ("CallHistoryDB/CallHistory.storedata-wal",      "callhistory_db"),
    ("CoreDuet/Knowledge/knowledgeC.db",             "knowledgec_db"),
    ("CoreDuet/People/interactionC.db",              "interactionc_db"),
    ("Safari/History.db",                            "safari_db"),
    ("Safari/Bookmarks.db",                          "safari_db"),
    ("Safari/RecentlyClosedTabs.db",                 "safari_db"),
    ("Mail/Envelope Index",                          "mail_db"),
    ("Notes/notes.sqlite",                           "notes_db"),
    ("Notes/NoteStore.sqlite",                       "notes_db"),
    ("Health/healthdb_secure.sqlite",                "health_db"),
    ("Health/healthdb.sqlite",                       "health_db"),
    ("Caches/com.apple.routined/Cache.sqlite",       "locationd_db"),
    ("FrontBoard/applicationState.db",               "applicationstate_db"),
    ("Preferences/com.apple.mobile.ldd.plist",       "preferences"),
    ("Preferences/com.apple.preferences.network.plist", "preferences"),
    ("Preferences/com.apple.springboard.plist",      "preferences"),
    ("Preferences/com.apple.wifi.plist",             "preferences"),
    ("Preferences/com.apple.locationd.plist",        "preferences"),
)


def extract_ios_artifacts(input_dir: Path, exports_dir: Path) -> dict:
    """Walk an iOS filesystem-tree input, copy IR artifacts.
    Returns artifact-class → count dict."""
    out: dict[str, int] = {}
    input_dir = Path(input_dir)
    exports_dir = Path(exports_dir)

    # System version / build identifier
    sv = (input_dir / "System" / "Library" / "CoreServices"
          / "SystemVersion.plist")
    if sv.is_file():
        sv_out = (exports_dir / "System" / "Library" / "CoreServices"
                  / "SystemVersion.plist")
        if _sudo_cp(sv, sv_out):
            out["system_version"] = 1

    # Jailbreak markers — preserve presence so downstream triage sees it.
    # These are mostly directories (Cydia.app, /private/var/jb, /private/
    # var/lib/apt); copy the file when a marker is a file, otherwise
    # write a .keep placeholder at the same relative path.
    _JB_MARKER_PATHS = (
        "Applications/Cydia.app", "Applications/Sileo.app",
        "Applications/Zebra.app", "Applications/Installer.app",
        "Applications/unc0ver.app", "Applications/Checkra1n.app",
        "Applications/Taurine.app",
        "usr/libexec/cydia",
        "private/var/lib/apt", "private/var/lib/dpkg",
        "private/var/jb",
        "private/var/mobile/Library/Cydia",
        "bin/bash", "bin/sh", "usr/bin/ssh",
    )
    for rel in _JB_MARKER_PATHS:
        src_path = input_dir / rel
        if not src_path.exists():
            continue
        dst_path = exports_dir / rel
        if src_path.is_file():
            if _sudo_cp(src_path, dst_path):
                out["jailbreak_markers"] = (
                    out.get("jailbreak_markers", 0) + 1)
        else:
            # Directory — preserve the path as evidence of presence
            dst_path.mkdir(parents=True, exist_ok=True)
            (dst_path / ".keep").write_text(
                f"jailbreak marker directory: {rel}\n")
            out["jailbreak_markers"] = (
                out.get("jailbreak_markers", 0) + 1)

    # Native user-data DBs under /private/var/mobile/Library/
    mob_lib = input_dir / "private" / "var" / "mobile" / "Library"
    mob_lib_out = exports_dir / "private" / "var" / "mobile" / "Library"
    if mob_lib.is_dir():
        for rel, bucket in _MOBILE_LIBRARY_FILES:
            src = mob_lib / rel
            if src.is_file():
                if _sudo_cp(src, mob_lib_out / rel):
                    out[bucket] = out.get(bucket, 0) + 1

    # MobileInstallation — app install lineage
    mi_dir = (input_dir / "private" / "var" / "installd" / "Library"
              / "MobileInstallation")
    if mi_dir.is_dir():
        mi_out = (exports_dir / "private" / "var" / "installd" / "Library"
                  / "MobileInstallation")
        n = _cp_glob(mi_dir, mi_out, "*.plist")
        if n:
            out["mobileinstallation_plists"] = n

    # Provisioning profiles — presence = enterprise/dev-signed apps
    pp_dir = (input_dir / "private" / "var" / "MobileDevice"
              / "ProvisioningProfiles")
    if pp_dir.is_dir():
        pp_out = (exports_dir / "private" / "var" / "MobileDevice"
                  / "ProvisioningProfiles")
        n = _cp_glob(pp_dir, pp_out, "*.mobileprovision")
        if n:
            out["provisioning_profiles"] = n

    # App bundles — pull iTunesMetadata.plist + BundleMetadata.plist +
    # <Name>.app/Info.plist. The Info.plist carries CFBundleIdentifier;
    # the iTunesMetadata carries App Store purchase lineage. Both
    # feed sideloading / messenger detection.
    bundle_root = (input_dir / "private" / "var" / "containers"
                   / "Bundle" / "Application")
    if bundle_root.is_dir():
        bundle_out_root = (exports_dir / "private" / "var" / "containers"
                           / "Bundle" / "Application")
        for guid_dir in bundle_root.iterdir():
            if not guid_dir.is_dir():
                continue
            guid = guid_dir.name
            dst = bundle_out_root / guid
            # iTunesMetadata.plist + BundleMetadata.plist at GUID root
            for fname in ("iTunesMetadata.plist", "BundleMetadata.plist"):
                src = guid_dir / fname
                if src.is_file():
                    if _sudo_cp(src, dst / fname):
                        out["bundle_metadata_plists"] = (
                            out.get("bundle_metadata_plists", 0) + 1)
            # Find <Name>.app/Info.plist — the bundle-id anchor
            try:
                for entry in guid_dir.iterdir():
                    if entry.is_dir() and entry.name.endswith(".app"):
                        info = entry / "Info.plist"
                        if info.is_file():
                            if _sudo_cp(info, dst / entry.name
                                        / "Info.plist"):
                                out["app_info_plists"] = (
                                    out.get("app_info_plists", 0) + 1)
            except (PermissionError, OSError):
                continue

    return out


__all__ = ["extract_ios_artifacts"]
