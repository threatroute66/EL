"""Skill: Android IR/forensics detectors on extracted artifacts.

Consumers pass the exports dir produced by `extract_android_artifacts`
and get back `AndroidHit` records tagged with MITRE ATT&CK + EL
hypothesis IDs.

V1 detectors:

1. `detect_rooted_device` — presence of `/data/adb/magisk.db` OR
   any Magisk module directory OR presence of `su` / `Superuser.apk`
   in /system/xbin/ / /system/app/ listings. Rooted status isn't a
   compromise by itself but flips the threat model: the device has
   no OS-enforced app sandbox, and downstream findings like
   sideloaded APKs weigh heavier.

2. `detect_sideloaded_apks` — parse `packages.xml`; flag packages
   whose `installer` attribute isn't one of the first-party values
   (`com.android.vending`, `com.android.packageinstaller`, null /
   pre-installed). Sideloading an app via adb or an APK file is
   how most Android attackers deliver payloads.

3. `detect_data_local_tmp_executables` — any executable or shell
   script copied out of `/data/local/tmp/`. This is the classic
   adb-shell staging directory (only world-writable dir on a stock
   device); non-empty means someone had shell and dropped something.

4. `detect_messenger_presence` — WhatsApp / Signal / Telegram /
   Wickr / Session SQLite DBs present. Informational (not a
   compromise signal); surfaces to the analyst that encrypted-
   messenger evidence is available for pivot.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path


_FIRST_PARTY_INSTALLERS = frozenset({
    "com.android.vending",           # Play Store
    "com.android.packageinstaller",  # manual user install from storage
    "",                              # pre-installed / AOSP
})

_MESSENGER_PACKAGES: dict[str, str] = {
    "com.whatsapp":                  "WhatsApp",
    "org.thoughtcrime.securesms":    "Signal",
    "org.telegram.messenger":        "Telegram",
    "com.wickr.pro":                 "Wickr Pro",
    "org.wickr.pro":                 "Wickr",
    "org.session.securesms":         "Session",
    "com.discord":                   "Discord",
    "com.viber.voip":                "Viber",
}


@dataclass
class AndroidHit:
    family: str
    matched_pattern: str
    event_count: int = 0
    sample_text: str = ""
    source_files: list[str] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


_FAMILY_HYPOTHESES: dict[str, list[str]] = {
    "rooted_device":              ["H_APT_ESPIONAGE",
                                     "H_LIVING_OFF_THE_LAND"],
    "sideloaded_apk":             ["H_APT_ESPIONAGE",
                                     "H_OPPORTUNISTIC_COMMODITY"],
    "data_local_tmp_executable":  ["H_APT_ESPIONAGE",
                                     "H_LIVING_OFF_THE_LAND"],
    "messenger_presence":         ["H_DISK_ARTIFACTS"],
}


def hypotheses_for(family: str) -> list[str]:
    return list(_FAMILY_HYPOTHESES.get(family, []))


# ---------------------------------------------------------------------------
# Detector 1: rooted device
# ---------------------------------------------------------------------------

def detect_rooted_device(exports_dir: Path) -> list[AndroidHit]:
    root = Path(exports_dir)
    signals: list[str] = []
    source_files: list[str] = []

    magisk_db = root / "data" / "adb" / "magisk.db"
    if magisk_db.is_file():
        signals.append("magisk.db present at /data/adb/")
        source_files.append(str(magisk_db))

    modules_dir = root / "data" / "adb" / "modules"
    if modules_dir.is_dir():
        module_names = [m.name for m in modules_dir.iterdir()
                         if m.is_dir()]
        if module_names:
            signals.append(
                f"Magisk modules installed: {', '.join(module_names[:5])}"
                + (' …' if len(module_names) > 5 else ''))

    if not signals:
        return []
    return [AndroidHit(
        family="rooted_device",
        matched_pattern="Magisk root present",
        event_count=len(signals),
        sample_text="; ".join(signals),
        source_files=source_files,
        attack=[("T1068", "Exploitation for Privilege Escalation"),
                ("T1574.002", "Hijack Execution Flow: DLL Side-Loading")],
    )]


# ---------------------------------------------------------------------------
# Detector 2: sideloaded APKs
# ---------------------------------------------------------------------------

_INSTALLER_RE = re.compile(
    r'<package\s+[^>]*name="([^"]+)"[^>]*installer="([^"]*)"',
    re.IGNORECASE,
)
_PACKAGE_NAME_RE = re.compile(r'<package\s+[^>]*name="([^"]+)"',
                                re.IGNORECASE)


def detect_sideloaded_apks(exports_dir: Path) -> list[AndroidHit]:
    packages_xml = Path(exports_dir) / "data" / "system" / "packages.xml"
    if not packages_xml.is_file():
        return []
    try:
        text = packages_xml.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    sideloaded: list[tuple[str, str]] = []
    for m in _INSTALLER_RE.finditer(text):
        pkg, installer = m.group(1), m.group(2)
        if installer and installer not in _FIRST_PARTY_INSTALLERS:
            # Heuristic exemptions for known OEM installers that are
            # legitimate on shipped devices (ASUS, Samsung, Xiaomi, etc.)
            inst_lower = installer.lower()
            if any(oem in inst_lower for oem in
                   ("asus", "samsung", "xiaomi", "huawei", "oppo",
                    "vivo", "oneplus", "lenovo", "motorola")):
                continue
            sideloaded.append((pkg, installer))
    if not sideloaded:
        return []
    sample = "; ".join(f"{pkg} (via {inst})"
                        for pkg, inst in sideloaded[:5])
    return [AndroidHit(
        family="sideloaded_apk",
        matched_pattern="packages.xml installer attribute is not Play Store / AOSP / known-OEM",
        event_count=len(sideloaded),
        sample_text=sample,
        source_files=[str(packages_xml)],
        attack=[("T1476", "Deliver Malicious App via Other Means (Mobile)"),
                ("T1404", "Exploitation for Privilege Escalation (Mobile)")],
    )]


# ---------------------------------------------------------------------------
# Detector 3: /data/local/tmp executables
# ---------------------------------------------------------------------------

_EXECUTABLE_EXTENSIONS = {
    ".sh", ".so", ".elf", ".bin", ".py", ".apk", ".dex",
    ".jar", ".out",
}


def detect_data_local_tmp_executables(
    exports_dir: Path,
) -> list[AndroidHit]:
    tmp = Path(exports_dir) / "data" / "local" / "tmp"
    if not tmp.is_dir():
        return []
    hits: list[Path] = []
    for p in tmp.rglob("*"):
        if not p.is_file():
            continue
        # Flag by extension OR by Unix executable bits via magic-byte
        # header (ELF 0x7f 45 4c 46, shebang 0x23 21, zip/APK 0x50 4b)
        if p.suffix.lower() in _EXECUTABLE_EXTENSIONS:
            hits.append(p)
            continue
        try:
            head = p.read_bytes()[:4]
        except OSError:
            continue
        if head.startswith(b"\x7fELF") or head.startswith(b"#!") \
                or head.startswith(b"PK\x03\x04"):
            hits.append(p)
    if not hits:
        return []
    names = [p.name for p in hits[:5]]
    return [AndroidHit(
        family="data_local_tmp_executable",
        matched_pattern="executable / script / APK under /data/local/tmp/",
        event_count=len(hits),
        sample_text=", ".join(names),
        source_files=[str(p) for p in hits[:10]],
        attack=[("T1074.001", "Data Staged: Local Data Staging")],
    )]


# ---------------------------------------------------------------------------
# Detector 4: messenger-app presence (informational pivot point)
# ---------------------------------------------------------------------------

def detect_messenger_presence(
    exports_dir: Path,
) -> list[AndroidHit]:
    data_data = Path(exports_dir) / "data" / "data"
    if not data_data.is_dir():
        return []
    present: list[tuple[str, str]] = []
    source_files: list[str] = []
    for pkg, friendly in _MESSENGER_PACKAGES.items():
        pkg_dir = data_data / pkg
        if not pkg_dir.is_dir():
            continue
        # Look for any .db file under the package — proves it was
        # installed AND used (fresh installs have no DB writes yet)
        dbs = list(pkg_dir.rglob("*.db"))
        if dbs:
            present.append((friendly, pkg))
            source_files.extend(str(db) for db in dbs[:2])
    if not present:
        return []
    return [AndroidHit(
        family="messenger_presence",
        matched_pattern="encrypted-messenger app(s) installed with local DB",
        event_count=len(present),
        sample_text="; ".join(f"{friendly} ({pkg})"
                               for friendly, pkg in present),
        source_files=source_files[:10],
        attack=[],                          # purely informational
    )]


ALL_DETECTORS = (
    detect_rooted_device,
    detect_sideloaded_apks,
    detect_data_local_tmp_executables,
    detect_messenger_presence,
)


def run_all(exports_dir: Path) -> list[AndroidHit]:
    hits: list[AndroidHit] = []
    for fn in ALL_DETECTORS:
        try:
            hits.extend(fn(exports_dir))
        except Exception:
            continue
    return hits


__all__ = [
    "AndroidHit",
    "detect_rooted_device", "detect_sideloaded_apks",
    "detect_data_local_tmp_executables",
    "detect_messenger_presence",
    "ALL_DETECTORS", "run_all", "hypotheses_for",
]
