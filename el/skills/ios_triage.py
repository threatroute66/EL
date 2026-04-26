"""Skill: iOS IR/forensics detectors on extracted artifacts.

Parallel to `android_triage` / `macos_triage`. Consumers pass the
exports dir produced by `extract_ios_artifacts` and get back `IOSHit`
records tagged with MITRE ATT&CK + hypothesis IDs.

V1 detectors:

1. `detect_jailbreak_indicator` — Cydia / Sileo / unc0ver / checkra1n
   markers (/Applications/Cydia.app, /private/var/jb, /usr/libexec/cydia,
   /private/var/lib/apt, /bin/bash). iOS ships with none of these; their
   presence flips the threat model — the iOS sandbox is weakened or
   absent and downstream findings weigh heavier.

2. `detect_sideloaded_app` — any app bundle under
   /private/var/containers/Bundle/Application/<GUID>/ that has NO
   iTunesMetadata.plist (App Store apps always carry one) AND isn't
   one of the system-preinstalled bundles. Sideloaded apps on iOS
   come via enterprise provisioning, TestFlight, or dev signing —
   each of which is a threat-model shift.

3. `detect_provisioning_profile_present` — any file in
   /private/var/MobileDevice/ProvisioningProfiles/. Stock consumer
   iOS devices don't have these; presence indicates enterprise MDM
   enrollment, dev-signed apps, or sideloading infrastructure.

4. `detect_messenger_presence` — known encrypted-messenger and
   privacy-tool app bundles installed (Signal, Telegram, WhatsApp,
   Wickr, Session, Threema, Wire, Kik, Dust, LINE, Viber, ProtonMail,
   Tutanota, Onion Browser, KeepSafe, PhotoVault, Burner). Informational
   pivot point — surfaces to the analyst that encrypted-comms or
   anti-forensic evidence is available.
"""
from __future__ import annotations

import plistlib
from dataclasses import dataclass, field
from pathlib import Path


# iOS-system-default / AOSP-equivalent preinstalled bundle IDs. Any
# app bundle whose CFBundleIdentifier starts with one of these prefixes
# is Apple-first-party and should NOT be flagged as sideloaded even
# when iTunesMetadata.plist is absent (first-party apps typically
# don't carry one).
_FIRST_PARTY_BUNDLE_PREFIXES: tuple[str, ...] = (
    "com.apple.",
)


# Known privacy/encrypted-comms apps worth surfacing for the analyst.
# Keyed on the Name in <GUID>/<Name>.app/ — the directory name is the
# stable hook (CFBundleIdentifier varies across builds/regions).
_MESSENGER_APPS: dict[str, str] = {
    # Encrypted messengers
    "Signal":           "Signal",
    "Telegram":         "Telegram",
    "WhatsApp":         "WhatsApp",
    "Wickr":            "Wickr Me",
    "WickrEnterprise":  "Wickr Enterprise / Pro",
    "WickrPro":         "Wickr Pro",
    "Session":          "Session",
    "Threema":          "Threema",
    "Wire":             "Wire",
    "Element":          "Element (Matrix)",
    "Kik":              "Kik",
    "Dust":             "Dust",
    "LINE":             "LINE",
    "Viber":            "Viber",
    "Skype4Life":       "Skype",
    "Skype":            "Skype",
    # Encrypted email
    "ProtonMail":       "ProtonMail",
    "tutanota":         "Tutanota",
    # Privacy / anti-forensics
    "OnionBrowser":     "Onion Browser (Tor)",
    "Firefox Focus":    "Firefox Focus (anti-tracking)",
    "DuckDuckGo":       "DuckDuckGo Privacy Browser",
    "Brave":            "Brave Browser",
    "KeepSafe":         "KeepSafe (photo hider)",
    "PhotoVault":       "PhotoVault",
    "Burner":           "Burner (disposable phone numbers)",
}


@dataclass
class IOSHit:
    family: str
    matched_pattern: str
    event_count: int = 0
    sample_text: str = ""
    source_files: list[str] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


_FAMILY_HYPOTHESES: dict[str, list[str]] = {
    # Jailbreak indicator on a phone the user didn't own-jailbreak is
    # the canonical Pegasus-class fingerprint — emit the spyware tag
    # alongside H_APT_ESPIONAGE so ACH ranks both at the case level.
    "jailbreak_indicator":         ["H_MOBILE_SPYWARE_PERSISTENCE",
                                      "H_APT_ESPIONAGE",
                                      "H_LIVING_OFF_THE_LAND"],
    "sideloaded_app":              ["H_MOBILE_SIDELOADED_APP",
                                      "H_APT_ESPIONAGE",
                                      "H_OPPORTUNISTIC_COMMODITY"],
    # Provisioning profiles are the iOS MDM mechanism — the family
    # IS the MDM-abuse signal.
    "provisioning_profile":        ["H_MOBILE_MDM_ABUSE",
                                      "H_APT_ESPIONAGE"],
    "messenger_presence":          ["H_DISK_ARTIFACTS"],
}


def hypotheses_for(family: str) -> list[str]:
    return list(_FAMILY_HYPOTHESES.get(family, []))


# ---------------------------------------------------------------------------
# Detector 1: jailbreak indicators
# ---------------------------------------------------------------------------

_JAILBREAK_MARKERS: tuple[tuple[str, str], ...] = (
    # (path_relative_to_root, human_label)
    ("Applications/Cydia.app",                         "Cydia"),
    ("Applications/Sileo.app",                         "Sileo"),
    ("Applications/Zebra.app",                         "Zebra package manager"),
    ("Applications/Installer.app",                     "Installer (legacy JB store)"),
    ("Applications/unc0ver.app",                       "unc0ver jailbreak"),
    ("Applications/Checkra1n.app",                     "checkra1n jailbreak"),
    ("Applications/Taurine.app",                       "Taurine jailbreak"),
    ("usr/libexec/cydia",                              "cydia runtime"),
    ("private/var/lib/apt",                            "APT package database"),
    ("private/var/lib/dpkg",                           "dpkg package database"),
    ("private/var/jb",                                 "/var/jb (rootless jailbreak)"),
    ("private/var/mobile/Library/Cydia",               "Cydia user data"),
    ("bin/bash",                                       "/bin/bash (not on stock iOS)"),
    ("bin/sh",                                         "/bin/sh (not on stock iOS)"),
    ("usr/bin/ssh",                                    "OpenSSH (jailbreak tool)"),
)


def detect_jailbreak_indicator(exports_dir: Path) -> list[IOSHit]:
    root = Path(exports_dir)
    hits: list[tuple[str, str]] = []
    for rel, label in _JAILBREAK_MARKERS:
        p = root / rel
        if p.exists():
            hits.append((str(p), label))
    if not hits:
        return []
    sample = "; ".join(lbl for _, lbl in hits[:5])
    return [IOSHit(
        family="jailbreak_indicator",
        matched_pattern="jailbreak marker present on iOS filesystem",
        event_count=len(hits),
        sample_text=sample,
        source_files=[p for p, _ in hits[:10]],
        attack=[("T1068", "Exploitation for Privilege Escalation"),
                ("T1404", "Exploitation for Privilege Escalation (Mobile)")],
    )]


# ---------------------------------------------------------------------------
# Detector 2: sideloaded apps (no iTunesMetadata.plist, not first-party)
# ---------------------------------------------------------------------------

def _read_bundle_id(info_plist: Path) -> str:
    """Return CFBundleIdentifier or '' on any failure."""
    try:
        with info_plist.open("rb") as f:
            doc = plistlib.load(f)
    except Exception:
        return ""
    if not isinstance(doc, dict):
        return ""
    return str(doc.get("CFBundleIdentifier") or "")


def detect_sideloaded_app(exports_dir: Path) -> list[IOSHit]:
    bundle_root = (Path(exports_dir) / "private" / "var" / "containers"
                   / "Bundle" / "Application")
    if not bundle_root.is_dir():
        return []
    sideloaded: list[tuple[str, str]] = []   # (app_name, bundle_id)
    for guid_dir in bundle_root.iterdir():
        if not guid_dir.is_dir():
            continue
        itunes_meta = guid_dir / "iTunesMetadata.plist"
        # App Store apps always have iTunesMetadata — skip those
        if itunes_meta.is_file():
            continue
        # Find the .app subdir to read CFBundleIdentifier
        try:
            app_dirs = [e for e in guid_dir.iterdir()
                        if e.is_dir() and e.name.endswith(".app")]
        except (PermissionError, OSError):
            continue
        if not app_dirs:
            continue
        app_dir = app_dirs[0]
        bid = _read_bundle_id(app_dir / "Info.plist")
        if bid.startswith(_FIRST_PARTY_BUNDLE_PREFIXES):
            continue      # Apple-preinstalled — OK with no iTunesMetadata
        if not bid:
            continue      # unreadable — don't false-positive
        sideloaded.append((app_dir.name.rsplit(".app", 1)[0], bid))
    if not sideloaded:
        return []
    sample = "; ".join(f"{n} ({b})" for n, b in sideloaded[:5])
    return [IOSHit(
        family="sideloaded_app",
        matched_pattern=("app bundle with no iTunesMetadata.plist and "
                          "non-Apple CFBundleIdentifier"),
        event_count=len(sideloaded),
        sample_text=sample,
        source_files=[str(bundle_root)],
        attack=[("T1476", "Deliver Malicious App via Other Means (Mobile)"),
                ("T1444", "Masquerade as Legitimate Application (Mobile)")],
    )]


# ---------------------------------------------------------------------------
# Detector 3: provisioning profile presence
# ---------------------------------------------------------------------------

def detect_provisioning_profile_present(
    exports_dir: Path,
) -> list[IOSHit]:
    pp_dir = (Path(exports_dir) / "private" / "var" / "MobileDevice"
              / "ProvisioningProfiles")
    if not pp_dir.is_dir():
        return []
    profiles = [p for p in pp_dir.iterdir()
                if p.is_file() and p.suffix == ".mobileprovision"]
    if not profiles:
        return []
    names = [p.name for p in profiles[:5]]
    return [IOSHit(
        family="provisioning_profile",
        matched_pattern=("/private/var/MobileDevice/ProvisioningProfiles/"
                          " non-empty — enterprise/dev-signed apps or MDM"),
        event_count=len(profiles),
        sample_text=", ".join(names),
        source_files=[str(p) for p in profiles[:10]],
        attack=[("T1478", "Install Insecure or Malicious Configuration (Mobile)")],
    )]


# ---------------------------------------------------------------------------
# Detector 4: messenger / privacy-tool app presence
# ---------------------------------------------------------------------------

def detect_messenger_presence(exports_dir: Path) -> list[IOSHit]:
    bundle_root = (Path(exports_dir) / "private" / "var" / "containers"
                   / "Bundle" / "Application")
    if not bundle_root.is_dir():
        return []
    found: list[tuple[str, str]] = []
    source_files: list[str] = []
    for guid_dir in bundle_root.iterdir():
        if not guid_dir.is_dir():
            continue
        try:
            for entry in guid_dir.iterdir():
                if not (entry.is_dir() and entry.name.endswith(".app")):
                    continue
                stem = entry.name.rsplit(".app", 1)[0]
                friendly = _MESSENGER_APPS.get(stem)
                if friendly:
                    found.append((friendly, stem))
                    source_files.append(str(entry))
        except (PermissionError, OSError):
            continue
    if not found:
        return []
    return [IOSHit(
        family="messenger_presence",
        matched_pattern="encrypted-messenger / privacy-tool app(s) installed",
        event_count=len(found),
        sample_text="; ".join(f"{friendly}" for friendly, _ in found),
        source_files=source_files[:10],
        attack=[],      # informational
    )]


ALL_DETECTORS = (
    detect_jailbreak_indicator,
    detect_sideloaded_app,
    detect_provisioning_profile_present,
    detect_messenger_presence,
)


def run_all(exports_dir: Path) -> list[IOSHit]:
    hits: list[IOSHit] = []
    for fn in ALL_DETECTORS:
        try:
            hits.extend(fn(exports_dir))
        except Exception:
            continue
    return hits


__all__ = [
    "IOSHit",
    "detect_jailbreak_indicator", "detect_sideloaded_app",
    "detect_provisioning_profile_present",
    "detect_messenger_presence",
    "ALL_DETECTORS", "run_all", "hypotheses_for",
]
