"""Skill: macOS IR/forensics detectors on extracted artifacts.

Parallel to `linux_triage` and `powershell_triage`. Takes the exports
dir produced by `extract_macos_artifacts` and returns
`MacOSHit` records tagged with MITRE ATT&CK + hypothesis IDs.

V1 detectors:

1. `detect_launch_persistence_suspicious_path` — any LaunchAgent /
   LaunchDaemon plist (system-wide OR per-user) whose
   `ProgramArguments[0]` or `Program` points at `/tmp`, `/private/tmp`,
   `/var/tmp`, or a user-writable path under `/Users/Shared`. Also
   catches plists with shell one-liners in `ProgramArguments[1]` that
   contain `curl`/`wget`/`base64` piped to shell.

2. `detect_shell_history_malicious` — reuses the Linux family pattern
   library (bash/zsh histories on macOS carry the same attacker
   shell tropes).

3. `detect_quarantine_unusual_source` — rows in QuarantineEventsV2
   whose `LSQuarantineOriginURLString` maps to raw IPv4 or unusual
   TLDs (`.pw`, `.cc`, `.top`, `.xyz`). Suggestive of drive-by
   downloads.

4. `detect_safari_downloads_plist_suspicious` — entries in
   Downloads.plist whose target path is under `/tmp` / `/var/tmp` OR
   whose source URL is raw-IP.

All detectors silent on missing files so a clean extract produces
[] rather than crashing.
"""
from __future__ import annotations

import plistlib
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from el.skills._sqlite import EvidenceDBError, open_evidence_db
from el.skills.linux_triage import (
    detect_shell_history_malicious as _linux_shell_detect,
)


_SUSPICIOUS_PATH_MARKERS = (
    "/tmp/", "/private/tmp/", "/var/tmp/",
    "/private/var/tmp/",
    "/users/shared/",
    "/private/var/folders/",
    "/users/guest/",
)


_SUSPICIOUS_TLDS = frozenset({
    "pw", "cc", "top", "xyz", "bid", "click", "download",
    "tk", "ml", "ga", "cf", "gq",
})


@dataclass
class MacOSHit:
    family: str
    matched_pattern: str
    event_count: int = 0
    sample_text: str = ""
    source_files: list[str] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


_FAMILY_HYPOTHESES: dict[str, list[str]] = {
    # The Mac-platform-specific tag fires alongside H_APT_ESPIONAGE so
    # the case-level rollup keeps both: ACH ranks H_MAC_LAUNCH_DAEMON_
    # PERSISTENCE for the local "what kind of persistence?" question
    # and H_APT_ESPIONAGE for "who is doing this?".
    "launch_persistence_suspicious": ["H_MAC_LAUNCH_DAEMON_PERSISTENCE",
                                        "H_APT_ESPIONAGE"],
    "shell_history_malicious":       ["H_LIVING_OFF_THE_LAND",
                                        "H_C2_OR_REVERSE_SHELL"],
    "shell_history_remote_access_screensharing":
                                     ["H_C2_OR_REVERSE_SHELL",
                                      "H_PERSISTENCE_SERVICE"],
    "shell_history_tunnel_vnc":      ["H_C2_OR_REVERSE_SHELL",
                                      "H_LATERAL_MOVEMENT"],
    "quarantine_unusual_source":     ["H_LIVING_OFF_THE_LAND"],
    "safari_downloads_suspicious":   ["H_LIVING_OFF_THE_LAND"],
}


# macOS-only shell-history patterns. Linux_triage carries the cross-
# platform attacker patterns (reverse_shell, download_cradle,
# persistence_ssh, ...). These are macOS-platform-only — they would
# never fire on a Linux history because the commands don't exist
# there. Keeping them isolated stops them from polluting linux runs
# and lets us tag them with macOS-specific ATT&CK techniques.
_MAC_SHELL_PATTERNS: dict[str, tuple[str, ...]] = {
    # Enabling macOS Screen Sharing (VNC) as a remote-access backdoor.
    # The legitimate path is System Preferences → Sharing → Screen
    # Sharing; doing this from the shell is unusual outside MDM
    # context and very common in attacker playbooks for remote takeover.
    "remote_access_screensharing": (
        r"\blaunchctl\s+(?:load|enable|bootstrap)\b.*\b(?:screensharing|"
        r"ScreenSharing|ARDAgent|RemoteDesktop)\b",
        r"\bsystemsetup\s+-setremotelogin\s+on\b",
        r"\bkickstart\s+-(?:activate|configure)\s+-access\b",
    ),
    # SSH local-port-forward of VNC (5900) or Apple Remote Desktop (3283
    # data, 5988 control). Tunneling a GUI-session port through SSH is
    # the canonical "pivot in / persist remote-control" tradecraft.
    "tunnel_vnc": (
        r"\bssh\s+(?:-\S+\s+)*-L\s+\d+:[^\s]*:5900\b",
        r"\bssh\s+(?:-\S+\s+)*-L\s+\d+:[^\s]*:3283\b",
        r"\bssh\s+(?:-\S+\s+)*-L\s+\d+:[^\s]*:5988\b",
        r"\bssh\s+(?:-\S+\s+)*-R\s+\d+:[^\s]*:5900\b",
    ),
}


_MAC_FAMILY_ATTACK: dict[str, list[tuple[str, str]]] = {
    "remote_access_screensharing": [
        ("T1021.005", "Remote Services: VNC"),
        ("T1543.001", "Create or Modify System Process: Launch Agent"),
        ("T1543.004", "Create or Modify System Process: Launch Daemon"),
    ],
    "tunnel_vnc": [
        ("T1572",     "Protocol Tunneling"),
        ("T1021.005", "Remote Services: VNC"),
    ],
}


def hypotheses_for(family: str) -> list[str]:
    return list(_FAMILY_HYPOTHESES.get(family, []))


# ---------------------------------------------------------------------------
# Detector 1: LaunchAgent / LaunchDaemon plist with suspicious path
# ---------------------------------------------------------------------------

def _plist_suspicious_program(doc: dict) -> tuple[bool, str]:
    """Return (is_suspicious, sample_text). True if the plist's
    executable path OR any shell one-liner argument lives in a
    user-writable marker dir, or invokes a download cradle."""
    program = doc.get("Program") or ""
    args = doc.get("ProgramArguments") or []
    if not isinstance(args, list):
        args = []

    candidates: list[str] = []
    if isinstance(program, str):
        candidates.append(program)
    for a in args:
        if isinstance(a, str):
            candidates.append(a)

    joined = "\n".join(candidates).lower()
    for marker in _SUSPICIOUS_PATH_MARKERS:
        if marker in joined:
            return True, joined[:300]
    # Shell cradle patterns inside plist ProgramArguments
    cradle_patterns = (
        r"\bcurl\s+.*\|\s*(?:sh|bash|zsh)\b",
        r"\bwget\s+.*\|\s*(?:sh|bash|zsh)\b",
        r"\bbase64\s+-d\b.*\|\s*(?:sh|bash|zsh)\b",
    )
    for pat in cradle_patterns:
        if re.search(pat, joined, re.IGNORECASE):
            return True, joined[:300]
    return False, ""


def detect_launch_persistence_suspicious_path(
    exports_dir: Path,
) -> list[MacOSHit]:
    root = Path(exports_dir)
    plist_dirs = [
        root / "Library" / "LaunchAgents",
        root / "Library" / "LaunchDaemons",
    ]
    # Walk per-user LaunchAgents too
    users_root = root / "Users"
    if users_root.is_dir():
        for u in users_root.iterdir():
            if u.is_dir():
                p = u / "Library" / "LaunchAgents"
                if p.is_dir():
                    plist_dirs.append(p)

    flagged: list[tuple[Path, str]] = []
    for d in plist_dirs:
        if not d.is_dir():
            continue
        for pl in d.glob("*.plist"):
            try:
                with pl.open("rb") as f:
                    doc = plistlib.load(f)
            except Exception:
                continue
            if not isinstance(doc, dict):
                continue
            ok, sample = _plist_suspicious_program(doc)
            if ok:
                flagged.append((pl, sample))
    if not flagged:
        return []
    return [MacOSHit(
        family="launch_persistence_suspicious",
        matched_pattern=("LaunchAgent/Daemon Program[Arguments] in "
                          "/tmp|/var/tmp|/Users/Shared or shell-cradle"),
        event_count=len(flagged),
        sample_text=flagged[0][1],
        source_files=[str(p) for p, _ in flagged[:10]],
        attack=[("T1543.001", "Create or Modify System Process: Launch Agent"),
                ("T1543.004", "Create or Modify System Process: Launch Daemon")],
    )]


# ---------------------------------------------------------------------------
# Detector 2: macOS shell-history (delegates to linux_triage)
# ---------------------------------------------------------------------------

def detect_shell_history_malicious(exports_dir: Path) -> list[MacOSHit]:
    """Walk macOS shell histories under `Users/<user>/`, scanning each
    line against (1) `linux_triage._SHELL_PATTERNS` — the cross-platform
    attacker patterns (reverse_shell, download_cradle, persistence_ssh,
    ...) and (2) the local `_MAC_SHELL_PATTERNS` — macOS-only
    patterns (launchctl-screensharing enablement, VNC SSH-tunnel).
    The ATT&CK metadata attached to each hit comes from
    `_MAC_FAMILY_ATTACK` first (mac-specific) then
    `linux_triage._FAMILY_ATTACK` (cross-platform)."""
    root = Path(exports_dir)
    users_root = root / "Users"
    if not users_root.is_dir():
        return []
    from collections import Counter, defaultdict
    from el.skills.linux_triage import _SHELL_PATTERNS, _FAMILY_ATTACK

    # Merge cross-platform + macOS-only patterns. macOS keys override
    # if a name collides (none today; this is forward-defensive).
    combined_patterns = {**_SHELL_PATTERNS, **_MAC_SHELL_PATTERNS}

    family_counter: Counter = Counter()
    family_users: dict[str, Counter] = defaultdict(Counter)
    family_files: dict[str, set[str]] = defaultdict(set)
    family_samples: dict[str, str] = {}
    family_pattern: dict[str, str] = {}

    for user_dir in sorted(users_root.iterdir()):
        if not user_dir.is_dir():
            continue
        user = user_dir.name
        for hist in user_dir.iterdir():
            if not hist.is_file():
                continue
            try:
                text = hist.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for family, patterns in combined_patterns.items():
                    for pat in patterns:
                        if re.search(pat, line, re.IGNORECASE):
                            family_counter[family] += 1
                            family_users[family][user] += 1
                            family_files[family].add(str(hist))
                            if family not in family_pattern:
                                family_pattern[family] = pat
                            if family not in family_samples:
                                family_samples[family] = line[:200]
                            break  # one pattern per family per line

    out: list[MacOSHit] = []
    for family, count in family_counter.items():
        out.append(MacOSHit(
            family=f"shell_history_{family}",
            matched_pattern=family_pattern[family],
            event_count=count,
            sample_text=family_samples[family],
            source_files=sorted(family_files[family])[:10],
            attack=_MAC_FAMILY_ATTACK.get(family)
                   or _FAMILY_ATTACK.get(family, []),
        ))
    return out


# ---------------------------------------------------------------------------
# Detector 3: quarantine events from unusual sources
# ---------------------------------------------------------------------------

def _quarantine_db_paths(exports_dir: Path) -> list[Path]:
    root = Path(exports_dir)
    users_root = root / "Users"
    if not users_root.is_dir():
        return []
    out: list[Path] = []
    for u in users_root.iterdir():
        qe = (u / "Library" / "Preferences" /
              "com.apple.LaunchServices.QuarantineEventsV2")
        if qe.is_file():
            out.append(qe)
    return out


def detect_quarantine_unusual_source(
    exports_dir: Path,
) -> list[MacOSHit]:
    dbs = _quarantine_db_paths(exports_dir)
    if not dbs:
        return []
    suspicious: list[tuple[str, str]] = []
    for db in dbs:
        # Copy-then-open: the quarantine DB's newest rows may live only in a
        # -wal sidecar that ?immutable=1 would skip; the copy keeps evidence
        # read-only. See el.skills._sqlite.
        try:
            with open_evidence_db(db) as conn:
                rows = conn.execute(
                    "SELECT LSQuarantineAgentName, "
                    "LSQuarantineOriginURLString, LSQuarantineDataURLString "
                    "FROM LSQuarantineEvent"
                ).fetchall()
        except (sqlite3.Error, EvidenceDBError):
            rows = []
        for agent, origin_url, data_url in rows:
            url = origin_url or data_url or ""
            if not url:
                continue
            # Raw IPv4 in URL
            if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
                suspicious.append((agent or "", url))
                continue
            # Unusual TLD
            m = re.search(r"https?://[^/]+\.([a-z]{2,20})", url.lower())
            if m and m.group(1) in _SUSPICIOUS_TLDS:
                suspicious.append((agent or "", url))
    if not suspicious:
        return []
    sample = suspicious[0][1][:200]
    return [MacOSHit(
        family="quarantine_unusual_source",
        matched_pattern="Quarantine origin URL is raw-IP or on "
                         "suspicious TLD",
        event_count=len(suspicious),
        sample_text=sample,
        source_files=[str(p) for p in dbs],
        attack=[("T1189", "Drive-by Compromise"),
                ("T1204.002", "User Execution: Malicious File")],
    )]


# ---------------------------------------------------------------------------
# Detector 4: Safari Downloads.plist with suspicious target path
# ---------------------------------------------------------------------------

def detect_safari_downloads_plist_suspicious(
    exports_dir: Path,
) -> list[MacOSHit]:
    root = Path(exports_dir)
    users_root = root / "Users"
    if not users_root.is_dir():
        return []
    flagged: list[tuple[str, str]] = []
    sources: list[str] = []
    for u in users_root.iterdir():
        pl = u / "Library" / "Safari" / "Downloads.plist"
        if not pl.is_file():
            continue
        sources.append(str(pl))
        try:
            with pl.open("rb") as f:
                doc = plistlib.load(f)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        history = doc.get("DownloadHistory") or []
        for item in history if isinstance(history, list) else []:
            if not isinstance(item, dict):
                continue
            target = str(item.get("DownloadEntryPath") or "").lower()
            url = str(item.get("DownloadEntryURL") or "")
            if any(m in target for m in _SUSPICIOUS_PATH_MARKERS):
                flagged.append((target, url))
            elif re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
                flagged.append((target, url))
    if not flagged:
        return []
    sample = f"{flagged[0][0]} <- {flagged[0][1]}"
    return [MacOSHit(
        family="safari_downloads_suspicious",
        matched_pattern="Safari download target in /tmp or URL raw-IP",
        event_count=len(flagged),
        sample_text=sample[:300],
        source_files=sources,
        attack=[("T1204.002", "User Execution: Malicious File")],
    )]


ALL_DETECTORS = (
    detect_launch_persistence_suspicious_path,
    detect_shell_history_malicious,
    detect_quarantine_unusual_source,
    detect_safari_downloads_plist_suspicious,
)


def run_all(exports_dir: Path) -> list[MacOSHit]:
    hits: list[MacOSHit] = []
    for fn in ALL_DETECTORS:
        try:
            hits.extend(fn(exports_dir))
        except Exception:
            continue
    return hits


__all__ = [
    "MacOSHit",
    "detect_launch_persistence_suspicious_path",
    "detect_shell_history_malicious",
    "detect_quarantine_unusual_source",
    "detect_safari_downloads_plist_suspicious",
    "ALL_DETECTORS", "run_all", "hypotheses_for",
]
