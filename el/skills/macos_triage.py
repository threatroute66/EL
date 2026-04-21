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
    "launch_persistence_suspicious": ["H_PERSISTENCE_SERVICE",
                                        "H_APT_ESPIONAGE"],
    "shell_history_malicious":       ["H_LIVING_OFF_THE_LAND",
                                        "H_C2_OR_REVERSE_SHELL"],
    "quarantine_unusual_source":     ["H_LIVING_OFF_THE_LAND"],
    "safari_downloads_suspicious":   ["H_LIVING_OFF_THE_LAND"],
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
    """Route through linux_triage's family library — the shell
    patterns are identical on macOS (same bash/zsh, same attacker
    tropes). Adapter re-boxes LinuxHit → MacOSHit."""
    # linux_triage expects `<exports>/home/<user>/.bash_history`
    # layout. macOS layout is `<exports>/Users/<user>/`. Construct
    # a symlinked shim on the fly so we don't have to duplicate the
    # scanner code.
    root = Path(exports_dir)
    users_root = root / "Users"
    if not users_root.is_dir():
        return []
    # Walk Users/ directly — skip the adapter detour
    from collections import Counter, defaultdict
    from el.skills.linux_triage import _SHELL_PATTERNS, _scan_text, _FAMILY_ATTACK

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
                per_family: dict[str, list[str]] = \
                    {k: [] for k in _SHELL_PATTERNS}
                _scan_text(line, per_family)
                for family, matches in per_family.items():
                    if not matches:
                        continue
                    family_counter[family] += 1
                    family_users[family][user] += 1
                    family_files[family].add(str(hist))
                    if family not in family_pattern:
                        family_pattern[family] = matches[0]
                    if family not in family_samples:
                        family_samples[family] = line[:200]

    out: list[MacOSHit] = []
    for family, count in family_counter.items():
        out.append(MacOSHit(
            family=f"shell_history_{family}",
            matched_pattern=family_pattern[family],
            event_count=count,
            sample_text=family_samples[family],
            source_files=sorted(family_files[family])[:10],
            attack=_FAMILY_ATTACK.get(family, []),
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
        try:
            uri = f"file:{db.resolve()}?mode=ro&immutable=1"
            conn = sqlite3.connect(uri, uri=True)
        except sqlite3.Error:
            continue
        try:
            rows = conn.execute(
                "SELECT LSQuarantineAgentName, "
                "LSQuarantineOriginURLString, LSQuarantineDataURLString "
                "FROM LSQuarantineEvent"
            ).fetchall()
        except sqlite3.Error:
            rows = []
        finally:
            conn.close()
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
