"""Skill: disk-side anomaly patterns.

Walks an fls bodyfile (or mactime CSV) for SKILL-documented suspicious
file-path patterns and returns per-pattern hits with hypothesis tags.

Conservative library: each pattern is a known operator signal documented
in Protocol SIFT skill files or Mandiant/MITRE write-ups. We do not invent
detections — every pattern here has at least one real-case justification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PathHit:
    pattern_id: str
    description: str
    matches: list[str]
    hypotheses: list[str]
    attack_techniques: list[tuple[str, str]] = field(default_factory=list)
    # Earliest / latest non-zero mtime (Unix seconds) across matched
    # rows when the detector parses bodyfile columns. None for path-
    # pattern matches that scan text without line-level structure.
    # Populated by row-wise detectors so anomaly findings can carry
    # real artifact time on the kill-chain swimlane.
    earliest_unix: int | None = None
    latest_unix: int | None = None


@dataclass
class PathPattern:
    pattern_id: str
    description: str
    regex: re.Pattern
    hypotheses: list[str]
    attack_techniques: list[tuple[str, str]]
    max_samples: int = 10


# Patterns are ordered most-specific to least-specific. All matched against
# the raw bodyfile/mactime text (case-insensitive). Match is on the full
# path, not just basename, to keep context.
# Path-separator class: fls bodyfile uses `/`, EZT/CSV outputs may use `\`.
# We accept both throughout.
_S = r"[/\\]"  # separator
_NS = r"[^/\\\r\n|]"  # not-separator-not-newline-not-pipe (single segment)


PATTERNS: list[PathPattern] = [
    PathPattern(
        pattern_id="PSEXEC_SERVICE_ARTIFACT",
        description="PsExec service binary (PSEXESVC.EXE) — classic remote-RCE / lateral-movement footprint",
        regex=re.compile(rf"{_S}PSEXESVC(?:\.EXE)?\b", re.I),
        hypotheses=["H_LATERAL_MOVEMENT", "H_LIVING_OFF_THE_LAND"],
        attack_techniques=[("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
                           ("T1569.002", "System Services: Service Execution")],
    ),
    PathPattern(
        pattern_id="PYINSTALLER_TEMP_DIR",
        description="PyInstaller _MEI temp directory — Python script packaged as standalone .exe; common dropper / RAT packaging",
        regex=re.compile(rf"{_S}_MEI\d{{2,8}}{_S}", re.I),
        hypotheses=["H_OPPORTUNISTIC_COMMODITY", "H_PROCESS_INJECTION"],
        attack_techniques=[("T1027.002", "Obfuscated Files or Information: Software Packing")],
    ),
    PathPattern(
        pattern_id="SVCHOST_OUTSIDE_SYSTEM32",
        description="svchost.exe in a path that is NOT Windows/System32/ — disguise pattern (legitimate svchost only lives in System32)",
        # Match svchost.exe whose parent dir is NOT exactly System32.
        # Anchor the `.exe` tail with "end of path segment" rather than \b
        # so Prefetch filenames like SVCHOST.EXE-3530F672.pf don't match.
        regex=re.compile(
            rf"{_S}({_NS}+){_S}svchost\.exe(?=[|\s]|$)", re.I),
        hypotheses=["H_LIVING_OFF_THE_LAND", "H_PROCESS_INJECTION"],
        attack_techniques=[("T1036.005", "Masquerading: Match Legitimate Name or Location")],
    ),
    PathPattern(
        pattern_id="LSASS_OUTSIDE_SYSTEM32",
        description="lsass.exe in a path that is NOT Windows/System32/ — disguise of credential subsystem",
        regex=re.compile(
            rf"{_S}({_NS}+){_S}lsass\.exe(?=[|\s]|$)", re.I),
        hypotheses=["H_CREDENTIAL_ACCESS", "H_PROCESS_INJECTION"],
        attack_techniques=[("T1036.005", "Masquerading: Match Legitimate Name or Location")],
    ),
    PathPattern(
        pattern_id="EXE_IN_TEMP",
        description="Executable in user-writable Temp directory — common dropper pattern",
        regex=re.compile(
            rf"{_S}(?:Temp|AppData{_S}Local{_S}Temp){_S}{_NS}+\."
            r"(?:exe|dll|scr|bat|ps1|hta|js|vbs)(?=[|\s]|$)", re.I),
        hypotheses=["H_OPPORTUNISTIC_COMMODITY"],
        attack_techniques=[("T1059", "Command and Scripting Interpreter")],
    ),
    PathPattern(
        pattern_id="SCHEDULED_TASK_NONMS",
        description="Windows/Tasks/ entry with a non-Microsoft task name — possible scheduled-task persistence",
        # Narrowed from match-everything in Tasks/: require a .job file
        # (XP/7 at-jobs) OR a file with no extension but a non-stock name.
        # Stock Windows files in Tasks/ (desktop.ini, SA.DAT) are excluded
        # via _post_filter.
        regex=re.compile(rf"{_S}Windows{_S}Tasks{_S}(?!Microsoft)[A-Za-z0-9_.-]+", re.I),
        hypotheses=["H_PERSISTENCE_SCHEDULED_TASK"],
        attack_techniques=[("T1053.005", "Scheduled Task/Job: Scheduled Task")],
    ),
    PathPattern(
        pattern_id="MIMIKATZ_NAMED_BINARY",
        description="File literally named mimikatz / sekurlsa / kiwi — operator-named credential-dumping tooling left on disk",
        regex=re.compile(
            rf"{_S}(?:mimikatz|sekurlsa|kiwi)(?:[.\-_][a-z0-9]+)?\.(?:exe|dll|kirbi)\b",
            re.I),
        hypotheses=["H_CREDENTIAL_ACCESS"],
        attack_techniques=[("T1003.001", "OS Credential Dumping: LSASS Memory")],
    ),
    PathPattern(
        pattern_id="RECYCLE_BIN_EXE",
        description="Executable inside $Recycle.Bin — anti-forensic / persistence",
        regex=re.compile(rf"{_S}\$Recycle\.Bin{_S}{_NS}+\.(?:exe|dll|scr|bat)\b", re.I),
        hypotheses=["H_PROCESS_INJECTION"],
        attack_techniques=[("T1564.001", "Hide Artifacts: Hidden Files and Directories")],
    ),
    PathPattern(
        pattern_id="VSSADMIN_DELETE_SHADOWS_TRACE",
        description="Shadow-copy deletion command strings — ransomware / anti-forensic inhibit-recovery pattern",
        # Narrowed: was also matching the mere EXISTENCE of vssadmin.exe
        # or wbadmin.exe anywhere on disk — these are Windows built-ins
        # present on every host. Real signal is a command-line-shaped
        # trace (prefetch execution string, PowerShell transcript, etc.),
        # not the binary's presence. Keep only the command-shape alternates.
        regex=re.compile(
            r"(?:"
            r"vssadmin(?:\.exe)?\s+delete\s+shadows"
            r"|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstate)"
            r"|shadowcopy[^|\n]{0,40}delete"
            r"|delete\s+shadows\s*/all"
            r")",
            re.I),
        hypotheses=["H_RANSOMWARE"],
        attack_techniques=[("T1490", "Inhibit System Recovery")],
    ),
]


# Direct-parent directory names (case-insensitive) that hold legitimate
# svchost.exe / lsass.exe copies. These are NOT masquerade — they're
# standard Windows component stores placed by install / service-pack /
# file-protection / side-by-side.
#
# The regex for SVCHOST_/LSASS_OUTSIDE_SYSTEM32 captures the direct parent
# in group(1); we reject only when that SPECIFIC parent is in this set.
# A nested path like Windows/System32/dllhost/svchost.exe (parent =
# "dllhost", grandparent = "System32") is STILL flagged because the
# immediate parent is suspicious even if the ancestor tree is legit.
_LEGIT_PARENT_DIRS = {
    "system32",                    # legitimate runtime location
    "syswow64",                    # 32-bit-on-64-bit legitimate location
    "dllcache",                    # Windows File Protection cache (XP/2003)
    "i386",                        # install image source (matches on
    "amd64",                       # <win>/ServicePackFiles/i386/lsass.exe)
}

# Ancestor-tree fragments (any path segment anywhere in the snippet)
# that indicate a known Windows backup / cache area. Unlike the
# direct-parent list, these disqualify the whole subtree: e.g. anything
# under $NtServicePackUninstall$/ is SP rollback backup, anything under
# winsxs/ is side-by-side, etc.
_LEGIT_ANCESTOR_FRAGMENTS = (
    "servicepackfiles",            # SP install cache
    "ntservicepackuninstall",      # SP rollback backup
    "winsxs",                      # Win7+ side-by-side assembly store
    "$hf_mig$",                    # hotfix migration backup
)

# Installer-temp paths. MSI/InstallShield/VMware/etc. extract to
# dirs like Temp/00006b1c/, Temp/_IS<letters>/, Temp/{GUID}/,
# Temp/Installer<N>/. Executables landing there are benign installer
# unpacks — very common, very noisy. Filter by looking for a path
# segment that follows the Temp/AppData/Local/Temp/ prefix and matches
# a known installer shape.
_INSTALLER_TEMP_SEGMENT = re.compile(
    r"(?i)(?:temp|appdata[/\\]local[/\\]temp)[/\\]"
    r"(?:"
    r"[0-9a-f]{6,}"                # MSI hex dir (e.g. 00006b1c)
    r"|_is[a-z0-9]+"               # InstallShield _ISxxxxx
    r"|\{[0-9a-f-]{8,}\}"          # {GUID} or {partial guid}
    r"|installer[0-9]*"            # Installer*
    r"|msi[0-9a-z]{2,}\.tmp"       # msi*.tmp extract
    r")[/\\]"
)

# Extract the DIRECT parent dir name for an svchost/lsass match.
# Operates on the match snippet (which may or may not contain the full
# captured group, depending on scan_text's context window). Looks for
# the pattern "<sep><PARENT><sep>svchost.exe" and returns PARENT.
_SVCHOST_LSASS_PARENT = re.compile(
    r"[/\\]([^/\\]+)[/\\](?:svchost|lsass)\.exe", re.I)


# Stock filenames that always live under Windows/Tasks/ on a clean
# Windows install — desktop preferences + the task scheduler's own
# state file. Not persistence artifacts.
_STOCK_TASKS_FILES = {"desktop.ini", "sa.dat"}


def _post_filter(pattern_id: str, snippet: str) -> bool:
    """Return True if the match should be kept, False if it's a known legit case."""
    s = snippet.lower()
    if pattern_id in ("SVCHOST_OUTSIDE_SYSTEM32", "LSASS_OUTSIDE_SYSTEM32"):
        # Direct-parent check: reject if immediate parent dir is one of
        # the legitimate runtime/install locations.
        m = _SVCHOST_LSASS_PARENT.search(s)
        if m and m.group(1).lower() in _LEGIT_PARENT_DIRS:
            return False
        # Ancestor-tree check: reject if the path passes through a known
        # backup / SP-cache / side-by-side area.
        for frag in _LEGIT_ANCESTOR_FRAGMENTS:
            if frag in s:
                return False
    if pattern_id == "EXE_IN_TEMP":
        # MSI / InstallShield / VMware-Tools installer unpacks land in
        # Temp/<hex>/, Temp/_IS*/, Temp/{GUID}/ etc. Real droppers don't
        # use these structured subdirs — an .exe directly in Temp/ is still
        # flagged, but known installer shapes are excluded.
        if _INSTALLER_TEMP_SEGMENT.search(s):
            return False
    if pattern_id == "SCHEDULED_TASK_NONMS":
        # desktop.ini / SA.DAT are stock Windows files — desktop folder
        # preferences + the task-scheduler service's own data file. Every
        # clean Windows install has them; they are not persistence.
        for stock in _STOCK_TASKS_FILES:
            if f"/tasks/{stock}" in s or f"\\tasks\\{stock}" in s:
                return False
    return True


def scan_text(text: str) -> list[PathHit]:
    """Match each pattern against the text and return hits in order."""
    out: list[PathHit] = []
    for p in PATTERNS:
        seen: list[str] = []
        for m in p.regex.finditer(text):
            snippet = text[max(0, m.start() - 32):min(len(text), m.end() + 32)]
            snippet = snippet.replace("\r", "").replace("\n", " ").strip()
            if not _post_filter(p.pattern_id, snippet):
                continue
            if snippet not in seen:
                seen.append(snippet)
            if len(seen) >= p.max_samples:
                break
        if seen:
            out.append(PathHit(
                pattern_id=p.pattern_id,
                description=p.description,
                matches=seen,
                hypotheses=list(p.hypotheses),
                attack_techniques=list(p.attack_techniques),
            ))
    # Row-level detector: zero-size / zero-timestamp Windows system
    # binaries — the anti-forensic pattern jynxora flagged on M57-Jean
    # (debug.exe / ipconfig.exe / wscntfy.exe etc. wiped to 0 bytes
    # with 0000-00-00 timestamps under /WINDOWS/system32 + /dllcache +
    # /ServicePackFiles). bodyfile columns are
    # md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
    out.extend(_scan_bodyfile_rowwise(text))
    return out


_SYSTEM_BIN_PATH_RE = re.compile(
    r"[/\\](?:"
    r"WINDOWS[/\\]system32(?:[/\\]dllcache)?"
    r"|WINDOWS[/\\]ServicePackFiles[/\\](?:i386|amd64)"
    r"|Windows[/\\]System32(?:[/\\]dllcache)?"
    r"|Windows[/\\]ServicePackFiles[/\\](?:i386|amd64)"
    r")[/\\][^/\\|\r\n]+\.(?:exe|dll|sys)\b",
    re.I,
)


def _scan_bodyfile_rowwise(text: str) -> list[PathHit]:
    """Parse pipe-delimited fls bodyfile lines. Three detectors:

    1. System binaries with size=0 (zeroed-out-after-execution wipe).
    2. System binaries with all four MACB timestamps zero.
    3. **MACB timestomp skew**: any $DATA row where crtime (B) predates
       mtime (M) by ≥ 7 days and all four timestamps are non-zero.
       Every tool that timestomps to a plausible-looking earlier date
       (TimestompPro, SetMACE, PowerShell `[DateTime]`, attrib) leaves
       this footprint — B-time can't be legitimately years before M-time
       on the same inode. The 7-day floor absorbs DST / timezone shifts
       and restored-from-backup cases; anything beyond is deliberate.
       Detector #2 catches the degenerate "all zeroes" case; this one
       catches the realistic case.
    """
    zero_size: list[str] = []
    zero_size_mtimes: list[int] = []
    zero_ts: list[str] = []
    macb_skew: list[str] = []
    macb_skew_mtimes: list[int] = []
    # Floor: crtime more than SEVEN_DAYS before mtime is the trip point.
    _SKEW_FLOOR_SECONDS = 7 * 24 * 60 * 60
    for line in text.splitlines():
        if "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 11:
            continue
        name = parts[1]
        try:
            size = int(parts[6] or "0")
            atime = int(parts[7] or "0")
            mtime = int(parts[8] or "0")
            ctime = int(parts[9] or "0")
            crtime = int(parts[10] or "0")
        except ValueError:
            continue
        # FILE_NAME attribute rows (NTFS 48-2) often have size=0 legitimately;
        # only flag DATA rows (mode shows $DATA or no $-suffix)
        is_fname_attr = "($FILE_NAME)" in name
        is_directory = len(parts) > 3 and parts[3].startswith("d/")
        is_system_path = bool(_SYSTEM_BIN_PATH_RE.search(name))

        if is_system_path and size == 0 and not is_fname_attr:
            if len(zero_size) < 15:
                zero_size.append(name[-120:])
            if mtime > 0:
                zero_size_mtimes.append(mtime)
        if (is_system_path and atime == mtime == ctime == crtime == 0
                and not is_fname_attr):
            if len(zero_ts) < 15:
                zero_ts.append(name[-120:])

        # MACB skew: applies to every $DATA row (not system-path-only),
        # since real attackers timestomp user files, too — the Rathbun
        # anti-forensics reference image demonstrates exactly this.
        if (not is_fname_attr and not is_directory
                and atime and mtime and ctime and crtime
                and mtime - crtime >= _SKEW_FLOOR_SECONDS):
            if len(macb_skew) < 15:
                days = (mtime - crtime) // 86400
                macb_skew.append(f"{name[-120:]} (B→M skew {days} days)")
            macb_skew_mtimes.append(mtime)
    hits: list[PathHit] = []
    if zero_size:
        hits.append(PathHit(
            pattern_id="SYSTEM_BINARY_ZERO_SIZE",
            description=("Windows system binary / DLL / driver with "
                         "size=0 — anti-forensic wipe of a binary the "
                         "attacker executed (jynxora M57-Jean signature)"),
            matches=zero_size,
            hypotheses=["H_ANTI_FORENSICS", "H_LOG_CLEARED"],
            attack_techniques=[
                ("T1070.004",
                  "Indicator Removal: File Deletion"),
                ("T1565.001",
                  "Stored Data Manipulation"),
            ],
            earliest_unix=min(zero_size_mtimes) if zero_size_mtimes else None,
            latest_unix=max(zero_size_mtimes) if zero_size_mtimes else None,
        ))
    if zero_ts:
        hits.append(PathHit(
            pattern_id="SYSTEM_BINARY_ZERO_TIMESTAMPS",
            description=("Windows system binary with all four MACB "
                         "timestamps zero — timestomping / anti-forensic "
                         "tampering of a system file"),
            matches=zero_ts,
            hypotheses=["H_ANTI_FORENSICS"],
            attack_techniques=[
                ("T1070.006", "Indicator Removal: Timestomp"),
            ],
        ))
    if macb_skew:
        hits.append(PathHit(
            pattern_id="MACB_TIMESTOMP_SKEW",
            description=("File with crtime (B) more than 7 days before "
                         "mtime (M) on the same inode — created-in-the-"
                         "past while modified-now is the signature of "
                         "deliberate timestomping (TimestompPro, SetMACE, "
                         "PowerShell [DateTime], attrib). Unlike "
                         "SYSTEM_BINARY_ZERO_TIMESTAMPS this fires on "
                         "user files too, since real attackers timestomp "
                         "payloads they plant under /Users/."),
            matches=macb_skew,
            hypotheses=["H_ANTI_FORENSICS"],
            attack_techniques=[
                ("T1070.006", "Indicator Removal: Timestomp"),
            ],
            earliest_unix=min(macb_skew_mtimes) if macb_skew_mtimes else None,
            latest_unix=max(macb_skew_mtimes) if macb_skew_mtimes else None,
        ))
    return hits


def scan_file(path: Path, max_bytes: int = 200 * 1024 * 1024) -> list[PathHit]:
    """Scan a bodyfile or mactime CSV. Caps at ~200MB by default to keep the
    pass bounded on huge timelines; substring-style patterns work fine on
    truncated input — the SKILL says first ~200MB of fls bodyfile already
    contains the system file tree."""
    try:
        with path.open("r", errors="ignore") as f:
            text = f.read(max_bytes)
    except Exception:
        return []
    return scan_text(text)
