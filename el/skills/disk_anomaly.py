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
        # Match svchost.exe whose parent dir is NOT exactly System32
        regex=re.compile(rf"{_S}({_NS}+){_S}svchost\.exe\b", re.I),
        hypotheses=["H_LIVING_OFF_THE_LAND", "H_PROCESS_INJECTION"],
        attack_techniques=[("T1036.005", "Masquerading: Match Legitimate Name or Location")],
    ),
    PathPattern(
        pattern_id="LSASS_OUTSIDE_SYSTEM32",
        description="lsass.exe in a path that is NOT Windows/System32/ — disguise of credential subsystem",
        regex=re.compile(rf"{_S}({_NS}+){_S}lsass\.exe\b", re.I),
        hypotheses=["H_CREDENTIAL_ACCESS", "H_PROCESS_INJECTION"],
        attack_techniques=[("T1036.005", "Masquerading: Match Legitimate Name or Location")],
    ),
    PathPattern(
        pattern_id="EXE_IN_TEMP",
        description="Executable in user-writable Temp directory — common dropper pattern",
        regex=re.compile(
            rf"{_S}(?:Temp|AppData{_S}Local{_S}Temp){_S}{_NS}+\."
            r"(?:exe|dll|scr|bat|ps1|hta|js|vbs)\b", re.I),
        hypotheses=["H_OPPORTUNISTIC_COMMODITY"],
        attack_techniques=[("T1059", "Command and Scripting Interpreter")],
    ),
    PathPattern(
        pattern_id="SCHEDULED_TASK_NONMS",
        description="Windows/Tasks/ entry with a non-Microsoft task name — possible scheduled-task persistence",
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
        description="vssadmin / wbadmin shadowcopy strings — ransomware shadow-copy deletion tooling on disk",
        regex=re.compile(
            rf"(?:{_S}(?:vssadmin|wbadmin)\.exe\b|shadowcopy.*delete|delete\s+shadows)",
            re.I),
        hypotheses=["H_RANSOMWARE"],
        attack_techniques=[("T1490", "Inhibit System Recovery")],
    ),
]


# Post-filter for SVCHOST_OUTSIDE_SYSTEM32 / LSASS_OUTSIDE_SYSTEM32: my regex
# captures the parent directory; we reject the match if the parent is exactly
# "System32" (legitimate location).
_LEGIT_PARENTS = {"system32"}


def _post_filter(pattern_id: str, snippet: str) -> bool:
    """Return True if the match should be kept, False if it's a known legit case."""
    if pattern_id in ("SVCHOST_OUTSIDE_SYSTEM32", "LSASS_OUTSIDE_SYSTEM32"):
        s = snippet.lower()
        # If the path segment immediately before svchost/lsass is "system32", drop it
        for term in ("system32/svchost", "system32\\svchost",
                     "system32/lsass", "system32\\lsass"):
            if term in s:
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
    return out


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
