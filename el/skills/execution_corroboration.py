"""Skill: Windows execution-artifact cross-correlation.

SANS Windows Forensics poster "Program Execution" section lists eight
independent evidence sources: UserAssist, Shimcache, BAM/DAM, Amcache,
SRUM, Last-Visited MRU, Windows 10 Timeline, Prefetch. Each can miss
some executions (Shimcache doesn't mean definitely-ran; Prefetch caps
at 128/1024 files; Amcache only records binaries with PE header). The
stronger signal is CORROBORATION — an executable that appears in ≥2
independent sources ran for real.

This skill walks the CSVs EL's windows_artifact agent already produces
and emits per-executable corroboration counts:

   ExecutionEntry(name_lc, full_path, sources: {shimcache, prefetch,
   amcache, userassist, ...}, last_seen_utc, notes)

The agent turns entries with ≥2 sources into high-confidence findings.

Schemas this skill knows (from EZ Tools CSV output):

  AppCompatCacheParser shimcache.csv
      ControlSet, CacheEntryPosition, Path, LastModifiedTimeUTC,
      Executed (True/False), Duplicate, SourceFile

  PECmd prefetch CSV (both per-file and aggregate 'prefetch.csv')
      SourceFilename, SourceCreated, SourceModified, SourceAccessed,
      ExecutableName, Hash, Size, Version, RunCount, LastRun,
      PreviousRun0..7, Volume0Name, ...

  AmcacheParser UnassociatedFileEntries.csv
      ApplicationName, ProgramId, FileId, LowerCaseLongPath, LongPath,
      Name, Publisher, Version, ... FileIDLastWriteTimestamp

  RECmd UserAssist (Kroll_Batch "UserAssist" plugin)
      Timestamp, BatchKeyPath, ProgramName, BatchValueName, ...

Graceful: missing CSVs are silent skips; malformed rows silently
ignored; timestamps parsed best-effort.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path


# --- Normalized record ----------------------------------------------------

@dataclass
class ExecutionHit:
    name_lc: str                      # lowercase basename, e.g. "cmd.exe"
    full_path: str = ""
    source: str = ""                  # "shimcache" / "prefetch" / ...
    last_seen: str = ""               # raw timestamp as written by the tool
    extra: dict = field(default_factory=dict)


@dataclass
class ExecutionEntry:
    """Aggregated view for a single executable basename."""
    name_lc: str
    sources: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    last_seen_by_source: dict[str, str] = field(default_factory=dict)
    hit_count: int = 0

    @property
    def corroboration(self) -> int:
        return len(self.sources)


# --- Per-source parsers ---------------------------------------------------

def _basename_lc(path: str) -> str:
    """Return the lowercase final path segment from a Windows-style path."""
    p = (path or "").strip().replace("\\", "/")
    return p.rsplit("/", 1)[-1].lower()


def _read_csv(path: Path) -> list[dict]:
    try:
        with path.open(newline="", errors="ignore") as f:
            # Handle BOM
            reader = csv.DictReader((line.lstrip("\ufeff") for line in f))
            return list(reader)
    except Exception:
        return []


def parse_shimcache(csv_path: Path) -> list[ExecutionHit]:
    out: list[ExecutionHit] = []
    for r in _read_csv(csv_path):
        path = r.get("Path", "")
        if not path:
            continue
        # Shimcache's "Executed" flag is heuristic; we still record it as a
        # source because presence in the cache implies the file was at least
        # resolved by the OS for compat-check.
        out.append(ExecutionHit(
            name_lc=_basename_lc(path),
            full_path=path, source="shimcache",
            last_seen=r.get("LastModifiedTimeUTC", ""),
            extra={"Executed": r.get("Executed", "")},
        ))
    return out


def parse_prefetch(csv_path: Path) -> list[ExecutionHit]:
    out: list[ExecutionHit] = []
    for r in _read_csv(csv_path):
        exe = r.get("ExecutableName", "") or r.get("SourceFilename", "")
        if not exe:
            continue
        # PECmd ExecutableName is usually just the basename already (e.g.
        # "CMD.EXE"). Normalize to lowercase.
        name_lc = _basename_lc(exe)
        out.append(ExecutionHit(
            name_lc=name_lc,
            full_path=r.get("SourceFilename", ""),
            source="prefetch",
            last_seen=r.get("LastRun", ""),
            extra={"RunCount": r.get("RunCount", ""),
                   "Hash": r.get("Hash", "")},
        ))
    return out


def parse_amcache(csv_path: Path) -> list[ExecutionHit]:
    out: list[ExecutionHit] = []
    for r in _read_csv(csv_path):
        # UnassociatedFileEntries: LowerCaseLongPath is the canonical path.
        # Other Amcache CSV flavours fall back to Name / LongPath.
        path = (r.get("LowerCaseLongPath")
                or r.get("LongPath") or r.get("Name") or "")
        if not path:
            continue
        out.append(ExecutionHit(
            name_lc=_basename_lc(path),
            full_path=path, source="amcache",
            last_seen=(r.get("FileIDLastWriteTimestamp")
                       or r.get("FirstRun", "")),
            extra={"SHA1": r.get("SHA1", "") or r.get("Hash", ""),
                   "Publisher": r.get("Publisher", "")},
        ))
    return out


def parse_userassist(csv_path: Path) -> list[ExecutionHit]:
    """RECmd UserAssist plugin output. ProgramName column holds the
    launch target; some rows point at CLSIDs / shortcuts rather than
    real EXE names — we keep only rows whose ProgramName ends in .exe
    to avoid polluting the corroboration."""
    out: list[ExecutionHit] = []
    for r in _read_csv(csv_path):
        prog = (r.get("ProgramName") or "").strip()
        if not prog.lower().endswith(".exe"):
            continue
        out.append(ExecutionHit(
            name_lc=_basename_lc(prog),
            full_path=prog, source="userassist",
            last_seen=r.get("ModifiedTime", ""),
        ))
    return out


# --- Top-level corroborator -----------------------------------------------

def discover_csvs(artifact_analysis_dir: Path) -> dict[str, list[Path]]:
    """Find the EZ Tools CSV outputs under a case's
    analysis/windows_artifact/ dir. Returns {source: [paths...]}.

    Filename discovery is tolerant — EZ Tools use slightly different
    names per run. Every matching CSV's rows contribute to the source."""
    d = Path(artifact_analysis_dir)
    out: dict[str, list[Path]] = {
        "shimcache": [], "prefetch": [], "amcache": [], "userassist": [],
    }
    if not d.is_dir():
        return out
    for p in d.rglob("*.csv"):
        name = p.name.lower()
        parent = p.parent.name.lower()
        # Shimcache outputs live under shimcache/
        if parent == "shimcache" or "shimcache" in name or "appcompat" in name:
            out["shimcache"].append(p)
        # Prefetch outputs — PECmd writes prefetch.csv and a Timeline.csv
        elif parent == "prefetch" or "pecmd" in name or "prefetch" in name:
            if "timeline" not in name:  # skip the per-run timeline CSV
                out["prefetch"].append(p)
        # AmcacheParser outputs: UnassociatedFileEntries, Associated*, etc.
        elif "amcache" in name or "unassociatedfileentries" in name:
            out["amcache"].append(p)
        # UserAssist is written by RECmd under a UserAssist batch subdir
        elif "userassist" in name:
            out["userassist"].append(p)
    return out


def correlate(
    artifact_analysis_dir: Path,
    min_sources: int = 2,
) -> tuple[dict[str, ExecutionEntry], dict[str, int]]:
    """Walk every CSV, build ExecutionEntry per basename.

    Returns (entries_by_name, per_source_row_count). Only entries whose
    corroboration ≥ `min_sources` should typically be promoted to a
    Finding; callers may want the full dict for analytical reports.
    """
    csvs = discover_csvs(artifact_analysis_dir)
    parsers = {
        "shimcache":   parse_shimcache,
        "prefetch":    parse_prefetch,
        "amcache":     parse_amcache,
        "userassist":  parse_userassist,
    }
    entries: dict[str, ExecutionEntry] = {}
    counts: dict[str, int] = {s: 0 for s in parsers}
    for source, paths in csvs.items():
        parser = parsers[source]
        for p in paths:
            hits = parser(p)
            counts[source] += len(hits)
            for h in hits:
                if not h.name_lc:
                    continue
                e = entries.setdefault(
                    h.name_lc, ExecutionEntry(name_lc=h.name_lc))
                e.sources.add(h.source)
                if h.full_path:
                    e.paths.add(h.full_path)
                if h.last_seen:
                    e.last_seen_by_source[h.source] = h.last_seen
                e.hit_count += 1
    return entries, counts


# --- Suspicious-path overlay ----------------------------------------------

_USER_WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\temp\\",
    "\\downloads\\",
    "\\recycle.bin\\",
    "/appdata/local/temp/",
    "/appdata/roaming/",
    "/programdata/",
    "/users/public/",
    "/temp/",
    "/downloads/",
    "/recycle.bin/",
)


def is_user_writable_path(full_path: str) -> bool:
    """Returns True if any path observed for this executable sits in a
    user-writable location (Temp, AppData, Downloads, ProgramData).
    These are classic dropper / downloader staging directories."""
    lp = (full_path or "").lower()
    return any(m in lp for m in _USER_WRITABLE_MARKERS)
