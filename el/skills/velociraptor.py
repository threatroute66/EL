"""Skill: Velociraptor collection JSON parser.

Velociraptor exports collected data as JSONL files, one per artifact.
Filenames are usually `<Artifact.Name>.json` (line-delimited JSON, one
event per line). The KNOWN_PARSERS table below maps every artifact name
EL currently recognises to a short label used in the summary.

The schema audit done for Tier 4.2 (proposal docs/enhancement_proposals.md)
added the post-Velociraptor-0.7 artifact set: Generic.System.PEDump for
dumped PE files inside running processes, Windows.Memory.ProcessInfo for
per-process memory metadata, plus the modern Linux + filesystem-forensics
artifacts (Windows.NTFS.MFT, Windows.Forensics.Amcache / Lnk / Jumplists /
Shellbags / UserAssist, Linux.Sys.Pslist, Linux.Forensics.BashHistory).

Other artifact files are noted but not deeply parsed — the framework
is extensible: add a per-artifact parser here when the case demands it.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


KNOWN_PARSERS = {
    # Cross-platform process list — covers both Windows + Linux. The
    # row schema (Pid / Ppid / Name / CommandLine / Username / Exe)
    # is a superset of Windows.System.Pslist, so we map it to the
    # same "pslist" key and `_populate_processes` handles it without
    # branching on platform.
    "Generic.System.Pstree": "pslist",
    # Windows: process / network / persistence (v0.6 era — already wired)
    "Windows.System.Pslist": "pslist",
    "Windows.Network.Netstat": "netstat",
    "Windows.Sysinternals.Autoruns": "autoruns",
    "Windows.Forensics.Prefetch": "prefetch",
    "Windows.System.TaskScheduler": "tasks",
    "Windows.EventLogs.EvtxHunter": "evtx_hunter",
    # Windows: memory + PE dumps (v0.7+)
    "Generic.System.PEDump": "pe_dump",
    "Windows.Memory.ProcessInfo": "process_info",
    "Windows.Memory.Acquisition": "memory_acq",
    # Windows: filesystem forensics (v0.6+ but commonly added in 0.7+ recipes)
    "Windows.NTFS.MFT": "mft",
    "Windows.Forensics.Amcache": "amcache",
    "Windows.Forensics.Lnk": "lnk",
    "Windows.Forensics.Jumplists_JumplistsFile": "jumplist",
    "Windows.Forensics.Shellbags": "shellbags",
    "Windows.Forensics.UserAssist": "userassist",
    # Windows: detection-content-driven (v0.7+)
    "Windows.Detection.PsexecService": "psexec",
    "Generic.System.Hash": "file_hash",
    # Linux: live-response equivalents
    "Linux.Sys.Pslist": "linux_pslist",
    "Linux.Network.Netstat": "linux_netstat",
    "Linux.Network.PacketCapture": "linux_pcap",
    "Linux.Forensics.BashHistory": "linux_bash_history",
    "Linux.Forensics.RecentlyUsed": "linux_recently_used",
}


@dataclass
class GenericArtifact:
    """Schema-aware projection of a Velociraptor artifact file the
    KNOWN_PARSERS table doesn't recognise. Captures enough metadata
    for the analyst to see "what artifact ran, what columns it
    produced, what time window it covers" without a per-artifact
    hand-coded parser.

    See `VelociraptorSummary.generic_artifacts` for the tier-1
    bucket this populates.
    """
    artifact_name: str           # e.g. "Generic.System.Pstree"
    file_path: str               # relative to input_dir
    file_format: str             # "json" or "csv"
    row_count: int
    column_names: list[str]
    time_range_utc: tuple[str, str] | None    # (earliest, latest); None when no
                                              # time column was detected
    sample_rows: list[dict]      # up to 3 raw rows


@dataclass
class VelociraptorSummary:
    out_path: Path
    artifact_files: list[str] = field(default_factory=list)
    parsed: dict[str, list[dict]] = field(default_factory=dict)
    process_count: int = 0
    netstat_count: int = 0
    autorun_count: int = 0
    # Per-artifact counts. Populated when the relevant artifact is present;
    # left at 0 otherwise. Keep this dataclass backwards-compatible —
    # process_count / netstat_count / autorun_count fields stay for the
    # existing tests + downstream code that reads them by name.
    pe_dump_count: int = 0
    process_info_count: int = 0
    mft_record_count: int = 0
    amcache_count: int = 0
    lnk_count: int = 0
    bash_history_count: int = 0
    linux_process_count: int = 0
    linux_netstat_count: int = 0
    # Tier-1 generic ingest — every artifact file the operator's hunt
    # produced that didn't have a dedicated parser. The agent emits
    # one Finding per entry so an analyst sees what ran even when EL
    # has no purpose-built logic for that artifact.
    generic_artifacts: list[GenericArtifact] = field(default_factory=list)

    def as_evidence(self) -> EvidenceItem:
        sha = hashlib.sha256(self.out_path.read_bytes()).hexdigest()
        return EvidenceItem(
            tool="el.velociraptor", version="0.2.0",
            command=f"el.velociraptor.parse({self.out_path.parent})",
            output_sha256=sha, output_path=str(self.out_path),
            extracted_facts={
                "artifact_file_count": len(self.artifact_files),
                "process_count": self.process_count,
                "netstat_count": self.netstat_count,
                "autorun_count": self.autorun_count,
                # New (post-0.7) artifact counts.
                "pe_dump_count": self.pe_dump_count,
                "process_info_count": self.process_info_count,
                "mft_record_count": self.mft_record_count,
                "amcache_count": self.amcache_count,
                "lnk_count": self.lnk_count,
                # Linux artifact counts.
                "bash_history_count": self.bash_history_count,
                "linux_process_count": self.linux_process_count,
                "linux_netstat_count": self.linux_netstat_count,
                "parsed_artifacts": list(self.parsed.keys()),
            },
        )


def _iter_jsonl(path: Path) -> Iterator[dict]:
    try:
        with path.open("r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except Exception:
        return


def _identify(path: Path) -> str | None:
    name = path.name
    for needle, key in KNOWN_PARSERS.items():
        if needle in name:
            return key
    return None


# Velociraptor housekeeping files — present in every hunt download but
# they describe the COLLECTION itself, not artifact data. Skipping
# them from the generic-ingest path keeps the "N artifacts collected"
# count honest (the analyst doesn't want hunt_info.json counted as
# an artifact).
_HOUSEKEEPING_FILENAMES = frozenset({
    "hunt_info.json",
    "client_info.json",
    "collection_context.json",
    "requests.json",
    "uploads.csv",
    "uploads.json",
    "uploads.json.index",
    "log.csv",
    "log.json",
})


# Timestamp-shaped column names commonly seen across Velociraptor's
# 500+ artifacts. First-hit-wins per file — we scan rows for the
# first column whose name is in this set and use it for the time
# window. `_ts` is Velociraptor's standard server-side timestamp on
# event artifacts.
_TS_COLUMNS = (
    "_ts", "Timestamp", "EventTime", "TimeCreated",
    "StartTime", "EndTime",
    "Time", "time", "time_utc", "Created", "Modified",
)


def _extract_artifact_name(path: Path) -> str:
    """Velociraptor names its output files after the artifact they ran:
       `Generic.System.Pstree.json` / `Generic.System.Pstree.csv` /
       `All Generic.System.Pstree.json` (hunt aggregate).
    Strip the format suffix + the optional `All ` prefix that the
    hunt-merge tool prepends. Falls back to the bare filename when
    the path doesn't match either convention."""
    stem = path.stem
    if stem.startswith("All "):
        stem = stem[4:]
    return stem


def _parse_ts(value: object) -> str | None:
    """Lenient timestamp parser — Velociraptor stores its `_ts`
    field as a Unix epoch (int or string), most artifact rows use
    ISO-8601 (`2026-05-19T07:45:12Z`). Return ISO-8601 string or
    None on parse failure. Keeps the time-window detection robust
    against arbitrary artifact schemas."""
    if value is None or value == "" or value == "0001-01-01T00:00:00Z":
        return None
    from datetime import datetime, timezone
    if isinstance(value, (int, float)):
        # Unix epoch seconds or microseconds — Velociraptor uses both
        # depending on the row type. Heuristic: > 1e12 → microseconds.
        try:
            if value > 1e12:
                value = value / 1e6
            return datetime.fromtimestamp(
                float(value), tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            return None
    if isinstance(value, str):
        # Try ISO first; fall through to epoch-as-string.
        for variant in (value, value.replace("Z", "+00:00")):
            try:
                dt = datetime.fromisoformat(variant)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                pass
        try:
            n = float(value)
            if n > 1e12:
                n = n / 1e6
            if n > 0:
                return datetime.fromtimestamp(
                    n, tz=timezone.utc).isoformat()
        except ValueError:
            return None
    return None


def _probe_json_artifact(path: Path,
                          row_cap: int = 200_000
                          ) -> tuple[int, list[str], tuple[str, str] | None,
                                       list[dict]]:
    """Walk a Velociraptor JSONL artifact and return
    (row_count, column_names, time_range, sample_rows). Caps at
    `row_cap` to bound runtime on large MFT-style outputs."""
    column_names: list[str] = []
    earliest: str | None = None
    latest: str | None = None
    sample: list[dict] = []
    count = 0
    ts_col: str | None = None
    for row in _iter_jsonl(path):
        count += 1
        if not column_names and isinstance(row, dict):
            column_names = list(row.keys())
        if len(sample) < 3 and isinstance(row, dict):
            # Truncate any oversized string value so the sample
            # rows don't bloat the summary JSON.
            sample.append({k: (v[:200] if isinstance(v, str) else v)
                            for k, v in row.items()})
        if ts_col is None and column_names:
            for cand in _TS_COLUMNS:
                if cand in column_names:
                    ts_col = cand
                    break
        if ts_col and isinstance(row, dict):
            ts = _parse_ts(row.get(ts_col))
            if ts:
                if earliest is None or ts < earliest:
                    earliest = ts
                if latest is None or ts > latest:
                    latest = ts
        if count >= row_cap:
            break
    time_range = (earliest, latest) if earliest and latest else None
    return count, column_names, time_range, sample


def _probe_csv_artifact(path: Path, row_cap: int = 200_000
                        ) -> tuple[int, list[str], tuple[str, str] | None,
                                     list[dict]]:
    """CSV equivalent of _probe_json_artifact. Velociraptor often
    writes the same artifact twice (.json + .csv); we only need to
    probe one of them, but the schema-aware tier keeps both paths
    so an operator who sealed only the CSV still gets coverage."""
    import csv
    earliest: str | None = None
    latest: str | None = None
    sample: list[dict] = []
    count = 0
    ts_col: str | None = None
    column_names: list[str] = []
    try:
        with path.open("r", errors="ignore") as fh:
            reader = csv.DictReader(fh)
            column_names = list(reader.fieldnames or [])
            if column_names:
                for cand in _TS_COLUMNS:
                    if cand in column_names:
                        ts_col = cand
                        break
            for row in reader:
                count += 1
                if len(sample) < 3:
                    sample.append({k: (v[:200] if isinstance(v, str) else v)
                                    for k, v in row.items()})
                if ts_col:
                    ts = _parse_ts(row.get(ts_col))
                    if ts:
                        if earliest is None or ts < earliest:
                            earliest = ts
                        if latest is None or ts > latest:
                            latest = ts
                if count >= row_cap:
                    break
    except (OSError, csv.Error):
        return 0, [], None, []
    time_range = (earliest, latest) if earliest and latest else None
    return count, column_names, time_range, sample


def parse(input_dir: Path, out_dir: Path) -> VelociraptorSummary:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "velociraptor_summary.json"
    summary = VelociraptorSummary(out_path=summary_path)

    # Track every artifact we've already covered via the specific-
    # parser tier (KNOWN_PARSERS) so the generic tier doesn't emit
    # duplicate findings — generic-tier coverage is for files the
    # specific tier didn't claim.
    specifically_parsed: set[Path] = set()

    for p in sorted(input_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".json", ".jsonl"):
            continue
        if p.name in _HOUSEKEEPING_FILENAMES:
            continue
        summary.artifact_files.append(str(p.relative_to(input_dir)))
        kind = _identify(p)
        if kind:
            specifically_parsed.add(p)
            rows = list(_iter_jsonl(p))
            summary.parsed[kind] = rows
            if kind == "pslist":
                summary.process_count += len(rows)
            elif kind == "netstat":
                summary.netstat_count += len(rows)
            elif kind == "autoruns":
                summary.autorun_count += len(rows)
            elif kind == "pe_dump":
                summary.pe_dump_count += len(rows)
            elif kind == "process_info":
                summary.process_info_count += len(rows)
            elif kind == "mft":
                summary.mft_record_count += len(rows)
            elif kind == "amcache":
                summary.amcache_count += len(rows)
            elif kind == "lnk":
                summary.lnk_count += len(rows)
            elif kind == "linux_bash_history":
                summary.bash_history_count += len(rows)
            elif kind == "linux_pslist":
                summary.linux_process_count += len(rows)
            elif kind == "linux_netstat":
                summary.linux_netstat_count += len(rows)

    # Tier-1 generic ingest pass — every JSON / CSV artifact file
    # that wasn't claimed by KNOWN_PARSERS gets a schema-aware
    # probe so the analyst sees what ran. Also handles CSV outputs
    # the specific tier doesn't touch (Velociraptor often writes
    # both .json and .csv for the same artifact; if we lose the
    # .json half — operator sealed only the CSV — at least the
    # generic tier surfaces row counts + time range).
    seen_artifact_names: set[str] = set()
    for p in sorted(input_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.name in _HOUSEKEEPING_FILENAMES:
            continue
        suffix = p.suffix.lower()
        if suffix not in (".json", ".jsonl", ".csv"):
            continue
        if p in specifically_parsed:
            continue
        artifact_name = _extract_artifact_name(p)
        # Skip if the same artifact-name has already been generic-
        # probed via a previous file (typical for hunt downloads
        # where the same artifact appears once at root in `results/`
        # AND once per-client subdirectory; the per-client copy is
        # the source of truth).
        if artifact_name in seen_artifact_names:
            continue
        seen_artifact_names.add(artifact_name)
        if suffix == ".csv":
            row_count, cols, tr, sample = _probe_csv_artifact(p)
            fmt = "csv"
        else:
            row_count, cols, tr, sample = _probe_json_artifact(p)
            fmt = "json"
        if row_count == 0 and not cols:
            # Truly empty / unreadable — don't emit a finding for
            # a file with literally nothing in it.
            continue
        summary.generic_artifacts.append(GenericArtifact(
            artifact_name=artifact_name,
            file_path=str(p.relative_to(input_dir)),
            file_format=fmt,
            row_count=row_count,
            column_names=cols,
            time_range_utc=tr,
            sample_rows=sample,
        ))

    payload = {
        "artifact_files": summary.artifact_files,
        "process_count": summary.process_count,
        "netstat_count": summary.netstat_count,
        "autorun_count": summary.autorun_count,
        "pe_dump_count": summary.pe_dump_count,
        "process_info_count": summary.process_info_count,
        "mft_record_count": summary.mft_record_count,
        "amcache_count": summary.amcache_count,
        "lnk_count": summary.lnk_count,
        "bash_history_count": summary.bash_history_count,
        "linux_process_count": summary.linux_process_count,
        "linux_netstat_count": summary.linux_netstat_count,
        "parsed_artifacts": {
            k: rows[:50] for k, rows in summary.parsed.items()
        },
        "generic_artifacts": [
            {
                "artifact_name": a.artifact_name,
                "file_path": a.file_path,
                "file_format": a.file_format,
                "row_count": a.row_count,
                "column_names": a.column_names,
                "time_range_utc": list(a.time_range_utc)
                                    if a.time_range_utc else None,
                "sample_rows": a.sample_rows,
            }
            for a in summary.generic_artifacts
        ],
    }
    summary_path.write_text(json.dumps(payload, indent=2, default=str))
    return summary
