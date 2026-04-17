"""Skill: Velociraptor collection JSON parser.

Velociraptor exports collected data as JSONL files, one per artifact.
Filenames are usually `<Artifact.Name>.json` (line-delimited JSON, one
event per line). This skill parses the most common artifacts:

  - Windows.System.Pslist
  - Windows.Network.Netstat
  - Windows.Sysinternals.Autoruns
  - Windows.Forensics.Prefetch
  - Windows.System.TaskScheduler

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
    "Windows.System.Pslist": "pslist",
    "Windows.Network.Netstat": "netstat",
    "Windows.Sysinternals.Autoruns": "autoruns",
    "Windows.Forensics.Prefetch": "prefetch",
    "Windows.System.TaskScheduler": "tasks",
    "Windows.EventLogs.EvtxHunter": "evtx_hunter",
}


@dataclass
class VelociraptorSummary:
    out_path: Path
    artifact_files: list[str] = field(default_factory=list)
    parsed: dict[str, list[dict]] = field(default_factory=dict)
    process_count: int = 0
    netstat_count: int = 0
    autorun_count: int = 0

    def as_evidence(self) -> EvidenceItem:
        sha = hashlib.sha256(self.out_path.read_bytes()).hexdigest()
        return EvidenceItem(
            tool="el.velociraptor", version="0.1.0",
            command=f"el.velociraptor.parse({self.out_path.parent})",
            output_sha256=sha, output_path=str(self.out_path),
            extracted_facts={
                "artifact_file_count": len(self.artifact_files),
                "process_count": self.process_count,
                "netstat_count": self.netstat_count,
                "autorun_count": self.autorun_count,
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


def parse(input_dir: Path, out_dir: Path) -> VelociraptorSummary:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "velociraptor_summary.json"
    summary = VelociraptorSummary(out_path=summary_path)

    for p in sorted(input_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".json", ".jsonl"):
            continue
        summary.artifact_files.append(str(p.relative_to(input_dir)))
        kind = _identify(p)
        if kind:
            rows = list(_iter_jsonl(p))
            summary.parsed[kind] = rows
            if kind == "pslist":
                summary.process_count += len(rows)
            elif kind == "netstat":
                summary.netstat_count += len(rows)
            elif kind == "autoruns":
                summary.autorun_count += len(rows)

    payload = {
        "artifact_files": summary.artifact_files,
        "process_count": summary.process_count,
        "netstat_count": summary.netstat_count,
        "autorun_count": summary.autorun_count,
        "parsed_artifacts": {
            k: rows[:50] for k, rows in summary.parsed.items()
        },
    }
    summary_path.write_text(json.dumps(payload, indent=2, default=str))
    return summary
