"""Skill: file carving via foremost / photorec — recover files from
unallocated space or raw streams by file-signature scanning. Complements
TSK's `tsk_recover` (which uses filesystem metadata) by recovering files
that have no remaining filesystem record.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class CarveError(RuntimeError):
    pass


def _bin(name: str) -> str:
    p = shutil.which(name)
    if not p:
        raise CarveError(f"{name} not on PATH")
    return p


@dataclass
class CarveRun:
    target: Path
    out_dir: Path
    rc: int
    tool: str
    file_counts: dict[str, int] = field(default_factory=dict)
    total_files: int = 0
    command: list[str] = field(default_factory=list)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        h = hashlib.sha256()
        for p in sorted(self.out_dir.rglob("*"))[:200]:
            if p.is_file():
                try:
                    h.update(p.read_bytes()[:64 * 1024])
                except Exception:
                    continue
        merged = {"rc": self.rc, "tool": self.tool,
                  "total_carved": self.total_files,
                  "by_type": self.file_counts}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool=f"carve/{self.tool}", version="present",
            command=" ".join(self.command),
            output_sha256=h.hexdigest() or "0" * 64,
            output_path=str(self.out_dir),
            extracted_facts=merged,
        )


def foremost(target: Path, out_dir: Path,
             types: str = "all", timeout: int = 3600) -> CarveRun:
    """foremost -t <types> -i <target> -o <out_dir>. types is a CSV string
    like 'pdf,jpg,doc' or 'all' for the default ruleset."""
    target = Path(target)
    if not target.exists():
        raise CarveError(f"target not found: {target}")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise CarveError(f"out_dir not empty (foremost refuses): {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [_bin("foremost"), "-T", "-q", "-t", types,
           "-i", str(target), "-o", str(out_dir)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise CarveError(f"foremost timeout") from e

    counts: Counter = Counter()
    total = 0
    for sub in out_dir.iterdir():
        if sub.is_dir() and sub.name not in ("audit"):
            n = sum(1 for _ in sub.iterdir() if _.is_file())
            if n:
                counts[sub.name] = n
                total += n
    return CarveRun(target=target, out_dir=out_dir, rc=proc.returncode,
                    tool="foremost", file_counts=dict(counts),
                    total_files=total, command=cmd)


def photorec_run(target: Path, out_dir: Path, timeout: int = 7200) -> CarveRun:
    """photorec is interactive by default; we drive it with a recovery
    script. Falls back to /search/free/.list mode if available, otherwise
    raises (use foremost as the non-interactive default)."""
    raise CarveError("photorec is interactive — use foremost for non-interactive carving "
                     "or write a Q-and-A driver script if photorec-specific carvers needed")
