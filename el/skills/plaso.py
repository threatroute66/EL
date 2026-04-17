"""Skill: Plaso wrappers (log2timeline.py + psort.py).

Two-stage timeline build:
  1. log2timeline.py extracts events into a .plaso storage file
  2. psort.py emits a sorted CSV/JSON timeline

Both stages are slow on real disk images. Tunable timeouts default
generous; callers should pass a tighter timeout in interactive runs.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem


class PlasoError(RuntimeError):
    pass


@dataclass
class PlasoRun:
    tool: str
    rc: int
    output_path: Path
    stderr_path: Path
    command: list[str]

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        try:
            sha = hashlib.sha256(self.output_path.read_bytes()).hexdigest()
        except Exception:
            sha = "0" * 64
        return EvidenceItem(
            tool=f"plaso/{self.tool}", version="present",
            command=" ".join(self.command),
            output_sha256=sha, output_path=str(self.output_path),
            extracted_facts={"rc": self.rc, **(facts or {})},
        )


def _which(name: str) -> str:
    p = shutil.which(name)
    if not p:
        raise PlasoError(f"{name} not on PATH")
    return p


def log2timeline(image_or_path: Path, out_dir: Path, timeout: int = 7200,
                 parsers: str = "win10", hashers: str = "md5,sha256",
                 vss: bool = False) -> PlasoRun:
    """SKILL defaults applied:
      - --parsers win10  (preferred for modern Windows, more complete than win7)
      - --hashers md5,sha256  (hash all processed files)
      - --timezone UTC  (always)
      - --vss-stores all  (essential for intrusion cases — attackers delete files VSS preserves)
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    storage = out_dir / "events.plaso"
    stderr_path = out_dir / "log2timeline.stderr"
    cmd = [_which("log2timeline.py"), "--unattended", "--quiet",
           "--parsers", parsers, "--hashers", hashers, "--timezone", "UTC"]
    if vss:
        cmd += ["--vss-stores", "all"]
    cmd += [str(storage), str(image_or_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise PlasoError("log2timeline timeout") from e
    stderr_path.write_text(proc.stderr or "")
    return PlasoRun("log2timeline.py", proc.returncode, storage, stderr_path, cmd)


def pinfo(storage: Path, out_dir: Path, timeout: int = 120) -> PlasoRun:
    """SKILL: mandatory after log2timeline — zero parser hits = config error."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "pinfo.txt"
    stderr_path = out_dir / "pinfo.stderr"
    cmd = [_which("pinfo.py"), "-v", str(storage)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise PlasoError("pinfo timeout") from e
    out_file.write_text(proc.stdout or "")
    stderr_path.write_text(proc.stderr or "")
    return PlasoRun("pinfo.py", proc.returncode, out_file, stderr_path, cmd)


def psort(storage_file: Path, out_dir: Path, output_format: str = "l2tcsv",
          timeout: int = 3600) -> PlasoRun:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"timeline.{output_format}.csv"
    stderr_path = out_dir / "psort.stderr"
    cmd = [_which("psort.py"), "--unattended", "--quiet",
           "-o", output_format, "-w", str(out_file), str(storage_file)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise PlasoError("psort timeout") from e
    stderr_path.write_text(proc.stderr or "")
    return PlasoRun("psort.py", proc.returncode, out_file, stderr_path, cmd)
