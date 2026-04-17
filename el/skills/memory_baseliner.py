"""Skill: Memory Baseliner wrapper.

Wraps /opt/memory-baseliner/baseline.py per the memory-analysis SKILL.

Compares a suspect memory image against a known-good JSON baseline to surface
anomalous processes, drivers, and services without requiring a second image.
Three modes:
  - proc: processes + loaded DLLs
  - drv:  kernel drivers (rootkit detection)
  - svc:  services

The SKILL warns: --loadbaseline is a STANDALONE BOOLEAN and --jsonbaseline
is the SEPARATE path argument. Both must be present when loading. We pass
both unconditionally in load mode.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem


BASELINE_PATHS = [
    Path("/opt/memory-baseliner/baseline.py"),
    Path("/opt/memory-baseliner/Memory-Baseliner/baseline.py"),
]


class BaselinerError(RuntimeError):
    pass


@dataclass
class BaselineRun:
    mode: str
    rc: int
    output_csv: Path
    stderr_path: Path
    command: list[str]
    nonbaseline_count: int = 0

    def as_evidence(self) -> EvidenceItem:
        try:
            sha = hashlib.sha256(self.output_csv.read_bytes()).hexdigest()
        except Exception:
            sha = "0" * 64
        return EvidenceItem(
            tool="memory-baseliner", version="present",
            command=" ".join(self.command),
            output_sha256=sha, output_path=str(self.output_csv),
            extracted_facts={"mode": self.mode, "rc": self.rc,
                             "nonbaseline_count": self.nonbaseline_count},
        )


def _baseline_script() -> Path:
    for p in BASELINE_PATHS:
        if p.exists():
            return p
    raise BaselinerError("memory-baseliner not installed (see provisioning/optional-tools.txt)")


def _python() -> str:
    """Memory-baseliner imports volatility3 — use the venv interpreter where vol3 lives."""
    import sys
    return sys.executable


def compare(mode: str, image: Path, baseline: Path, out_dir: Path,
            timeout: int = 3600) -> BaselineRun:
    """Run a baseline comparison.

    mode: 'proc' | 'drv' | 'svc'
    baseline: either a baseline JSON (loaded via --loadbaseline) or another
              memory image (passed via -b for direct image-vs-image diff).
              Detected by file extension: .json → JSON workflow, otherwise image.
    """
    if mode not in ("proc", "drv", "svc"):
        raise BaselinerError(f"unknown mode: {mode}")
    if not image.exists():
        raise BaselinerError(f"image not found: {image}")
    if not baseline.exists():
        raise BaselinerError(f"baseline not found: {baseline}")

    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = out_dir / f"{mode}_baseline.csv"
    stderr_path = out_dir / f"baseliner_{mode}.stderr"
    script = _baseline_script()

    if baseline.suffix.lower() == ".json":
        baseline_args = ["--loadbaseline", "--jsonbaseline", str(baseline)]
    else:
        baseline_args = ["-b", str(baseline)]

    cmd = [_python(), str(script), f"-{mode}",
           "-i", str(image), *baseline_args,
           "-o", str(out_csv)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise BaselinerError(f"baseliner {mode} timeout") from e

    stderr_path.write_text(proc.stderr or "")
    if proc.stdout and not out_csv.exists():
        # csababarta's tool sometimes writes to stdout instead of -o; capture either.
        out_csv.write_text(proc.stdout)

    nb_count = 0
    if out_csv.exists():
        try:
            txt = out_csv.read_text(errors="ignore")
            nb_count = max(0, sum(1 for line in txt.splitlines() if line.strip()) - 1)
        except Exception:
            nb_count = 0

    return BaselineRun(mode=mode, rc=proc.returncode, output_csv=out_csv,
                       stderr_path=stderr_path, command=cmd,
                       nonbaseline_count=nb_count)


def save_baseline(image: Path, baseline_json: Path, mode: str = "proc",
                  out_dir: Path | None = None, timeout: int = 3600) -> BaselineRun:
    """Generate a NEW baseline JSON from a known-clean image."""
    if not image.exists():
        raise BaselinerError(f"image not found: {image}")
    out_dir = out_dir or baseline_json.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    stderr_path = out_dir / f"baseliner_save_{mode}.stderr"
    script = _baseline_script()
    cmd = ["python3", str(script), f"-{mode}",
           "-i", str(image),
           "--savebaseline",
           "--jsonbaseline", str(baseline_json)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise BaselinerError(f"baseliner save timeout") from e
    stderr_path.write_text(proc.stderr or "")
    return BaselineRun(mode=mode, rc=proc.returncode, output_csv=baseline_json,
                       stderr_path=stderr_path, command=cmd)
