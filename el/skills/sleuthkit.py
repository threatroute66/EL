"""Skill: Sleuth Kit wrapper.

Subprocess wrappers for fls, mactime, mmls. Each function captures stdout
to disk, hashes the output, and returns an EvidenceItem-compatible record.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem


class SleuthkitError(RuntimeError):
    pass


@dataclass
class TskRun:
    tool: str
    image: Path
    rc: int
    stdout_path: Path
    stderr_path: Path
    command: list[str]

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = hashlib.sha256(self.stdout_path.read_bytes()).hexdigest()
        return EvidenceItem(
            tool=f"sleuthkit/{self.tool}", version=_version(self.tool),
            command=" ".join(self.command),
            output_sha256=sha, output_path=str(self.stdout_path),
            extracted_facts={"rc": self.rc, **(facts or {})},
        )


def _which(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        raise SleuthkitError(f"{tool} not on PATH")
    return p


def _version(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        return "unknown"
    try:
        r = subprocess.run([p, "-V"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "present"
    except Exception:
        return "present"


def _run(tool: str, image: Path, args: list[str], out_dir: Path, label: str, timeout: int) -> TskRun:
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"{label}.txt"
    stderr_path = out_dir / f"{label}.stderr"
    cmd = [_which(tool), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise SleuthkitError(f"timeout running {tool}") from e
    stdout_path.write_text(proc.stdout or "")
    stderr_path.write_text(proc.stderr or "")
    return TskRun(tool=tool, image=image, rc=proc.returncode,
                  stdout_path=stdout_path, stderr_path=stderr_path, command=cmd)


def mmls(image: Path, out_dir: Path, timeout: int = 120) -> TskRun:
    return _run("mmls", image, [str(image)], out_dir, "mmls", timeout)


def fls(image: Path, out_dir: Path, offset: int | None = None,
        recursive: bool = True, timeout: int = 1800) -> TskRun:
    args: list[str] = []
    if offset is not None:
        args += ["-o", str(offset)]
    if recursive:
        args += ["-r"]
    args += ["-m", "/", str(image)]  # mactime body output
    return _run("fls", image, args, out_dir, f"fls{('_o'+str(offset)) if offset else ''}", timeout)


def mactime(body_file: Path, out_dir: Path, timeout: int = 600) -> TskRun:
    """SKILL: always pass -z UTC. Default is local tz which corrupts cross-tz analysis."""
    args = ["-d", "-z", "UTC", "-b", str(body_file)]  # -d csv, -z tz, -b body
    return _run("mactime", body_file, args, out_dir, "mactime", timeout)


def ewfinfo(image: Path, out_dir: Path, timeout: int = 60) -> TskRun:
    """SKILL: surfaces acquisition MD5/SHA1 + metadata; record in case notes."""
    return _run("ewfinfo", image, [str(image)], out_dir, "ewfinfo", timeout)


def ewfverify(image: Path, out_dir: Path, timeout: int = 7200) -> TskRun:
    """SKILL: must complete without errors before any analysis proceeds."""
    return _run("ewfverify", image, [str(image)], out_dir, "ewfverify", timeout)


def img_stat(image: Path, out_dir: Path, timeout: int = 60) -> TskRun:
    """SKILL: catches 4K-sector drives. Wrong sector size = wrong byte offset."""
    return _run("img_stat", image, [str(image)], out_dir, "img_stat", timeout)


def fsstat(image: Path, out_dir: Path, offset: int | None = None,
           timeout: int = 120) -> TskRun:
    args: list[str] = []
    if offset is not None:
        args += ["-o", str(offset)]
    args += [str(image)]
    return _run("fsstat", image, args, out_dir, "fsstat", timeout)


def tsk_recover(image: Path, out_subdir: Path, mode: str = "alloc",
                offset: int | None = None, timeout: int = 7200) -> TskRun:
    """SKILL: -a allocated only (default), -e everything (incl. unallocated)."""
    args: list[str] = []
    if mode == "all":
        args += ["-e"]
    elif mode == "alloc":
        args += ["-a"]
    if offset is not None:
        args += ["-o", str(offset)]
    args += [str(image), str(out_subdir)]
    out_subdir.mkdir(parents=True, exist_ok=True)
    return _run("tsk_recover", image, args, out_subdir.parent, f"tsk_recover_{mode}", timeout)
