"""Skill: ssdeep / hashdeep — fuzzy and traditional hashing.

ssdeep produces context-triggered piecewise hashes that match
similar-but-not-identical files (good for detecting modified malware
samples). hashdeep is a multi-algorithm bulk hasher (md5/sha1/sha256
in one pass). Used for known-file filtering and similarity clustering.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class HashError(RuntimeError):
    pass


def _bin(name: str) -> str:
    p = shutil.which(name)
    if not p:
        raise HashError(f"{name} not on PATH")
    return p


@dataclass
class HashResult:
    target: Path
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    ssdeep: str | None = None


def hashdeep_one(target: Path, timeout: int = 300) -> HashResult:
    """Compute md5+sha1+sha256 for a file in a single pass."""
    target = Path(target)
    if not target.is_file():
        raise HashError(f"not a file: {target}")
    cmd = [_bin("hashdeep"), "-c", "md5,sha1,sha256", "-l", str(target)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise HashError(f"hashdeep timeout") from e
    res = HashResult(target=target)
    for line in (proc.stdout or "").splitlines():
        if line.startswith("%%%%") or line.startswith("##") or not line.strip():
            continue
        # Format: size,md5,sha1,sha256,filename
        cells = line.split(",")
        if len(cells) >= 4:
            res.md5 = cells[1]
            res.sha1 = cells[2]
            res.sha256 = cells[3]
            break
    return res


def ssdeep_one(target: Path, timeout: int = 300) -> str | None:
    """Compute the ssdeep fuzzy hash of a file."""
    target = Path(target)
    if not target.is_file():
        raise HashError(f"not a file: {target}")
    cmd = [_bin("ssdeep"), "-s", str(target)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise HashError(f"ssdeep timeout") from e
    for line in (proc.stdout or "").splitlines():
        # Format: <ssdeep_hash>,<filename>
        if "," in line and not line.startswith("ssdeep"):
            return line.split(",", 1)[0].strip()
    return None


def ssdeep_compare(a: str, b: str) -> int:
    """Compute a 0-100 similarity score between two ssdeep hashes via the
    `ssdeep -m` mode. Returns 0 on unparseable input."""
    cmd = [_bin("ssdeep"), "-m", "-"]
    payload = f"{a},sample-a\n{b},sample-b\n"
    try:
        r = subprocess.run(cmd, input=payload, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return 0
    out = r.stdout or ""
    # Output: sample-a matches sample-b (NN)
    import re
    m = re.search(r"\((\d+)\)", out)
    return int(m.group(1)) if m else 0
