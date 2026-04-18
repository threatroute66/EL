"""Skill: FLOSS — Mandiant FLARE's obfuscated-string extractor.

Where standard `strings` only finds plain printable bytes, FLOSS also
recovers stack strings, tight-loop-decoded strings, and decoded constant
strings — exactly the strings malware tries to hide. Run on the .dmp
files vol3 malfind --dump produces; FLOSS often surfaces C2 URLs and
mutex names that string fingerprints missed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


class FlossError(RuntimeError):
    pass


def _bin() -> str:
    p = shutil.which("floss") or str(Path(sys.executable).parent / "floss")
    if not Path(p).is_file():
        raise FlossError("floss not installed (pip install flare-floss)")
    return p


@dataclass
class FlossResult:
    target: Path
    rc: int
    static_strings: list[str] = field(default_factory=list)
    stack_strings: list[str] = field(default_factory=list)
    tight_strings: list[str] = field(default_factory=list)
    decoded_strings: list[str] = field(default_factory=list)
    json_path: Path | None = None
    command: list[str] = field(default_factory=list)


def analyze(target: Path, out_dir: Path,
            shellcode_arch: str | None = None,
            min_length: int = 6,
            timeout: int = 600) -> FlossResult:
    """Run FLOSS on a binary or shellcode dump. Returns the four classes
    of recovered strings. shellcode_arch='32' or '64' for raw shellcode."""
    target = Path(target)
    if not target.exists():
        raise FlossError(f"target not found: {target}")
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"floss-{target.name}.json"

    cmd = [_bin(), "--json", "-n", str(min_length)]
    if shellcode_arch:
        cmd += ["--format", f"sc{shellcode_arch}"]
    cmd.append(str(target))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise FlossError(f"floss timeout") from e

    static, stack, tight, decoded = [], [], [], []
    if proc.stdout:
        json_path.write_text(proc.stdout)
        try:
            data = json.loads(proc.stdout)
            strs = data.get("strings") or {}
            def _vals(k):
                items = strs.get(k) or []
                return [s.get("string") or s if isinstance(s, dict) else s for s in items]
            static = _vals("static_strings")
            stack = _vals("stack_strings")
            tight = _vals("tight_strings")
            decoded = _vals("decoded_strings")
        except (json.JSONDecodeError, AttributeError):
            pass

    return FlossResult(
        target=target, rc=proc.returncode,
        static_strings=static, stack_strings=stack,
        tight_strings=tight, decoded_strings=decoded,
        json_path=json_path, command=cmd,
    )
