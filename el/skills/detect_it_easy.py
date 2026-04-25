"""Skill: wrap Detect-It-Easy (`diec` CLI) for packer / compiler /
protector identification on PE files + dumped shellcode.

Closes the gap-doc Malware-RE bullet "Detect-It-Easy / `diec`"
(line 139).

DiE (https://github.com/horsicq/Detect-It-Easy) is a maintained
signature library that classifies a binary's packer ("UPX 3.96",
"Themida 2.4.x"), compiler ("Microsoft Visual C/C++ 19.34"), tool
("Inno Setup 6.0.5"), and detects suspicious anti-* features. The
``diec`` CLI accepts a path and emits human-readable text or
``-j`` JSON. We wrap the JSON form so callers parse structured
output, not free-form text.

Detection is opt-in by virtue of `diec` not being a SIFT default —
when missing, ``analyze()`` returns a `DiECResult` flagged as
unavailable rather than raising. The `malware_triage` agent can
chain it into its existing capa + FLOSS run path.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DiECResult:
    target: Path
    available: bool = True
    rc: int = 0
    detects: list[dict] = field(default_factory=list)   # raw diec JSON entries
    error: str = ""

    @property
    def packers(self) -> list[str]:
        return [d.get("string", "") for d in self.detects
                if (d.get("type") or "").lower() == "packer"]

    @property
    def compilers(self) -> list[str]:
        return [d.get("string", "") for d in self.detects
                if (d.get("type") or "").lower() == "compiler"]

    @property
    def protectors(self) -> list[str]:
        return [d.get("string", "") for d in self.detects
                if (d.get("type") or "").lower() == "protector"]

    @property
    def has_packed(self) -> bool:
        return bool(self.packers or self.protectors)


def _diec_bin() -> str | None:
    """Resolve a DiE CLI on PATH. Order: ``diec`` (Linux package
    name), ``die_console`` (Windows-style binary occasionally
    shipped via WINE), ``die``."""
    for name in ("diec", "die_console", "die"):
        p = shutil.which(name)
        if p:
            return p
    return None


def is_diec_available() -> bool:
    return _diec_bin() is not None


def analyze(target: str | Path, *, timeout: int = 60) -> DiECResult:
    """Run `diec -j <target>` and parse the JSON. On failure (binary
    missing, invalid file, timeout) returns a result with available
    or rc populated and an empty detects list — never raises."""
    target = Path(target)
    bin_path = _diec_bin()
    if bin_path is None:
        return DiECResult(target=target, available=False,
                           error="diec not on PATH")
    cmd = [bin_path, "-j", str(target)]
    try:
        r = subprocess.run(cmd, check=False, capture_output=True,
                            text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return DiECResult(target=target, available=True, rc=-1,
                           error=f"diec invocation failed: {e}")
    if r.returncode != 0:
        return DiECResult(target=target, rc=r.returncode,
                           error=(r.stderr or "").strip()[-200:])
    detects: list[dict] = []
    raw = (r.stdout or "").strip()
    if raw:
        try:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                # DiE wraps results under "detects" / "matches" / similar
                for key in ("detects", "matches", "results"):
                    val = payload.get(key)
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, dict):
                                detects.append(item)
                # Some builds emit a top-level "type" + "string" pair
                if not detects and "string" in payload:
                    detects.append(payload)
            elif isinstance(payload, list):
                detects = [d for d in payload if isinstance(d, dict)]
        except json.JSONDecodeError:
            return DiECResult(target=target, rc=r.returncode,
                               error="diec stdout not valid JSON")
    return DiECResult(target=target, rc=r.returncode, detects=detects)


__all__ = ["DiECResult", "analyze", "is_diec_available"]
