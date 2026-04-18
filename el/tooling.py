from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ToolStatus:
    name: str
    invocation: list[str] | None
    version: str | None
    available: bool
    note: str = ""


def _run(cmd: list[str], timeout: int = 8) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def _which_or_paths(name: str, candidates: list[str]) -> str | None:
    p = shutil.which(name)
    if p:
        return p
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def probe_volatility3() -> ToolStatus:
    """shutil.which respects PATH only — when EL is invoked via .venv/bin/el
    WITHOUT venv activation, the venv's bin/ is NOT on PATH. Also probe the
    bin directory next to the active Python interpreter.
    """
    import sys
    candidates: list[str] = []
    p = shutil.which("vol")
    if p:
        candidates.append(p)
    venv_vol = Path(sys.executable).parent / "vol"
    if venv_vol.is_file() and str(venv_vol) not in candidates:
        candidates.append(str(venv_vol))
    for c in candidates:
        rc, out, err = _run([c, "--help"])
        if rc == 0:
            try:
                from volatility3.framework import constants
                ver = constants.PACKAGE_VERSION
            except Exception:
                ver = "present"
            return ToolStatus("volatility3", [c], ver, True)
    for c in ("/opt/volatility3-2.20.0/vol.py", "/opt/volatility3/vol.py"):
        if Path(c).exists():
            rc, out, _ = _run(["python3", c, "--version"])
            if rc == 0:
                return ToolStatus("volatility3", ["python3", c], out.splitlines()[0], True)
    return ToolStatus("volatility3", None, None, False, "not installed; required for memory-image analysis")


def probe_memory_baseliner() -> ToolStatus:
    p = Path("/opt/memory-baseliner/baseline.py")
    if p.exists():
        return ToolStatus("memory-baseliner", ["python3", str(p)], "present", True)
    return ToolStatus("memory-baseliner", None, None, False)


def probe_simple(name: str, version_args: list[str] | None = None) -> ToolStatus:
    p = shutil.which(name)
    if not p:
        return ToolStatus(name, None, None, False)
    version = ""
    if version_args:
        rc, out, err = _run([p, *version_args])
        text = out or err
        for line in text.splitlines():
            if line.strip():
                version = line.strip()
                break
    return ToolStatus(name, [p], version or "present", True)


def probe_ezt(dll: str, subdir: str | None = None) -> ToolStatus:
    base = Path("/opt/zimmermantools")
    full = (base / subdir / dll) if subdir else (base / dll)
    if full.exists() and shutil.which("dotnet"):
        return ToolStatus(dll, ["dotnet", str(full)], "ez-tool", True)
    return ToolStatus(dll, None, None, False)


def survey() -> list[ToolStatus]:
    import sys
    capa_bin = str(Path(sys.executable).parent / "capa")
    floss_bin = str(Path(sys.executable).parent / "floss")
    return [
        probe_volatility3(),
        probe_memory_baseliner(),
        probe_simple("fls"),
        probe_simple("icat"),
        probe_simple("mactime"),
        probe_simple("ewfmount"),
        probe_simple("log2timeline.py", ["--version"]),
        probe_simple("psort.py", ["--version"]),
        probe_simple("bulk_extractor", ["-V"]),
        probe_simple("yara", ["--version"]),
        probe_simple("zeek", ["--version"]),
        probe_simple("suricata", ["-V"]),
        probe_simple("tshark", ["-v"]),
        probe_simple("foremost", ["-V"]),
        probe_simple("photorec"),
        probe_simple("ssdeep", ["-V"]),
        probe_simple("hashdeep", ["-V"]),
        probe_simple("exiftool", ["-ver"]),
        probe_simple("hayabusa", ["help"]),
        probe_simple("chainsaw", ["--version"]),
        _probe_path(capa_bin, "capa", ["--version"]),
        _probe_path(floss_bin, "floss", ["--version"]),
        probe_simple("dotnet", ["--list-runtimes"]),
        probe_ezt("EvtxECmd.dll", "EvtxeCmd"),
        probe_ezt("MFTECmd.dll"),
        probe_ezt("RECmd.dll", "RECmd"),
        probe_ezt("PECmd.dll"),
        probe_ezt("AmcacheParser.dll"),
    ]


def _probe_path(path: str, name: str, version_args: list[str] | None = None) -> ToolStatus:
    """Probe an absolute path (for venv-installed binaries like capa / floss)."""
    if not Path(path).is_file():
        return ToolStatus(name, None, None, False)
    version = ""
    if version_args:
        rc, out, err = _run([path, *version_args])
        text = out or err
        for line in text.splitlines():
            if line.strip():
                version = line.strip()
                break
    return ToolStatus(name, [path], version or "present", True)
