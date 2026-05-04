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
        probe_yara_x(),
        probe_simple("zeek", ["--version"]),
        probe_simple("suricata", ["-V"]),
        probe_simple("tshark", ["-v"]),
        probe_simple("foremost", ["-V"]),
        probe_simple("photorec"),
        probe_simple("unyaffs"),
        _probe_path("/opt/yaffs2utils/unyaffs2", "unyaffs2"),
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
        probe_memprocfs(),
        probe_hindsight(),
        probe_mvt(),
        probe_timesketch(),
        probe_uac(),
        probe_weasyprint(),
    ]


def probe_yara_x() -> ToolStatus:
    """YARA-X (`yr`) — VirusTotal's Rust rewrite of YARA. ~10x faster.
    yara_hunt skill auto-prefers it when present (set EL_FORCE_YARA4=1
    to opt back to YARA 4.x)."""
    p = shutil.which("yr")
    if not p:
        return ToolStatus(
            "yara-x", None, None, False,
            note="install from https://github.com/VirusTotal/yara-x/releases (binary name: yr)",
        )
    rc, out, err = _run([p, "--version"], timeout=5)
    version = (out or err).strip().splitlines()[0] if (out or err) else "present"
    return ToolStatus(
        "yara-x", [p], version, True,
        note="auto-preferred by yara_hunt skill",
    )


def probe_timesketch() -> ToolStatus:
    """Timesketch push — collaborative super-timeline review (opt-in)."""
    try:
        import timesketch_api_client  # noqa: F401
        import timesketch_import_client  # noqa: F401
    except ImportError as e:
        return ToolStatus(
            "timesketch", None, None, False,
            note=f"pip install timesketch-api-client + timesketch-import-client ({e})",
        )
    from el.skills import timesketch as ts
    if ts.is_configured():
        url = os.environ.get("EL_TIMESKETCH_URL", "")
        return ToolStatus(
            "timesketch", None, "client present",
            True, note=f"configured for {url}",
        )
    return ToolStatus(
        "timesketch", None, "client present", True,
        note=("client installed; set EL_TIMESKETCH_URL + "
              "EL_TIMESKETCH_TOKEN to enable push (opt-in)"),
    )


def probe_mvt() -> ToolStatus:
    """MVT (Mobile Verification Toolkit) — Pegasus / mercenary spyware detector."""
    import sys
    venv_bin = Path(sys.executable).parent
    candidates = [
        venv_bin / "mvt-ios",
        venv_bin / "mvt-android",
    ]
    for c in candidates:
        if c.is_file():
            rc, out, err = _run([str(c), "version"], timeout=6)
            if rc == 0 or out:
                # `version` subcommand emits "MVT version: X.Y.Z" or similar
                version = ""
                for line in (out + "\n" + err).splitlines():
                    if "version" in line.lower() and any(ch.isdigit() for ch in line):
                        version = line.strip()
                        break
                return ToolStatus(
                    "mvt", [str(c)], version or "present", True,
                    note="Pegasus / mercenary spyware IOC matching",
                )
    return ToolStatus(
        "mvt", None, None, False,
        note="pip install mvt — provides mvt-ios and mvt-android",
    )


def probe_hindsight() -> ToolStatus:
    """Hindsight (pyhindsight) — Chromium-family browser forensics."""
    try:
        import pyhindsight  # noqa: F401
        version = getattr(pyhindsight, "__version__", "present")
        # Verify the GitHub-only ccl_chromium_reader dep is installed too.
        try:
            import ccl_chromium_reader  # noqa: F401
        except ImportError as e:
            return ToolStatus(
                "hindsight", None, version, False,
                note=f"pyhindsight installed but missing GitHub dep: {e}",
            )
        return ToolStatus(
            "hindsight", None, version, True,
            note="Chromium-family browser forensics (Chrome/Edge/Brave)",
        )
    except ImportError:
        return ToolStatus(
            "hindsight", None, None, False,
            note="pip install pyhindsight + ccl_chromium_reader (from GitHub)",
        )


def probe_memprocfs() -> ToolStatus:
    """MemProcFS — memory as a virtual filesystem (forensic triage).
    Complements vol3; shipped in /opt/memprocfs/ via install.sh."""
    candidates = [
        "/opt/memprocfs/memprocfs",
        "/usr/local/bin/memprocfs",
    ]
    p = shutil.which("memprocfs")
    if p:
        candidates.insert(0, p)
    for c in candidates:
        if Path(c).is_file():
            rc, out, err = _run([c, "-h"], timeout=4)
            text = (out + "\n" + err).lower()
            version = ""
            for line in (out + "\n" + err).splitlines():
                if "memprocfs v" in line.lower():
                    version = line.strip()
                    break
            if "memprocfs" in text:
                return ToolStatus(
                    "memprocfs", [c], version or "present", True,
                    note="memory-as-filesystem forensic triage",
                )
    return ToolStatus(
        "memprocfs", None, None, False,
        note="install via install.sh; download from https://github.com/ufrisk/MemProcFS/releases",
    )


def probe_uac() -> ToolStatus:
    """Unix Artifact Collector (UAC) for live response collection."""
    uac_paths = [
        "/opt/uac/uac",
        "/usr/local/bin/uac",
        shutil.which("uac")
    ]

    for path in uac_paths:
        if path and Path(path).exists():
            # UAC requires being run from its directory, so test with wrapper
            rc, out, err = _run(["uac", "--version"])
            if rc == 0:
                version_line = out.strip()
                return ToolStatus("uac", ["uac"], version_line, True,
                                  note="live response artifact collection")

    return ToolStatus("uac", None, None, False,
                      note="install from https://github.com/tclahr/uac")


def probe_weasyprint() -> ToolStatus:
    """WeasyPrint is a Python library, not a CLI — probe via import.
    Marked optional: PDF generation is feature-gated on its presence,
    so a missing install yields 'insufficient evidence' on that path
    rather than a hard failure of the whole report run."""
    try:
        import weasyprint as _wp
        return ToolStatus("weasyprint", None, _wp.__version__, True,
                          note="executive PDF rendering")
    except (ImportError, OSError) as e:
        return ToolStatus(
            "weasyprint", None, None, False,
            note=f"executive PDF will be skipped ({type(e).__name__})",
        )


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
