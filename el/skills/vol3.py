"""Skill: Volatility 3 wrapper.

Deterministic. No LLM. Runs a vol3 plugin against a memory image, captures
the JSON output to disk, hashes it, and returns a provenance bundle suitable
for embedding directly into a Finding's evidence[] field.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem


class Vol3Error(RuntimeError):
    pass


@dataclass
class PluginRun:
    plugin: str
    image: Path
    rc: int
    stdout_path: Path
    stderr_path: Path
    rows: list[dict]
    command: list[str]
    version: str

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = hashlib.sha256(self.stdout_path.read_bytes()).hexdigest()
        merged_facts = {"row_count": len(self.rows), "rc": self.rc}
        if facts:
            merged_facts.update(facts)
        return EvidenceItem(
            tool="volatility3",
            version=self.version,
            command=" ".join(self.command),
            output_sha256=sha,
            output_path=str(self.stdout_path),
            extracted_facts=merged_facts,
        )


def _vol_executable() -> str:
    """Locate the `vol` script. shutil.which respects PATH only — when EL is
    invoked via .venv/bin/el WITHOUT venv activation, the venv's bin/ is NOT
    on PATH, so we also probe the bin directory next to the active Python.
    """
    import sys
    from pathlib import Path as _Path
    p = shutil.which("vol")
    if p:
        return p
    venv_vol = _Path(sys.executable).parent / "vol"
    if venv_vol.is_file():
        return str(venv_vol)
    raise Vol3Error("vol3 not found (not on PATH and not next to active python interpreter); "
                    "install volatility3 in the venv via `pip install -e .`")


def _vol_version() -> str:
    try:
        from volatility3.framework import constants
        return constants.PACKAGE_VERSION
    except Exception:
        return "unknown"


def run_plugin(
    image: str | Path,
    plugin: str,
    out_dir: str | Path,
    extra_args: list[str] | None = None,
    timeout: int = 600,
    offline: bool = False,
) -> PluginRun:
    """Run a single vol3 plugin and capture its JSON output + stderr.

    plugin: e.g. 'windows.pslist', 'windows.pstree', 'windows.malfind'
    offline: pass --offline to fail fast when ISF symbol downloads would hang
             (per memory-analysis SKILL: vol3 fetches PDB symbol tables from
             Microsoft on first use; offline runs need this flag).
    """
    image = Path(image)
    if not image.exists():
        raise Vol3Error(f"image not found: {image}")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    safe = plugin.replace(".", "_").replace("/", "_")
    stdout_path = out_dir / f"{safe}.json"
    stderr_path = out_dir / f"{safe}.stderr"

    base = [_vol_executable(), "-q", "-r", "json"]
    if offline:
        base.append("--offline")
    # If --dump is in extra_args, plugins need -o <dir> to write dumped files to.
    # We route them into the plugin's own out_dir so they're colocated with the
    # JSON output.
    dump_args: list[str] = []
    if extra_args and "--dump" in extra_args:
        dump_args = ["-o", str(out_dir)]
    cmd = [*base, *dump_args, "-f", str(image), plugin, *(extra_args or [])]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise Vol3Error(f"timeout running {plugin}") from e

    stderr_path.write_text(proc.stderr or "")
    raw = proc.stdout or ""
    stdout_path.write_text(raw)

    rows: list[dict] = []
    if raw.strip():
        try:
            parsed = json.loads(raw)
            rows = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            rows = []

    return PluginRun(
        plugin=plugin,
        image=image,
        rc=proc.returncode,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        rows=rows,
        command=cmd,
        version=_vol_version(),
    )


def detect_os(image: str | Path, out_dir: str | Path) -> tuple[str | None, PluginRun]:
    """Best-effort OS family detection by trying banner plugins.

    Returns (os_family, run) where os_family in {'windows','linux','mac', None}.

    Timeout is generous (600 s) because PDB scanning reads most of the
    memory image; under host contention (parallel investigations) the
    scanner may need several minutes on a 2-4 GB dump. Previously capped
    at 120 s, which falsely reported "no banner plugin produced usable
    output" on perfectly valid images whenever the host was loaded.
    """
    out_dir = Path(out_dir)
    errors: list[str] = []
    for plugin, family in (
        ("windows.info.Info", "windows"),
        ("linux.bash.Bash", "linux"),
        ("mac.bash.Bash", "mac"),
        ("banners.Banners", None),
    ):
        try:
            r = run_plugin(image, plugin, out_dir, timeout=600)
        except Vol3Error as e:
            errors.append(f"{plugin}: {e}")
            continue
        if r.rc == 0 and r.rows:
            if family:
                return family, r
            txt = (r.stdout_path.read_text(errors="ignore") + r.stderr_path.read_text(errors="ignore")).lower()
            if "windows" in txt or "ntoskrnl" in txt:
                return "windows", r
            if "linux" in txt:
                return "linux", r
            if "darwin" in txt or "xnu" in txt:
                return "mac", r
            return None, r
    raise Vol3Error(
        "no banner plugin produced usable output "
        f"(attempted: {'; '.join(errors) if errors else 'all plugins returned empty output'})"
    )


def yarascan(image: str | Path, rules_path: str | Path,
             out_dir: str | Path, *, family: str = "windows",
             timeout: int = 1800) -> PluginRun:
    """Run vol3's process-attributed YARA scan — vadyarascan on Windows
    and vmayarascan on Linux. (vol3 2.27 renamed the flat yarascan
    plugin; the VAD/VMA variants are the ones that carry PID + task
    attribution.)

    Complements the standalone `yara` binary: these plugins walk the
    memory layer's virtual address space per process, so matches carry
    process attribution (PID, task name, VA) instead of just a raw
    offset into the .mem file. Callers can turn that into claims like
    "rule MIMI matched in PID 624 (lsass.exe) at VA 0x7fff..." rather
    than "rule MIMI matched at offset 0x..." which requires a second
    pass to attribute.

    The rules_path must be a single .yar file — vadyarascan / vmayarascan
    take one `--yara-file` path (their cousin `--yara-compiled-file`
    accepts a pre-compiled rules blob). For a rules directory, point at
    a single aggregator .yar that `include`s the rest, or compile with
    `yara -C` and use yarascan directly.

    Note: requires `yara-python` in the same environment as vol3 —
    without it vol3 silently drops every yarascan plugin from the
    choice list. Install via `pip install yara-python` into the venv.
    """
    rules_path = Path(rules_path)
    plugin_by_family = {
        "windows": "windows.vadyarascan.VadYaraScan",
        "linux":   "linux.vmayarascan.VmaYaraScan",
        # mac has no maintained yarascan plugin in 2.27 — surface a
        # clean error instead of a spurious "invalid choice" one.
    }
    plugin = plugin_by_family.get(family)
    if plugin is None:
        raise Vol3Error(
            f"vol3 has no yara-scan plugin for family={family!r}"
        )
    return run_plugin(
        image=image, plugin=plugin, out_dir=out_dir,
        extra_args=["--yara-file", str(rules_path)],
        timeout=timeout,
    )
