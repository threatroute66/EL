"""Skill: Volatility 3 wrapper.

Deterministic. No LLM. Runs a vol3 plugin against a memory image, captures
the JSON output to disk, hashes it, and returns a provenance bundle suitable
for embedding directly into a Finding's evidence[] field.

Two output modes:

  * **Eager (default)** — `-r json`, full result list materialised into
    `PluginRun.rows`. Suits small plugins (banners, hivelist) and any
    case where the consumer wants random access.
  * **Streaming (`streaming=True`)** — `-r jsonl`, subprocess stdout
    streams directly to `stdout_path` with no in-memory buffer.
    `PluginRun.rows` stays empty; consumers iterate via
    `iter_rows(run)` line-by-line. Use for plugins whose output is
    large enough to OOM (`netscan`, `malfind`, `vadinfo`,
    `pslist`/`psscan` on DC-class images).

The streaming path was added after the SRL-2018 mail capture (18 GB
image into 16 GB host) OOM-killed `memory_forensicator` mid-run via
the eager `proc.stdout` capture + full `json.loads`.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from el.schemas.finding import EvidenceItem


class Vol3Error(RuntimeError):
    pass


# Substrings vol3 emits when a Linux/macOS image has no matching ISF symbol
# table. Unlike Windows (PDBs auto-download from Microsoft), Linux/mac kernels
# need a per-kernel ISF JSON built from the target's debug kernel with
# dwarf2json — there is no public download for an arbitrary distro kernel.
_ISF_MISSING_MARKERS = (
    "unable to validate the plugin requirements",
    "no suitable",
    "symbol table",
    "could not find the symbols",
    "isf",
    "banner",
)

# Operator-facing remediation, referenced by agents and `el doctor`. Kept here
# so the message stays consistent across the skill, the agent, and the probe.
ISF_REMEDIATION = (
    "Linux/macOS memory image: no matching Volatility 3 ISF symbol table. "
    "Build one with dwarf2json from the target's debug kernel — e.g. "
    "`dwarf2json linux --elf <vmlinux-with-debug>` (Ubuntu: the matching "
    "linux-image-...-dbgsym .ddeb) — then drop the JSON under a symbols dir "
    "and pass it with `vol -s <dir>`. dwarf2json is an OPTIONAL tool "
    "(see provisioning/optional-tools.txt); `el doctor` reports its presence."
)


def isf_symbols_missing(run: "PluginRun") -> bool:
    """True when a Linux/mac plugin failed specifically because no ISF symbol
    table matched the image's kernel banner.

    Lets callers emit a precise, actionable `insufficient` finding ("build an
    ISF with dwarf2json") instead of a generic vol3 failure. Windows images
    never hit this path — their PDB symbols auto-download.
    """
    if run.rc == 0 and run.rows:
        return False
    try:
        txt = run.stderr_path.read_text(errors="ignore").lower()
    except Exception:
        return False
    if "symbol" not in txt and "isf" not in txt and "requirement" not in txt:
        return False
    return any(m in txt for m in _ISF_MISSING_MARKERS)


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
    # When True, `rows` is intentionally empty — output is JSON-Lines
    # at `stdout_path`. Consume via `iter_rows(run)` rather than the
    # `rows` list. `row_count` is populated by the wrapper after the
    # streamed write completes (cheap line-count pass) so
    # `as_evidence()` still reports a meaningful count.
    streaming: bool = False
    row_count: int = 0

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = hashlib.sha256(self.stdout_path.read_bytes()).hexdigest()
        count = self.row_count if self.streaming else len(self.rows)
        merged_facts = {"row_count": count, "rc": self.rc}
        if self.streaming:
            merged_facts["render_format"] = "jsonl"
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


def iter_rows(run: PluginRun) -> Iterator[dict]:
    """Yield rows from a vol3 PluginRun, streaming or eager.

    For `streaming=True` runs, parses the JSON-Lines file one line at
    a time — peak memory is one row + one line buffer.
    For eager runs, returns the materialised `rows` list as-is.

    Malformed lines are silently skipped (matches the eager path's
    `json.JSONDecodeError → rows=[]` behaviour) so a partial-write
    crash doesn't poison every consumer.
    """
    # `getattr` defensive — lets tests that pre-date the streaming
    # field pass plain row-list mocks without breaking.
    if not getattr(run, "streaming", False):
        yield from run.rows
        return
    if not run.stdout_path.is_file():
        return
    with run.stdout_path.open("r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


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


def _symbol_cache_dir() -> str:
    """A user-writable directory for vol3's auto-downloaded Windows PDB ISF
    symbols.

    vol3 writes each converted PDB into the FIRST writable entry of
    `volatility3.symbols.__path__` (see download_pdb_isf in
    framework/symbols/windows/pdbutil.py — it loops the search path and
    breaks on the first dir it can write to). On the SANS SIFT root install
    (`/opt/volatility3-*/volatility3/symbols`) that package dir is root-owned
    and unwritable, so the download silently fails with "Cannot write
    downloaded symbols", `windows.info` then reports no kernel, and Triage
    misroutes the memory image to the carve-only pipeline.

    Passing this dir via `-s` PREPENDS it to the search path
    (cli/__init__.py: `volatility3.symbols.__path__ = [...] + SYMBOL_BASEPATHS`),
    so downloads always land somewhere EL owns, independent of which `vol`
    binary resolves (venv vs the root SIFT install) and surviving vol3
    reinstalls. Reads still fall through to the package dirs, so any symbols
    already shipped there are found. Honour EL_VOL_SYMBOLS for an override.
    """
    base = os.environ.get("EL_VOL_SYMBOLS") or os.path.join(
        os.path.expanduser("~"), ".el", "volatility3-symbols")
    os.makedirs(base, exist_ok=True)
    return base


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
    with_output_dir: bool = False,
    streaming: bool = False,
) -> PluginRun:
    """Run a single vol3 plugin and capture its output + stderr.

    plugin: e.g. 'windows.pslist', 'windows.pstree', 'windows.malfind'
    offline: pass --offline to fail fast when ISF symbol downloads would hang
             (per memory-analysis SKILL: vol3 fetches PDB symbol tables from
             Microsoft on first use; offline runs need this flag).
    streaming: when True, render via JSON-Lines and stream subprocess
               stdout directly to disk — `PluginRun.rows` is left
               empty; consume via `iter_rows(run)`. Required for
               plugins whose result set is large enough to OOM the
               wrapper (DC-class netscan / malfind / vadinfo).
               Eager mode (default) preserves random access and
               matches every existing caller.
    """
    image = Path(image)
    if not image.exists():
        raise Vol3Error(f"image not found: {image}")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    safe = plugin.replace(".", "_").replace("/", "_")
    suffix = "jsonl" if streaming else "json"
    stdout_path = out_dir / f"{safe}.{suffix}"
    stderr_path = out_dir / f"{safe}.stderr"

    base = [_vol_executable(), "-q", "-r", "jsonl" if streaming else "json",
            "-s", _symbol_cache_dir()]
    if offline:
        base.append("--offline")
    # If --dump is in extra_args, plugins need -o <dir> to write dumped files to.
    # We route them into the plugin's own out_dir so they're colocated with the
    # JSON output.
    dump_args: list[str] = []
    if (extra_args and "--dump" in extra_args) or with_output_dir:
        # `-o <dir>` is a vol3 GLOBAL option (positional before the
        # plugin), used by --dump-supporting plugins AND by carve
        # plugins (windows.dumpfiles.DumpFiles) that write artefacts
        # implicitly. `with_output_dir=True` is the explicit knob;
        # `--dump` in extra_args is the legacy auto-detect.
        dump_args = ["-o", str(out_dir)]
    cmd = [*base, *dump_args, "-f", str(image), plugin, *(extra_args or [])]

    rows: list[dict] = []
    row_count = 0

    if streaming:
        # Stream subprocess stdout directly to disk — no Python-side
        # buffering of the full output. Memory peak = subprocess pipe
        # buffer + os.read() chunk. After the run, count lines for the
        # provenance fact `row_count`.
        try:
            with stdout_path.open("wb") as out_f:
                proc = subprocess.Popen(
                    cmd, stdout=out_f,
                    stderr=subprocess.PIPE, text=False)
                try:
                    _, stderr = proc.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    stderr_path.write_text(f"TIMEOUT after {timeout}s\n")
                    raise Vol3Error(f"timeout running {plugin}")
            stderr_path.write_bytes(stderr or b"")
        except FileNotFoundError as e:
            raise Vol3Error(f"vol executable not found: {e}") from e
        rc = proc.returncode
        # Cheap line-count pass — no JSON parsing.
        if stdout_path.is_file():
            with stdout_path.open("rb") as f:
                row_count = sum(1 for line in f if line.strip())
    else:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
            raise Vol3Error(f"timeout running {plugin}") from e
        stderr_path.write_text(proc.stderr or "")
        raw = proc.stdout or ""
        stdout_path.write_text(raw)
        rc = proc.returncode
        if raw.strip():
            try:
                parsed = json.loads(raw)
                rows = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                rows = []

    return PluginRun(
        plugin=plugin,
        image=image,
        rc=rc,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        rows=rows,
        command=cmd,
        version=_vol_version(),
        streaming=streaming,
        row_count=row_count if streaming else len(rows),
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


def dumpfiles(image: str | Path, out_dir: str | Path,
              *, pids: list[int] | None = None,
              timeout: int = 1800) -> PluginRun:
    """Run `vol3 windows.dumpfiles.DumpFiles [--pid <p> ...]` to carve
    file-object content out of a memory image.

    Without ``pids`` the plugin dumps EVERY mapped file object — useful
    on small images, very noisy on workstation-sized captures (10k+
    files). Callers should pass a focused PID list (e.g. processes
    flagged by malfind / hidden-procs / suspicious_threads).

    Carved files land under ``out_dir`` with names like
    ``file.<addr>.<name>.dat``. The plugin's stdout JSON enumerates
    each carved file's PID + handle + cache-type + on-disk path.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    extra: list[str] = []
    if pids:
        for pid in pids:
            extra.extend(["--pid", str(int(pid))])
    return run_plugin(
        image=image, plugin="windows.dumpfiles.DumpFiles",
        out_dir=out_dir, extra_args=extra, timeout=timeout,
        with_output_dir=True,
    )
