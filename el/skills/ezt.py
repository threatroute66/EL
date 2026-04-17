"""Skill: EZ Tools generic runner.

EZ Tools are .NET binaries shipped under /opt/zimmermantools. We invoke
them via the system dotnet runtime. Each tool gets its own thin wrapper
because the CLI flags are not uniform.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem


EZT_BASE = Path("/opt/zimmermantools")


class EztError(RuntimeError):
    pass


@dataclass
class EztRun:
    tool: str
    rc: int
    out_dir: Path
    stderr_path: Path
    command: list[str]
    output_files: list[Path]

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        h = hashlib.sha256()
        for p in sorted(self.output_files):
            try:
                h.update(p.read_bytes())
            except Exception:
                continue
        return EvidenceItem(
            tool=f"ezt/{self.tool}", version="ez-tool",
            command=" ".join(self.command),
            output_sha256=h.hexdigest() or "0" * 64,
            output_path=str(self.out_dir),
            extracted_facts={"rc": self.rc,
                             "output_files": [str(p.name) for p in self.output_files],
                             **(facts or {})},
        )


def _dotnet() -> str:
    p = shutil.which("dotnet")
    if not p:
        raise EztError("dotnet not on PATH")
    return p


def _resolve_dll(dll: str, subdir: str | None) -> Path:
    full = (EZT_BASE / subdir / dll) if subdir else (EZT_BASE / dll)
    if not full.exists():
        raise EztError(f"EZ Tool not installed: {full}")
    return full


def run_ezt(dll: str, subdir: str | None, args: list[str], out_dir: Path,
            timeout: int = 1800) -> EztRun:
    out_dir.mkdir(parents=True, exist_ok=True)
    full = _resolve_dll(dll, subdir)
    cmd = [_dotnet(), str(full), *args]
    stderr_path = out_dir / f"{Path(dll).stem}.stderr"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=out_dir)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise EztError(f"timeout running {dll}") from e
    (out_dir / f"{Path(dll).stem}.stdout").write_text(proc.stdout or "")
    stderr_path.write_text(proc.stderr or "")
    output_files = sorted([p for p in out_dir.iterdir() if p.is_file()])
    return EztRun(tool=Path(dll).stem, rc=proc.returncode, out_dir=out_dir,
                  stderr_path=stderr_path, command=cmd, output_files=output_files)


_EVTX_MAPS = EZT_BASE / "EvtxeCmd" / "Maps"
_KROLL_BATCH = EZT_BASE / "RECmd" / "BatchExamples" / "Kroll_Batch.reb"


def run_evtxecmd(evtx_file_or_dir: Path, out_dir: Path, timeout: int = 1800,
                 use_maps: bool = True) -> EztRun:
    """EvtxECmd parses EVTX files. SKILL: --maps enables PayloadData columns
    (rich structured field extraction)."""
    args: list[str] = []
    if evtx_file_or_dir.is_dir():
        args += ["-d", str(evtx_file_or_dir)]
    else:
        args += ["-f", str(evtx_file_or_dir)]
    args += ["--csv", str(out_dir), "--csvf", "evtx_parsed.csv"]
    if use_maps and _EVTX_MAPS.exists():
        args += ["--maps", str(_EVTX_MAPS)]
    return run_ezt("EvtxECmd.dll", "EvtxeCmd", args, out_dir, timeout)


def run_mftecmd(mft_path: Path, out_dir: Path, timeout: int = 1800,
                all_timestamps: bool = True, recover_slack: bool = False) -> EztRun:
    """SKILL: --at = both $SI and $FN timestamps; --rs = recover slack-space MFT entries."""
    args = ["-f", str(mft_path), "--csv", str(out_dir), "--csvf", "mft_parsed.csv"]
    if all_timestamps:
        args += ["--at"]
    if recover_slack:
        args += ["--rs"]
    return run_ezt("MFTECmd.dll", None, args, out_dir, timeout)


def run_usnjrnl(j_path: Path, out_dir: Path, timeout: int = 1800,
                vss: bool = False) -> EztRun:
    args = ["-f", str(j_path), "--csv", str(out_dir), "--csvf", "usnjrnl_parsed.csv"]
    if vss:
        args += ["--vss"]
    return run_ezt("MFTECmd.dll", None, args, out_dir, timeout)


def run_recmd(hive_path: Path, out_dir: Path, batch: str | None = None,
              timeout: int = 1800) -> EztRun:
    """SKILL: prefer --bn Kroll_Batch.reb — covers UserAssist, RecentDocs, TypedPaths,
    MRU, USB, Run keys, WordWheelQuery, OpenSaveMRU, etc. in one pass."""
    args = ["-d" if hive_path.is_dir() else "-f", str(hive_path),
            "--csv", str(out_dir)]
    chosen = batch
    if not chosen and _KROLL_BATCH.exists():
        chosen = str(_KROLL_BATCH)
    if chosen:
        args += ["--bn", chosen]
    return run_ezt("RECmd.dll", "RECmd", args, out_dir, timeout)


def run_amcache(amcache_hive: Path, out_dir: Path, timeout: int = 600,
                ignore_logs: bool = False) -> EztRun:
    args = ["-f", str(amcache_hive), "--csv", str(out_dir)]
    if ignore_logs:
        args += ["--nl"]
    return run_ezt("AmcacheParser.dll", None, args, out_dir, timeout)


def run_appcompat(system_hive: Path, out_dir: Path, timeout: int = 600,
                  sort_recent: bool = True) -> EztRun:
    """Shimcache parser. -t sorts by last-modified time descending."""
    args = ["-f", str(system_hive), "--csv", str(out_dir),
            "--csvf", "shimcache.csv"]
    if sort_recent:
        args += ["-t"]
    return run_ezt("AppCompatCacheParser.dll", None, args, out_dir, timeout)


def run_pecmd(prefetch_dir: Path, out_dir: Path, timeout: int = 600) -> EztRun:
    args = ["-d", str(prefetch_dir), "--csv", str(out_dir),
            "--csvf", "prefetch_parsed.csv"]
    return run_ezt("PECmd.dll", None, args, out_dir, timeout)


def run_sbecmd(target: Path, out_dir: Path, timeout: int = 600) -> EztRun:
    """Shellbags. --tz UTC: SKILL warns default is local."""
    args = ["-d" if target.is_dir() else "-f", str(target),
            "--csv", str(out_dir), "--tz", "UTC", "--dedupe"]
    return run_ezt("SBECmd.dll", None, args, out_dir, timeout)


def run_jlecmd(jumplist_dir: Path, out_dir: Path, timeout: int = 600) -> EztRun:
    args = ["-d", str(jumplist_dir), "--csv", str(out_dir),
            "--csvf", "jumplists_parsed.csv"]
    return run_ezt("JLECmd.dll", None, args, out_dir, timeout)


def run_lecmd(lnk_dir: Path, out_dir: Path, timeout: int = 600) -> EztRun:
    args = ["-d", str(lnk_dir), "--csv", str(out_dir), "--csvf", "lnk_parsed.csv"]
    return run_ezt("LECmd.dll", None, args, out_dir, timeout)


def run_srumecmd(srudb: Path, out_dir: Path, software_hive: Path | None = None,
                 timeout: int = 1800) -> EztRun:
    """SKILL: SRUM confirms execution AND data volumes (C2 exfil indicator).
    Pass SOFTWARE hive for application-name resolution."""
    args = ["-f", str(srudb), "--csv", str(out_dir), "--csvf", "srum_parsed.csv"]
    if software_hive:
        args += ["-r", str(software_hive)]
    return run_ezt("SrumECmd.dll", None, args, out_dir, timeout)


def run_rbcmd(recyclebin_dir: Path, out_dir: Path, timeout: int = 600) -> EztRun:
    args = ["-d", str(recyclebin_dir), "--csv", str(out_dir),
            "--csvf", "recyclebin_parsed.csv"]
    return run_ezt("RBCmd.dll", None, args, out_dir, timeout)
