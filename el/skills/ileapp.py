"""Skill: wrap iLEAPP (Brignoni — iOS Logs, Events, And Plists Parser).

iLEAPP is a 80+-artifact pure-Python parser for iOS file-system
extractions and iTunes/Finder logical backups. Each module emits a
TSV/CSV report + an HTML page; we drive it as a subprocess and walk
the resulting `_TSV_Exports/` directory.

Why wrap it instead of writing parsers from scratch:
- iLEAPP already covers the long tail (iMessage / SMS / Safari
  history / WhatsApp / Photos.sqlite / Knowledge events / app
  installs / Wi-Fi / Bluetooth / Apple Pay) and is actively
  maintained by the FOR585 author.
- Tool output IS evidence (CLAUDE.md rule). The TSV per artifact is
  exactly the shape EL's evidence chain wants.

Pure subprocess; no FUSE / no kernel involvement. Tested against
iLEAPP v2.3+ which exposes the CLI as `python iLEAPP/ileapp.py`.
"""
from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


# Standard install location used by SIFT / EL. Override via env var
# `EL_ILEAPP_DIR` for non-canonical layouts.
_DEFAULT_ILEAPP = Path("/opt/iLEAPP")


class ILeappError(RuntimeError):
    """Raised on any failure invoking iLEAPP."""


@dataclass
class ArtifactTable:
    """One iLEAPP TSV → headers + rows + the source path. Rows are
    capped on read to keep memory bounded on long iMessage histories."""
    name: str                              # e.g. "Calls.tsv"
    path: Path
    headers: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    truncated: bool = False
    total_rows: int = 0

    @property
    def populated(self) -> bool:
        return self.total_rows > 0


@dataclass
class ILeappRun:
    input_path: Path
    out_dir: Path                          # base out dir we passed
    report_dir: Path                       # the timestamped subdir iLEAPP made
    stdout_path: Path
    stderr_path: Path
    rc: int
    tables: list[ArtifactTable] = field(default_factory=list)
    version: str = ""


def _ileapp_dir() -> Path:
    """Resolve the iLEAPP install dir from `EL_ILEAPP_DIR` env var,
    falling back to /opt/iLEAPP."""
    env = os.environ.get("EL_ILEAPP_DIR")
    if env:
        p = Path(env)
        if p.is_dir():
            return p
    return _DEFAULT_ILEAPP


def _python() -> str:
    """Use the same Python executable EL is running under so iLEAPP
    sees the venv's installed dependencies."""
    return sys.executable


def is_ileapp_available() -> bool:
    """True iff /opt/iLEAPP/ileapp.py (or `EL_ILEAPP_DIR`) exists."""
    return (_ileapp_dir() / "ileapp.py").is_file()


def run(input_path: Path, out_dir: Path, *,
        mode: str = "fs", timeout: int = 14400) -> ILeappRun:
    """Invoke iLEAPP against an extracted iOS file-system tree.

    Parameters
    ----------
    input_path : Path
        Either an iOS AFU file-system root (`mode="fs"`, default) or
        an iTunes backup folder (`mode="itunes"`).
    out_dir : Path
        Pre-existing directory iLEAPP will write its timestamped
        report subdir inside.
    timeout : int
        Wall-clock cap. Default 4 h. iLEAPP touches thousands of
        small SQLite + plist files; on a local SSD-backed FS the run
        finishes in 5-30 min, but on a FUSE-bridged path
        (e.g. /mnt/hgfs/ from a VMware host) the per-file open cost
        balloons and the same dump takes hours. Pre-stage the input
        on a local filesystem before running if speed matters.
    """
    ileapp_dir = _ileapp_dir()
    script = ileapp_dir / "ileapp.py"
    if not script.is_file():
        raise ILeappError(
            f"iLEAPP not installed at {ileapp_dir} — set "
            f"EL_ILEAPP_DIR or `git clone abrignoni/iLEAPP /opt/iLEAPP`"
        )
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stdout_path = out_dir / "ileapp.stdout"
    stderr_path = out_dir / "ileapp.stderr"
    cmd = [_python(), str(script),
           "-t", mode, "-i", str(input_path), "-o", str(out_dir)]
    try:
        proc = subprocess.run(
            cmd, check=False, capture_output=True,
            timeout=timeout, text=True,
        )
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(
            (e.stderr or "") + f"\n[el] iLEAPP timed out after {timeout}s")
        raise ILeappError(f"iLEAPP timed out after {timeout}s") from e
    except OSError as e:
        raise ILeappError(f"iLEAPP invocation failed: {e}") from e

    stdout_path.write_text(proc.stdout or "")
    stderr_path.write_text(proc.stderr or "")

    # iLEAPP writes its run into a timestamped subdir
    # `iLEAPP_Reports_YYYYMMDD-HHMMSS/`. Locate the most-recent one.
    candidates = sorted(out_dir.glob("iLEAPP_Reports_*"),
                        key=lambda p: p.stat().st_mtime if p.exists() else 0)
    report_dir = candidates[-1] if candidates else out_dir

    # Parse stdout for the version banner so evidence records carry it.
    version = ""
    for line in (proc.stdout or "").splitlines():
        if "iLEAPP v" in line:
            version = line.split("iLEAPP", 1)[1].strip().split()[0]
            break

    tables = _walk_tsv_exports(report_dir)
    return ILeappRun(
        input_path=Path(input_path), out_dir=out_dir,
        report_dir=report_dir,
        stdout_path=stdout_path, stderr_path=stderr_path,
        rc=proc.returncode, tables=tables, version=version,
    )


def _walk_tsv_exports(report_dir: Path,
                       row_cap: int = 5000) -> list[ArtifactTable]:
    """Walk the iLEAPP report dir for `_TSV_Exports/*.tsv` and
    parse each into an ArtifactTable, capped at `row_cap` rows
    to keep memory bounded on multi-million-row iMessage extracts."""
    tables: list[ArtifactTable] = []
    tsv_root = report_dir / "_TSV Exports"
    # Brignoni's repo flips the underscore/space convention every
    # so often. Try both.
    if not tsv_root.is_dir():
        tsv_root = report_dir / "_TSV_Exports"
    if not tsv_root.is_dir():
        return tables
    for tsv_path in sorted(tsv_root.rglob("*.tsv")):
        if not tsv_path.is_file():
            continue
        t = ArtifactTable(name=tsv_path.name, path=tsv_path)
        try:
            with tsv_path.open("r", errors="replace") as f:
                reader = csv.reader(f, delimiter="\t")
                try:
                    t.headers = next(reader)
                except StopIteration:
                    pass
                for row in reader:
                    t.total_rows += 1
                    if len(t.rows) < row_cap:
                        t.rows.append(row)
                    elif not t.truncated:
                        t.truncated = True
        except OSError:
            continue
        tables.append(t)
    return tables


__all__ = [
    "ArtifactTable", "ILeappError", "ILeappRun",
    "is_ileapp_available", "run",
]
