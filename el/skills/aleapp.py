"""Skill: wrap ALEAPP (Brignoni — Android Logs, Events, and Protobuf
Parser).

Closes the FOR585-mobile gap-doc bullet "dedicated aleapp wrapper
module". Companion to :mod:`el.skills.ileapp` — same shape, same
``ArtifactTable`` contract, different vendor target. ALEAPP covers
the core Android artefacts the analyst pivots on:

- ``contacts2.db`` / ``mmssms.db``
- Chrome / WebView ``History`` + ``Cookies``
- WhatsApp ``msgstore.db`` / Telegram ``cache4.db`` / Signal
- Wi-Fi ``WifiConfigStore.xml`` / ``logcat`` ``radio.log``
- Geolocation provider DBs + EXIF from ``DCIM``
- App installation inventory + per-app SQLite DBs at
  ``/data/data/<pkg>/databases/``
- Bluetooth / Battery / Quick-Settings telemetry

Why subprocess wrap rather than reimplement: ALEAPP already
covers ~150 artefacts and tracks Android version drift.
Tool output IS evidence (CLAUDE.md rule): the per-artifact TSV
produced by ALEAPP's ``_TSV_Exports/`` is exactly the structured
shape EL's evidence chain consumes.

Pure subprocess; no FUSE / no kernel. Tested against ALEAPP
v3.2+ which exposes the CLI as ``python ALEAPP/aleapp.py``.
Resolved-from-env: ``EL_ALEAPP_DIR`` overrides the
``/opt/ALEAPP`` default location.
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


_DEFAULT_ALEAPP = Path("/opt/ALEAPP")


class ALeappError(RuntimeError):
    """Raised on any failure invoking ALEAPP."""


@dataclass
class ArtifactTable:
    """One ALEAPP TSV → headers + rows + the source path. Mirrors
    iLEAPP's ArtifactTable for cross-platform analyst parity."""
    name: str
    path: Path
    headers: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    truncated: bool = False
    total_rows: int = 0

    @property
    def populated(self) -> bool:
        return self.total_rows > 0


@dataclass
class ALeappRun:
    input_path: Path
    out_dir: Path
    report_dir: Path
    stdout_path: Path
    stderr_path: Path
    rc: int
    tables: list[ArtifactTable] = field(default_factory=list)
    version: str = ""


# ---------------------------------------------------------------------------
# Resolver helpers
# ---------------------------------------------------------------------------


def _aleapp_dir() -> Path:
    env = os.environ.get("EL_ALEAPP_DIR")
    if env:
        p = Path(env)
        if p.is_dir():
            return p
    return _DEFAULT_ALEAPP


def _python() -> str:
    return sys.executable


def is_aleapp_available() -> bool:
    """True iff /opt/ALEAPP/aleapp.py (or ``EL_ALEAPP_DIR``) exists."""
    return (_aleapp_dir() / "aleapp.py").is_file()


# Mode strings ALEAPP accepts — passed via ``-t``. ``fs`` consumes a
# folder with extracted Android files; ``tar`` / ``zip`` / ``gz``
# consume the compressed archive directly.
_VALID_MODES = ("fs", "tar", "zip", "gz")


def detect_mode(input_path: Path) -> str:
    """Pick the right ``-t`` mode based on the input file's
    extension. Directory → fs; .tar / .zip / .gz → matching mode.
    Defaults to ``fs`` when the extension isn't recognised so the
    caller can be explicit if needed."""
    p = Path(input_path)
    if p.is_dir():
        return "fs"
    name = p.name.lower()
    if name.endswith(".tar"):
        return "tar"
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(".gz"):
        return "gz"
    return "fs"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run(input_path: Path, out_dir: Path,
        *, mode: str | None = None,
        timeout: int = 14400) -> ALeappRun:
    """Invoke ALEAPP against an Android extraction.

    Parameters
    ----------
    input_path : Path
        Either a folder of extracted files (``mode="fs"``) or a
        compressed archive (``mode="tar"`` / ``"zip"`` / ``"gz"``).
        ``mode=None`` (default) auto-detects from the path's
        extension via :func:`detect_mode`.
    out_dir : Path
        Pre-existing directory ALEAPP will write its timestamped
        report subdir inside.
    timeout : int
        Wall-clock cap. Default 4 h, same rationale as iLEAPP:
        FUSE-bridged paths balloon per-file cost, so pre-stage
        the input on a local FS for speed.
    """
    aleapp_dir = _aleapp_dir()
    script = aleapp_dir / "aleapp.py"
    if not script.is_file():
        raise ALeappError(
            f"ALEAPP not installed at {aleapp_dir} — set "
            f"EL_ALEAPP_DIR or `git clone abrignoni/ALEAPP /opt/ALEAPP`")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if mode is None:
        mode = detect_mode(input_path)
    if mode not in _VALID_MODES:
        raise ALeappError(
            f"invalid mode {mode!r} — must be one of {_VALID_MODES}")

    stdout_path = out_dir / "aleapp.stdout"
    stderr_path = out_dir / "aleapp.stderr"
    cmd = [_python(), str(script),
           "-t", mode, "-i", str(input_path), "-o", str(out_dir)]
    try:
        proc = subprocess.run(
            cmd, check=False, capture_output=True,
            timeout=timeout, text=True,
        )
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(
            (e.stderr or "")
            + f"\n[el] ALEAPP timed out after {timeout}s")
        raise ALeappError(
            f"ALEAPP timed out after {timeout}s") from e
    except OSError as e:
        raise ALeappError(f"ALEAPP invocation failed: {e}") from e

    stdout_path.write_text(proc.stdout or "")
    stderr_path.write_text(proc.stderr or "")

    # ALEAPP writes its run into ``ALEAPP_Reports_YYYYMMDD-HHMMSS/``
    candidates = sorted(
        out_dir.glob("ALEAPP_Reports_*"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0)
    report_dir = candidates[-1] if candidates else out_dir

    version = ""
    for line in (proc.stdout or "").splitlines():
        if "ALEAPP v" in line:
            version = line.split("ALEAPP", 1)[1].strip().split()[0]
            break

    tables = _walk_tsv_exports(report_dir)
    return ALeappRun(
        input_path=Path(input_path), out_dir=out_dir,
        report_dir=report_dir,
        stdout_path=stdout_path, stderr_path=stderr_path,
        rc=proc.returncode, tables=tables, version=version,
    )


def _walk_tsv_exports(report_dir: Path,
                       *, max_rows_per_table: int = 5_000
                       ) -> list[ArtifactTable]:
    """Walk ``<report_dir>/_TSV_Exports/`` and load each TSV into
    an ``ArtifactTable``. Caps row count per table — long
    SMS / WhatsApp histories don't materialise wholesale."""
    out: list[ArtifactTable] = []
    tsv_dir = Path(report_dir) / "_TSV_Exports"
    if not tsv_dir.is_dir():
        return out
    for f in sorted(tsv_dir.glob("*.tsv")):
        rows: list[list[str]] = []
        headers: list[str] = []
        truncated = False
        total = 0
        try:
            with f.open("r", errors="replace", newline="") as fh:
                reader = csv.reader(fh, delimiter="\t")
                for i, row in enumerate(reader):
                    if i == 0:
                        headers = row
                        continue
                    total += 1
                    if len(rows) < max_rows_per_table:
                        rows.append(row)
                    elif not truncated:
                        truncated = True
        except OSError:
            continue
        out.append(ArtifactTable(
            name=f.name, path=f,
            headers=headers, rows=rows,
            truncated=truncated, total_rows=total,
        ))
    return out


# ---------------------------------------------------------------------------
# Aggregations / convenience accessors
# ---------------------------------------------------------------------------


def find_table(run: ALeappRun, name_substr: str
                ) -> ArtifactTable | None:
    """Case-insensitive substring lookup for an artefact by name.
    Returns the first match; None when no TSV name carries the
    needle."""
    n = (name_substr or "").lower()
    for t in run.tables:
        if n in t.name.lower():
            return t
    return None


def populated_table_names(run: ALeappRun) -> list[str]:
    """Sorted list of artefact names with at least one row.
    Useful as a quick triage view of the run's coverage."""
    return sorted(t.name for t in run.tables if t.populated)


__all__ = [
    "ArtifactTable", "ALeappRun", "ALeappError",
    "is_aleapp_available", "detect_mode", "run",
    "find_table", "populated_table_names",
]
