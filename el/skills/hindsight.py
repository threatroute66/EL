"""Hindsight skill — Chromium-family browser forensics.

Wraps Ryan Benson's Hindsight (`pyhindsight`) — the OSS standard for deep
Chromium-family forensic parsing. Covers Chrome, Edge, Brave, Opera, Vivaldi,
Chromium-derived shells. Goes well beyond the SQLite-table reading EL's
`browser` skill currently does for Firefox: includes Local Storage, IndexedDB,
Session Storage, cookies, autofill, login data, downloads, sync evidence,
extensions, FedCM, and timeline annotations.

Project: https://github.com/obsidianforensics/hindsight
JSONL output is the integration target — one event per line, easily
ingested into Findings without a CSV/XLSX intermediate step.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from el.schemas.finding import EvidenceItem


class HindsightError(Exception):
    pass


def _which() -> tuple[Path, list[str]]:
    """Return (python_interpreter, [hindsight_script_args]).

    Hindsight is installed as a script (`hindsight.py`) in the venv's bin/
    directory, but the script lacks an executable shebang on some installs.
    Always invoke it through the venv's python.
    """
    import sys
    py = Path(sys.executable)
    bin_dir = py.parent
    script = bin_dir / "hindsight.py"
    if py.is_file() and script.is_file():
        return py, [str(script)]
    # Fallback: shutil.which (in case hindsight is on PATH directly).
    p = shutil.which("hindsight.py") or shutil.which("hindsight")
    if p:
        return Path(p), []
    raise HindsightError(
        "Hindsight not found — install with `pip install pyhindsight` "
        "and the GitHub-only `ccl_chromium_reader` dependency"
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def looks_like_chromium_profile(path: Path) -> bool:
    """Heuristic: a Chromium *profile* dir has a 'History' SQLite + 'Cookies' file,
    or contains a 'Default'/'Profile *' subdir with the same."""
    if not path.is_dir():
        return False
    if (path / "History").is_file() and (path / "Cookies").is_file():
        return True
    for child in path.iterdir():
        if child.is_dir() and child.name in ("Default",) or (
            child.is_dir() and child.name.startswith("Profile ")
        ):
            if (child / "History").is_file():
                return True
    return False


@dataclass
class HindsightRun:
    profile_dir: Path
    output_jsonl: Path | None
    log_path: Path | None
    rc: int
    duration_seconds: float = 0.0
    record_count: int = 0
    distinct_event_types: list[str] = field(default_factory=list)
    output_sha256: str | None = None
    command: list[str] = field(default_factory=list)
    stderr_path: Path | None = None
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="hindsight",
            version="2026.04",
            command=" ".join(str(p) for p in self.command),
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_jsonl or self.profile_dir),
            extracted_facts={
                "profile_dir": str(self.profile_dir),
                "duration_seconds": round(self.duration_seconds, 2),
                "record_count": self.record_count,
                "event_types": self.distinct_event_types[:25],
                "rc": self.rc,
                "note": self.note,
                **extra,
            },
        )

    def iter_records(self, *, max_rows: int | None = None) -> Iterator[dict]:
        """Yield each JSONL record from the output file."""
        if not self.output_jsonl or not self.output_jsonl.is_file():
            return
        with self.output_jsonl.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if max_rows is not None and i >= max_rows:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def run(
    profile_dir: Path,
    output_dir: Path,
    *,
    timeout_seconds: int = 600,
) -> HindsightRun:
    """Run Hindsight against a Chromium profile directory; emit JSONL.

    Args:
        profile_dir: a Chromium profile dir (one containing 'History' +
            'Cookies') or a parent dir Hindsight will recursively search.
        output_dir: where to write hindsight output files.
        timeout_seconds: max runtime; large profiles can take minutes.
    """
    profile_dir = Path(profile_dir)
    output_dir = Path(output_dir)
    if not profile_dir.is_dir():
        raise HindsightError(f"profile_dir does not exist or is not a directory: {profile_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    out_base = output_dir / "hindsight_out"
    out_jsonl = output_dir / "hindsight_out.jsonl"
    log_path = output_dir / "hindsight.log"
    stderr_path = output_dir / "hindsight.stderr"

    py, leading = _which()
    cmd: list[str] = [
        str(py), *leading,
        "-i", str(profile_dir),
        "-o", str(out_base),  # Hindsight appends its own .jsonl extension
        "-f", "jsonl",
        "-l", str(log_path),
        "--temp_dir", str(output_dir / "tmp"),
    ]

    import time
    started = time.time()
    try:
        with stderr_path.open("wb") as ferr:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=ferr,
                timeout=timeout_seconds,
            )
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return HindsightRun(
            profile_dir=profile_dir, output_jsonl=None, log_path=log_path,
            rc=124, command=cmd, stderr_path=stderr_path,
            duration_seconds=time.time() - started,
            note=f"hindsight timed out after {timeout_seconds}s",
        )

    duration = time.time() - started

    # Hindsight writes <output_base>.jsonl on success; tolerate either path
    # (it might also write directly to out_jsonl name on some platforms).
    written = None
    for candidate in (out_jsonl, output_dir / "hindsight_out.jsonl",
                       out_base.with_suffix(".jsonl")):
        if candidate.is_file() and candidate.stat().st_size > 0:
            written = candidate
            break

    if written is None:
        return HindsightRun(
            profile_dir=profile_dir, output_jsonl=None, log_path=log_path,
            rc=rc, command=cmd, stderr_path=stderr_path,
            duration_seconds=duration,
            note="hindsight produced no JSONL output (profile may be empty or unsupported)",
        )

    # Pre-scan for record count + distinct event types (small files only).
    record_count = 0
    type_set: set[str] = set()
    try:
        with written.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record_count += 1
                if record_count <= 5000:  # bound the scan for very large outputs
                    try:
                        rec = json.loads(line)
                        et = rec.get("type") or rec.get("Type") or rec.get("row_type")
                        if et:
                            type_set.add(str(et))
                    except json.JSONDecodeError:
                        continue
    except OSError as e:
        return HindsightRun(
            profile_dir=profile_dir, output_jsonl=written, log_path=log_path,
            rc=rc, command=cmd, stderr_path=stderr_path,
            duration_seconds=duration,
            note=f"output written but unreadable: {e}",
        )

    return HindsightRun(
        profile_dir=profile_dir,
        output_jsonl=written,
        log_path=log_path,
        rc=rc,
        duration_seconds=duration,
        record_count=record_count,
        distinct_event_types=sorted(type_set),
        output_sha256=_sha256_file(written),
        command=cmd,
        stderr_path=stderr_path,
    )


def find_profiles(root: Path, *, max_depth: int = 6) -> list[Path]:
    """Walk *root* looking for Chromium profile directories.

    Returns all directories that have both a 'History' file and a 'Cookies'
    file (the canonical Chromium profile signature). De-duplicated.
    """
    root = Path(root)
    if not root.is_dir():
        return []
    found: list[Path] = []
    seen: set[Path] = set()

    def _walk(dir_path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = list(dir_path.iterdir())
        except (PermissionError, OSError):
            return
        files = {e.name for e in entries if e.is_file()}
        if "History" in files and "Cookies" in files:
            r = dir_path.resolve()
            if r not in seen:
                seen.add(r)
                found.append(dir_path)
        for entry in entries:
            if entry.is_dir() and not entry.is_symlink():
                _walk(entry, depth + 1)

    _walk(root, 0)
    return found
