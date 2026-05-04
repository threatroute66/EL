"""MemProcFS skill — memory-as-filesystem forensic triage.

Wraps MemProcFS (Ulf Frisk) in *forensic mode*: mounts a Windows memory image
as a virtual FUSE filesystem, lets the built-in forensic scanner populate
`forensic/findevil`, `forensic/yara`, `forensic/timeline`, then reads those
outputs and emits them as Findings.

This is **complementary** to ``el.skills.vol3``, not a replacement:
  - vol3 owns deep plugin analysis (psscan, malfind, modscan, etc.)
  - MemProcFS owns triage breadth via its built-in FindEvil scanner
  - Their outputs corroborate each other — exactly what the Red Reviewer's
    "single tool / single source" challenger asks for.

Project: https://github.com/ufrisk/MemProcFS
Forensic mode docs: https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic
"""
from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from el.schemas.finding import EvidenceItem


class MemProcFSError(Exception):
    pass


def _which() -> Path:
    candidates = [
        Path("/opt/memprocfs/memprocfs"),
        Path("/usr/local/bin/memprocfs"),
    ]
    p = shutil.which("memprocfs")
    if p:
        candidates.insert(0, Path(p))
    for c in candidates:
        if c.is_file():
            return c
    raise MemProcFSError(
        "memprocfs binary not found — install via install.sh or "
        "download from https://github.com/ufrisk/MemProcFS/releases"
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_csv_rows(path: Path, max_rows: int = 1000) -> list[dict]:
    """Read up to max_rows from a CSV file. Returns [] on any failure."""
    try:
        rows: list[dict] = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                rows.append(row)
        return rows
    except (OSError, csv.Error):
        return []


@dataclass
class FindEvilHit:
    rule: str
    process: str
    pid: str
    address: str
    detail: str

    @classmethod
    def from_csv_row(cls, row: dict) -> "FindEvilHit":
        return cls(
            rule=row.get("Rule", "").strip(),
            process=row.get("Process", "").strip(),
            pid=row.get("PID", "").strip(),
            address=row.get("Address", "").strip(),
            detail=row.get("Detail", "")[:500].strip(),
        )


@dataclass
class MemProcFSResult:
    image_path: Path
    mount_point: Path
    forensic_findings: list[FindEvilHit] = field(default_factory=list)
    yara_hits: list[dict] = field(default_factory=list)
    findevil_csv_path: Path | None = None
    findevil_csv_sha256: str | None = None
    yara_csv_path: Path | None = None
    yara_csv_sha256: str | None = None
    duration_seconds: float = 0.0
    command: list[str] = field(default_factory=list)
    stderr_path: Path | None = None
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        """Convert the run summary to an EvidenceItem."""
        extra = facts or {}
        return EvidenceItem(
            tool="memprocfs",
            version="5.17.6",
            command=" ".join(str(p) for p in self.command),
            output_sha256=self.findevil_csv_sha256 or "0" * 64,
            output_path=str(self.findevil_csv_path or self.mount_point),
            extracted_facts={
                "image_sha256_first16": _sha256_file(self.image_path)[:16] if self.image_path.exists() else None,
                "duration_seconds": round(self.duration_seconds, 2),
                "findevil_hits": len(self.forensic_findings),
                "yara_hits": len(self.yara_hits),
                "note": self.note,
                **extra,
            },
        )


def run_forensic_scan(
    image_path: Path,
    mount_dir: Path,
    *,
    forensic_mode: int = 1,
    timeout_seconds: int = 1800,
    yara_rules_path: Path | None = None,
    stderr_dir: Path | None = None,
) -> MemProcFSResult:
    """Mount *image_path* with MemProcFS, run forensic scan, harvest findings.

    Steps:
      1. Mount image at *mount_dir* with ``-forensic <mode>``
      2. Wait for the forensic scan to finish (polls
         ``forensic/progress_percent.txt`` for "100").
      3. Read ``forensic/findevil/findevil.csv`` and yara CSV.
      4. Unmount and return a :class:`MemProcFSResult`.

    Args:
        image_path: raw / dump / lime / vmem memory file. Must exist.
        mount_dir: empty directory where the FUSE FS will be mounted.
            Created if it does not exist.
        forensic_mode: MemProcFS forensic level (1=in-memory sqlite, 2=temp,
            3=keep temp db, 4=static named db). Use ``1`` for triage.
        timeout_seconds: max time to wait for scan completion.
        yara_rules_path: optional YARA rules file for ``-forensic-yara-rules``.
        stderr_dir: where to write the ``memprocfs.stderr`` log; defaults to
            *mount_dir*'s parent.

    The mount is always cleaned up — even on error.
    """
    image_path = Path(image_path)
    mount_dir = Path(mount_dir)
    if not image_path.is_file():
        raise MemProcFSError(f"image not found: {image_path}")
    mount_dir.mkdir(parents=True, exist_ok=True)
    if any(mount_dir.iterdir()):
        raise MemProcFSError(
            f"mount point not empty: {mount_dir} — refusing to mount over content"
        )

    binary = _which()
    cmd: list[str] = [
        str(binary),
        "-device", str(image_path),
        "-mount", str(mount_dir),
        "-forensic", str(forensic_mode),
    ]
    if yara_rules_path is not None:
        cmd.extend(["-forensic-yara-rules", str(yara_rules_path)])

    stderr_dir = stderr_dir or mount_dir.parent
    stderr_dir.mkdir(parents=True, exist_ok=True)
    stderr_path = stderr_dir / "memprocfs.stderr"

    started = time.time()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=stderr_path.open("wb"),
        # Spawn detached so the FUSE mount survives our wait-loop:
        start_new_session=True,
    )

    result = MemProcFSResult(
        image_path=image_path,
        mount_point=mount_dir,
        command=cmd,
        stderr_path=stderr_path,
    )

    try:
        # Wait for the FS to actually appear (FUSE mount can take a few seconds).
        forensic_root = mount_dir / "forensic"
        for _ in range(60):
            if forensic_root.is_dir():
                break
            if proc.poll() is not None:
                rc = proc.returncode
                raise MemProcFSError(
                    f"memprocfs exited early (rc={rc}); see {stderr_path}"
                )
            time.sleep(1)
        else:
            raise MemProcFSError(
                f"timed out waiting for FUSE mount at {forensic_root}"
            )

        # Wait for forensic scan to complete by polling progress_percent.txt.
        progress_path = forensic_root / "progress_percent.txt"
        deadline = started + timeout_seconds
        while time.time() < deadline:
            try:
                pct_text = progress_path.read_text(errors="replace").strip()
                if pct_text.startswith("100"):
                    break
            except OSError:
                pass
            time.sleep(2)
        else:
            result.note = (
                f"forensic scan did not reach 100% within {timeout_seconds}s; "
                "harvesting partial output"
            )

        # FindEvil — the headline triage signal.
        findevil_csv = forensic_root / "findevil" / "findevil.csv"
        if findevil_csv.is_file():
            result.findevil_csv_path = findevil_csv
            result.findevil_csv_sha256 = _sha256_file(findevil_csv)
            result.forensic_findings = [
                FindEvilHit.from_csv_row(r) for r in _read_csv_rows(findevil_csv)
            ]

        # YARA hits (if any rules ran).
        for candidate in (
            forensic_root / "yara" / "yara.csv",
            forensic_root / "yara" / "matches.csv",
        ):
            if candidate.is_file():
                result.yara_csv_path = candidate
                result.yara_csv_sha256 = _sha256_file(candidate)
                result.yara_hits = _read_csv_rows(candidate, max_rows=500)
                break

        result.duration_seconds = time.time() - started
        return result

    finally:
        # Always unmount and reap the process.
        try:
            subprocess.run(
                ["fusermount", "-u", str(mount_dir)],
                check=False,
                capture_output=True,
                timeout=30,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def iter_findevil_hits(result: MemProcFSResult) -> Iterator[FindEvilHit]:
    """Yield FindEvil hits with the most diagnostic ones first.

    Ordering: rules with explicit "MZ" / "INJECTED" / "HOLLOW" / "RWX" keywords
    sort first, since they're the highest-signal indicators in a triage pass.
    """
    priority_keywords = ("INJECTED", "HOLLOW", "RWX", "MZ", "PE_HEADER")

    def _rank(hit: FindEvilHit) -> int:
        for i, kw in enumerate(priority_keywords):
            if kw in hit.rule.upper():
                return i
        return len(priority_keywords)

    yield from sorted(result.forensic_findings, key=_rank)
