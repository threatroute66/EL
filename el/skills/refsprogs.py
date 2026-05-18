"""Skill: refsprogs — read-only ReFS filesystem walk.

Wraps the userspace ReFS tools from https://github.com/unsound/refsprogs
(GPLv2+). The Linux kernel + Sleuth Kit have no ReFS support; this
is the only path EL has to walk Windows 11 Dev Drives, Server 2016+
ReFS volumes, and Storage Spaces resilient pools on Linux.

Coverage caveat from the upstream README: "As ReFS lacks
documentation the utilities are dependent on independent
exploration of the on-disk format, and thus cannot yet be fully
relied upon." We treat refsprogs output at `medium` confidence and
explicitly tag findings as best-effort in the claim text so the
analyst knows.

Tools wrapped:

  - refsinfo  → volume metadata (ReFS version, sector / cluster
                sizes, serial number) — analogue of `fsstat`
  - refslabel → volume label — used in the case header
  - refsls    → filesystem walk → text listing — analogue of `fls`
                (refsprogs has no bodyfile output mode so we keep
                the listing as-is and emit per-finding facts;
                mactime-style time tables aren't reachable today)
  - refscat   → file content read — analogue of `icat`

The tools expect a raw ReFS-volume file (not a disk image
containing a ReFS partition). When the case has a partitioned
disk, the caller must carve the partition out via Python (or
`dd`) before invoking these wrappers.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class RefsprogsError(RuntimeError):
    pass


@dataclass
class RefsVolumeInfo:
    """Structured projection of `refsinfo` stdout."""
    refs_version: str = ""
    volume_serial: str = ""
    sector_size: int = 0
    cluster_size: int = 0
    sector_count: int = 0
    cluster_count: int = 0
    raw_stdout_path: Path | None = None
    rc: int = 0
    warnings: list[str] = field(default_factory=list)

    def as_evidence(self, extra: dict | None = None) -> EvidenceItem:
        h = hashlib.sha256()
        if self.raw_stdout_path and self.raw_stdout_path.is_file():
            h.update(self.raw_stdout_path.read_bytes())
        return EvidenceItem(
            tool="refsinfo", version="refsprogs",
            command="refsinfo <volume>",
            output_sha256=h.hexdigest() or "0" * 64,
            output_path=str(self.raw_stdout_path or ""),
            extracted_facts={
                "refs_version": self.refs_version,
                "volume_serial": self.volume_serial,
                "sector_size": self.sector_size,
                "cluster_size": self.cluster_size,
                "sector_count": self.sector_count,
                "cluster_count": self.cluster_count,
                "warnings_count": len(self.warnings),
                "warnings_sample": self.warnings[:3],
                "phase": "refs_probe",
                **(extra or {}),
            },
        )


@dataclass
class RefsListing:
    """Result of a `refsls -l -R` recursive walk."""
    entries: list[dict] = field(default_factory=list)
    raw_stdout_path: Path | None = None
    rc: int = 0
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    def as_evidence(self, extra: dict | None = None) -> EvidenceItem:
        h = hashlib.sha256()
        if self.raw_stdout_path and self.raw_stdout_path.is_file():
            h.update(self.raw_stdout_path.read_bytes())
        return EvidenceItem(
            tool="refsls", version="refsprogs",
            command="refsls -l -R <volume>",
            output_sha256=h.hexdigest() or "0" * 64,
            output_path=str(self.raw_stdout_path or ""),
            extracted_facts={
                "entry_count": self.entry_count,
                "truncated": self.truncated,
                "warnings_count": len(self.warnings),
                "phase": "refs_walk",
                **(extra or {}),
            },
        )


# ---------------------------------------------------------------------------
# Helpers — binary discovery + signature probe
# ---------------------------------------------------------------------------

def _bin(name: str) -> str:
    p = shutil.which(name)
    if not p:
        raise RefsprogsError(
            f"{name} not on PATH — install refsprogs ("
            "build from https://github.com/unsound/refsprogs) to handle "
            "ReFS volumes")
    return p


def is_refs_signature(path: Path, offset: int = 0) -> bool:
    """Cheap header check — read 0x14 bytes at `offset` and look for
    the ReFS OEM signature at byte 0x03 (`ReFS`) AND the FSRS
    sub-signature at byte 0x10. Both must be present to avoid
    false positives on stray text data.

    `offset` is the byte offset into the source file (when scanning
    a partitioned disk image, pass the partition's start byte)."""
    try:
        with Path(path).open("rb") as f:
            f.seek(offset)
            head = f.read(0x14)
    except OSError:
        return False
    return (len(head) >= 0x14
            and head[3:7] == b"ReFS"
            and head[0x10:0x14] == b"FSRS")


# ---------------------------------------------------------------------------
# Carve a ReFS partition out of a partitioned disk image
# ---------------------------------------------------------------------------

def carve_partition(disk_image: Path, partition_start_sector: int,
                      partition_length_sectors: int,
                      sector_size: int, out_path: Path) -> Path:
    """Copy a ReFS partition out of a partitioned disk into its own
    raw file at `out_path`. refsprogs doesn't accept a partition-
    offset flag; the wrapper for `_raw_disk_walk` needs a per-
    partition standalone file.

    The output is written **sparsely** — chunks that are all zeros
    are skipped (`fout.seek` past them) so the on-disk allocated
    size matches only the partition's actual data, not its declared
    length. A 50 GiB partition with ~300 MB of real data ends up
    using ~300 MB of disk instead of 50 GiB. The file LENGTH still
    reads as the partition's full size — refsprogs sees a complete
    volume — but `du` shows the real footprint.
    """
    import os as _os
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    src = Path(disk_image)
    total = partition_length_sectors * sector_size
    start_byte = partition_start_sector * sector_size
    chunk_size = 1024 * 1024  # 1 MB — small enough that an all-zero
                              # chunk is unlikely on real data
    zero_chunk = b"\x00" * chunk_size
    with src.open("rb") as fin, out_path.open("wb") as fout:
        fin.seek(start_byte)
        remaining = total
        while remaining > 0:
            buf = fin.read(min(chunk_size, remaining))
            if not buf:
                break
            # If the chunk is entirely zeros, skip writing it —
            # advance fout's position so the eventual truncate() sets
            # the right length. Linux + ext4/xfs honour the resulting
            # hole and only allocate blocks for non-zero data.
            if len(buf) == chunk_size and buf == zero_chunk:
                fout.seek(chunk_size, _os.SEEK_CUR)
            elif buf == b"\x00" * len(buf):
                fout.seek(len(buf), _os.SEEK_CUR)
            else:
                fout.write(buf)
            remaining -= len(buf)
        # truncate to declared partition length so refsprogs sees the
        # complete volume. The truncate also closes the final hole
        # when the last chunks were sparse-skipped.
        fout.truncate(total)
    return out_path


# ---------------------------------------------------------------------------
# refsinfo wrapper
# ---------------------------------------------------------------------------

def probe_volume(volume_path: Path, out_dir: Path,
                  timeout: int = 60) -> RefsVolumeInfo:
    """Run `refsinfo <volume>`, capture stdout, parse the key
    fields. Returns the dataclass even on rc != 0 — partial
    parses are useful diagnostics."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = _bin("refsinfo")
    stdout_path = out_dir / "refsinfo.stdout"
    stderr_path = out_dir / "refsinfo.stderr"
    cmd = [binary, str(volume_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise RefsprogsError(
            f"refsinfo timed out on {volume_path}") from e
    stdout_path.write_text(proc.stdout or "")
    stderr_path.write_text(proc.stderr or "")
    info = RefsVolumeInfo(rc=proc.returncode, raw_stdout_path=stdout_path)
    # Parse the stdout key-value-ish output
    for line in (proc.stdout or "").splitlines():
        s = line.strip()
        if s.startswith("ReFS version:"):
            info.refs_version = s.split(":", 1)[1].strip()
        elif s.startswith("Volume serial number:"):
            info.volume_serial = s.split(":", 1)[1].strip()
        elif s.startswith("Sector size:"):
            try:
                info.sector_size = int(s.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif s.startswith("Number of sectors:"):
            try:
                info.sector_count = int(s.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif s.startswith("Cluster size:"):
            try:
                info.cluster_size = int(s.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif s.startswith("Number of clusters:"):
            try:
                info.cluster_count = int(s.split(":", 1)[1].strip())
            except ValueError:
                pass
    # WARNING lines go to stdout (not stderr) in refsprogs
    info.warnings = [line for line in (proc.stdout or "").splitlines()
                      if line.startswith("[WARNING]")]
    return info


# ---------------------------------------------------------------------------
# refslabel wrapper
# ---------------------------------------------------------------------------

def read_label(volume_path: Path, timeout: int = 60) -> str:
    """Return the ReFS volume label (or empty string when absent /
    rc != 0)."""
    try:
        binary = _bin("refslabel")
    except RefsprogsError:
        return ""
    try:
        proc = subprocess.run([binary, str(volume_path)],
                                capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired:
        return ""
    if proc.returncode != 0:
        return ""
    # Skip [WARNING] lines, take the last non-empty line as the label
    for line in reversed((proc.stdout or "").splitlines()):
        s = line.strip()
        if s and not s.startswith("[WARNING]"):
            return s
    return ""


# ---------------------------------------------------------------------------
# refsls walker
# ---------------------------------------------------------------------------

_LL_RE_FIELDS = 6   # `refsls -l` produces: size attr date time name


def _parse_refsls_long(line: str) -> dict | None:
    """Parse one `refsls -l` line — `<size> <attrs> YYYY-MM-DD HH:MM <name>`.
    Returns None for non-data lines (warnings, headers, blank)."""
    s = line.rstrip()
    if not s or s.startswith("[WARNING]") or s.startswith("Listing"):
        return None
    parts = s.split(None, 4)
    if len(parts) < 5:
        return None
    size_str, attrs, date, time, name = parts
    try:
        size = int(size_str)
    except ValueError:
        return None
    return {
        "name": name,
        "size_bytes": size,
        "attrs": attrs,
        "mtime": f"{date} {time}",
    }


def walk(volume_path: Path, out_dir: Path, *,
         recursive: bool = True, show_hidden: bool = True,
         max_entries: int = 100_000,
         timeout: int = 1800) -> RefsListing:
    """Run `refsls -l [-R] [-a] <volume>`, capture + parse the
    listing. Returns a RefsListing dataclass.

    Truncation cap (`max_entries`) protects against pathological
    cases — refsprogs has no built-in cap and a fully-populated 50
    GB Dev Drive can produce millions of entries. We surface a
    truncation flag rather than silently dropping.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = _bin("refsls")
    flags = ["-l"]
    if recursive:
        flags.append("-R")
    if show_hidden:
        flags.append("-a")
    stdout_path = out_dir / "refsls.stdout"
    stderr_path = out_dir / "refsls.stderr"
    cmd = [binary, *flags, str(volume_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise RefsprogsError(
            f"refsls timed out on {volume_path}") from e
    stdout_path.write_text(proc.stdout or "")
    stderr_path.write_text(proc.stderr or "")
    listing = RefsListing(rc=proc.returncode, raw_stdout_path=stdout_path)
    entries: list[dict] = []
    truncated = False
    for line in (proc.stdout or "").splitlines():
        if line.startswith("[WARNING]"):
            listing.warnings.append(line)
            continue
        rec = _parse_refsls_long(line)
        if rec is None:
            continue
        entries.append(rec)
        if len(entries) >= max_entries:
            truncated = True
            break
    listing.entries = entries
    listing.truncated = truncated
    return listing


# ---------------------------------------------------------------------------
# refscat — read a single file's content
# ---------------------------------------------------------------------------

def cat_file(volume_path: Path, file_path: str, out_path: Path,
             *, timeout: int = 300, max_bytes: int = 100 * 1024 * 1024
             ) -> Path:
    """Write the named file's content from the ReFS volume to
    `out_path`. Caps at 100 MB to keep evidence-dir size predictable;
    re-invoke with `max_bytes=` for genuinely large files. Returns
    the on-disk path.

    Raises RefsprogsError on rc != 0 (file not found, corrupt block,
    or read past EOF)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    binary = _bin("refscat")
    cmd = [binary, "-p", file_path, str(volume_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RefsprogsError(
            f"refscat timed out reading {file_path}") from e
    if proc.returncode != 0:
        raise RefsprogsError(
            f"refscat failed (rc={proc.returncode}) for {file_path}: "
            f"{(proc.stderr or b'').decode(errors='ignore')[:200]}")
    data = proc.stdout or b""
    if len(data) > max_bytes:
        out_path.write_bytes(data[:max_bytes])
    else:
        out_path.write_bytes(data)
    return out_path


__all__ = [
    "RefsprogsError",
    "RefsVolumeInfo",
    "RefsListing",
    "is_refs_signature",
    "carve_partition",
    "probe_volume",
    "read_label",
    "walk",
    "cat_file",
]
