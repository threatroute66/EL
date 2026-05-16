"""Mine a (min, max) timestamp window from a CSV / TSV output file.

EZ Tools parsers (EvtxECmd, RECmd, AmcacheParser, PECmd, MFTECmd)
produce per-row timestamps in their CSV output. The
WindowsArtifactAgent's "parsed successfully" findings cite the
output files in extracted_facts but don't surface any time data
— so on the kill-chain swimlane those findings fall back to EL
ingest time even though the parsed CSV literally contains the
artifact's real time range.

This helper walks a file's rows looking for ISO-8601-shaped
timestamp values, returns (earliest, latest) as datetime objects.
Format-agnostic — works on EvtxECmd's TimeCreated, RECmd's
LastWriteTimestamp, AmcacheParser's KeyLastWriteTimestamp,
PECmd's LastRun, MFTECmd's per-attribute timestamps. Whichever
column has timestamps, scan_file finds them.

Capped at 50 MB / 200k rows per file by default so a 5 GB
EvtxECmd output doesn't OOM the agent — for the common case the
first row + last row + a few in the middle give a reliable
window already.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


# ISO-8601 + EZ-Tools-flavored timestamps. Covers:
#   2008-07-20T01:22:45
#   2008-07-20T01:22:45.123Z
#   2008-07-20T01:22:45+00:00
#   2008-07-20 01:22:45  (T → space, common EZ output)
#   2008-07-20 01:22:45.123456  (sub-second)
# Does NOT match year-zero / future-2106 garbage — bounded to
# 1980-2100 via the year prefix so Plaso-bookend overflow values
# don't pollute the window.
_TS_RE = re.compile(
    r"\b(?:19[89]\d|20\d{2})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"[T ](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?"
)


def _parse(ts_str: str) -> datetime | None:
    """Lenient parser — handles the variants the regex captures.
    Naive datetimes are assumed UTC per EL's all-UTC charter."""
    s = ts_str.strip().replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def scan_file(
    path: Path,
    max_bytes: int = 5 * 1024 * 1024,
    max_rows: int = 10_000,
    sample_bytes: int = 256 * 1024,
) -> tuple[datetime, datetime] | None:
    """Return (min_dt, max_dt) for the timestamps found in `path`,
    or None when no timestamps are present / file unreadable.

    Reads line-by-line so the memory footprint is bounded to one
    row at a time. Caps default to 10k rows / 5 MB whole-scan; past
    that we switch to head+tail 256 KB sampling to keep this helper
    well under a second per file even when the agent throws dozens
    of large EZT CSV outputs at it. A coordinator end-to-end test
    burned 4+ minutes here at the original 200k/50MB caps before
    the tightening.
    """
    try:
        st = path.stat()
    except OSError:
        return None
    if st.st_size == 0:
        return None
    if st.st_size > max_bytes:
        # Sample-only mode: read just the first and last sample_bytes.
        # Both ends cover the time window edges for an append-ordered
        # CSV (almost all EZT outputs). For time-unsorted outputs the
        # min/max may underestimate the true range but still beats
        # falling back to EL ingest time entirely.
        try:
            with path.open("rb") as fh:
                head = fh.read(sample_bytes).decode("utf-8", errors="ignore")
                fh.seek(max(0, st.st_size - sample_bytes))
                tail = fh.read(sample_bytes).decode("utf-8", errors="ignore")
            text = head + "\n" + tail
        except OSError:
            return None
        return _scan_text(text)

    # Whole-file scan with row cap.
    earliest: datetime | None = None
    latest: datetime | None = None
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i >= max_rows:
                    break
                for m in _TS_RE.finditer(line):
                    dt = _parse(m.group(0))
                    if dt is None:
                        continue
                    if earliest is None or dt < earliest:
                        earliest = dt
                    if latest is None or dt > latest:
                        latest = dt
    except OSError:
        return None
    if earliest is None:
        return None
    return earliest, latest


def _scan_text(text: str) -> tuple[datetime, datetime] | None:
    earliest: datetime | None = None
    latest: datetime | None = None
    for m in _TS_RE.finditer(text):
        dt = _parse(m.group(0))
        if dt is None:
            continue
        if earliest is None or dt < earliest:
            earliest = dt
        if latest is None or dt > latest:
            latest = dt
    if earliest is None:
        return None
    return earliest, latest


_TEXT_SUFFIXES = {".csv", ".tsv", ".txt", ".json", ".jsonl",
                  ".xml", ".log", ".stdout"}


def scan_files(paths: Iterable[Path]) -> tuple[datetime, datetime] | None:
    """Aggregate min/max across multiple files. Useful when an EZT
    parser writes more than one CSV (RECmd batch output, MFTECmd
    plus per-record summaries) — analyst wants one window covering
    the whole parser run.

    Only text-shaped extensions are scanned — passing a binary blob
    (raw hive copy, $MFT dump, .dat file) through a line-by-line
    UTF-8 decode + regex match is extremely expensive on large
    files and produces no usable matches anyway.
    """
    earliest: datetime | None = None
    latest: datetime | None = None
    # Aggregate cap: 16 MB total across all files, so a parser that
    # emits 50 medium CSVs doesn't blow the per-call budget. Once
    # the budget is spent we fall back to head+tail sampling for
    # the remaining files so we still see _something_ from each.
    bytes_remaining = 16 * 1024 * 1024
    for p in paths:
        if p.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if bytes_remaining > 0:
            result = scan_file(p)
            bytes_remaining -= size
        else:
            # Budget spent — sampling mode only
            result = scan_file(p, max_bytes=0)
        if result is None:
            continue
        e, l = result
        if earliest is None or e < earliest:
            earliest = e
        if latest is None or l > latest:
            latest = l
    if earliest is None:
        return None
    return earliest, latest


__all__ = ["scan_file", "scan_files"]
