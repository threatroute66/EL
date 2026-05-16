"""Tests for el.skills.csv_time_window — mine (min, max) timestamp
from EZ Tools CSV outputs.

This helper backstops the windows_artifact agent: every "parsed
successfully" finding (RECmd, EvtxECmd, AmcacheParser, PECmd, MFTECmd)
used to fall back to EL ingest time on the kill-chain swimlane
because the agent didn't carry a real-world artifact time. With this
helper the agent now mines the CSV row timestamps and puts the
finding on the swimlane at the actual artifact window.

Pins:
  - Format-agnostic ISO-8601 timestamp regex
  - 1980-2100 year bound rejects bookend / overflow garbage
  - 50 MB / 200k-row caps for bounded memory
  - Sample-only mode for large files (head + tail 1 MB)
  - scan_files aggregates across multiple paths
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from el.skills.csv_time_window import scan_file, scan_files


def _utc(year, month, day, h=0, m=0, s=0, us=0):
    return datetime(year, month, day, h, m, s, us, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Real EZT output shapes — pinning the formats that show up in practice
# ---------------------------------------------------------------------------

def test_evtxecmd_shape_timecreated_column(tmp_path):
    """EvtxECmd CSV header line + 3 rows in the canonical EvtxECmd
    `TimeCreated` column shape: `2008-07-19 18:22:45.1234567`."""
    csv = tmp_path / "evtx.csv"
    csv.write_text(
        "RecordNumber,EventRecordId,TimeCreated,Provider,EventId,...\n"
        "1,1,2008-07-19 18:22:45.1234567,Microsoft-Windows-Eventlog,4624,...\n"
        "2,2,2008-07-20 03:11:02.0000000,Microsoft-Windows-Security,4634,...\n"
        "3,3,2008-07-22 09:55:30.0000000,Microsoft-Windows-Security,4624,...\n"
    )
    result = scan_file(csv)
    assert result is not None
    earliest, latest = result
    # EvtxECmd uses 7-digit fractional seconds (.1234567 truncates to 123456 us)
    assert earliest == _utc(2008, 7, 19, 18, 22, 45, 123456)
    assert latest == _utc(2008, 7, 22, 9, 55, 30)


def test_recmd_shape_lastwritetimestamp_column(tmp_path):
    """RECmd shape uses ISO-8601 with T separator and microseconds."""
    csv = tmp_path / "recmd.csv"
    csv.write_text(
        "HivePath,KeyPath,ValueName,LastWriteTimestamp\n"
        "SOFTWARE,Microsoft\\Windows\\Run,Loader,2008-07-20T01:22:45.123456\n"
        "SOFTWARE,Microsoft\\Windows\\Run,Update,2008-07-21T05:00:00.000000\n"
    )
    result = scan_file(csv)
    assert result is not None
    earliest, latest = result
    assert earliest == _utc(2008, 7, 20, 1, 22, 45, 123456)
    assert latest == _utc(2008, 7, 21, 5, 0, 0)


def test_amcacheparser_shape_with_z_suffix(tmp_path):
    """AmcacheParser uses `Z` suffix for UTC."""
    csv = tmp_path / "amcache.csv"
    csv.write_text(
        "FullPath,KeyLastWriteTimestamp\n"
        "C:\\evil.exe,2008-07-20T18:00:00Z\n"
        "C:\\good.exe,2008-07-22T12:00:00Z\n"
    )
    result = scan_file(csv)
    assert result is not None
    earliest, latest = result
    assert earliest == _utc(2008, 7, 20, 18, 0, 0)
    assert latest == _utc(2008, 7, 22, 12, 0, 0)


# ---------------------------------------------------------------------------
# Edges — empty / missing / no timestamps / oversize
# ---------------------------------------------------------------------------

def test_missing_file_returns_none(tmp_path):
    assert scan_file(tmp_path / "does_not_exist.csv") is None


def test_empty_file_returns_none(tmp_path):
    csv = tmp_path / "empty.csv"
    csv.write_text("")
    assert scan_file(csv) is None


def test_no_timestamps_returns_none(tmp_path):
    csv = tmp_path / "no_ts.csv"
    csv.write_text("header1,header2\nfoo,bar\nbaz,qux\n")
    assert scan_file(csv) is None


def test_year_below_1980_rejected(tmp_path):
    """Plaso bookend dates (1601-01-01 NTFS-epoch zero) and other
    sentinel timestamps must not pollute the window. The regex
    year bound is 1980-2100."""
    csv = tmp_path / "garbage.csv"
    csv.write_text(
        "ts\n"
        "1601-01-01 00:00:00\n"   # NTFS epoch — must reject
        "1969-12-31 23:59:59\n"   # Unix epoch boundary — must reject
        "2008-07-20 18:00:00\n"   # real
    )
    result = scan_file(csv)
    assert result is not None
    earliest, _latest = result
    assert earliest == _utc(2008, 7, 20, 18, 0, 0)


def test_year_above_2100_rejected(tmp_path):
    """Overflow / wraparound timestamps in corrupted rows."""
    csv = tmp_path / "future.csv"
    csv.write_text(
        "ts\n"
        "2106-02-07 06:28:15\n"   # Unix 32-bit signed wraparound
        "2008-07-20 18:00:00\n"
    )
    result = scan_file(csv)
    assert result is not None
    _earliest, latest = result
    assert latest == _utc(2008, 7, 20, 18, 0, 0)


# ---------------------------------------------------------------------------
# Caps — row cap + size cap
# ---------------------------------------------------------------------------

def test_row_cap_short_circuits(tmp_path):
    """When max_rows is small, the scan stops early. Timestamps
    past the cap aren't reflected in the window."""
    csv = tmp_path / "many.csv"
    lines = ["ts\n"]
    for i in range(100):
        lines.append(f"2008-07-{1 + (i % 28):02d} 12:00:00\n")
    lines.append("2099-12-31 23:59:59\n")  # past the cap
    csv.write_text("".join(lines))
    result = scan_file(csv, max_rows=5)
    assert result is not None
    _earliest, latest = result
    # Year 2099 must NOT show up since the row cap stopped early
    assert latest.year == 2008


def test_oversize_file_uses_head_tail_sampling(tmp_path):
    """When file exceeds max_bytes, helper switches to sampling
    mode: reads 1 MB from head and 1 MB from tail. The earliest
    timestamp in the head and the latest in the tail must still
    be captured."""
    csv = tmp_path / "huge.csv"
    # Construct: small head with early ts, lots of filler, small tail
    # with late ts. Force max_bytes well under file size.
    head = "ts\n2008-07-19 00:00:00\n"
    filler_line = "filler,row,with,no,timestamp,whatsoever\n"
    filler = filler_line * 5000
    tail = "2008-07-22 23:00:00\n"
    csv.write_text(head + filler + tail)
    # Cap so total > max_bytes
    result = scan_file(csv, max_bytes=len(head + filler + tail) // 2)
    assert result is not None
    earliest, latest = result
    assert earliest == _utc(2008, 7, 19)
    assert latest == _utc(2008, 7, 22, 23, 0, 0)


# ---------------------------------------------------------------------------
# scan_files — multi-file aggregation
# ---------------------------------------------------------------------------

def test_scan_files_aggregates_across_multiple(tmp_path):
    """RECmd batch mode produces multiple CSVs; aggregate window
    must span the union of per-file windows."""
    csv_a = tmp_path / "a.csv"
    csv_a.write_text("ts\n2008-07-19 12:00:00\n2008-07-20 12:00:00\n")
    csv_b = tmp_path / "b.csv"
    csv_b.write_text("ts\n2008-07-15 12:00:00\n2008-07-22 12:00:00\n")
    result = scan_files([csv_a, csv_b])
    assert result is not None
    earliest, latest = result
    assert earliest == _utc(2008, 7, 15, 12, 0, 0)
    assert latest == _utc(2008, 7, 22, 12, 0, 0)


def test_scan_files_skips_unreadable_paths(tmp_path):
    """Some EZT output_files entries are stderr / stdout siblings
    that have no timestamps. Helper must skip them silently."""
    real = tmp_path / "real.csv"
    real.write_text("ts\n2008-07-20 12:00:00\n")
    missing = tmp_path / "missing.csv"
    stderr = tmp_path / "tool.stderr"
    stderr.write_text("warnings: 0\nerrors: 0\n")
    result = scan_files([missing, stderr, real])
    assert result is not None
    earliest, latest = result
    assert earliest == _utc(2008, 7, 20, 12, 0, 0)
    assert latest == _utc(2008, 7, 20, 12, 0, 0)


def test_scan_files_empty_input_returns_none():
    assert scan_files([]) is None


def test_scan_files_all_none_returns_none(tmp_path):
    """When no file in the list yields a timestamp, the aggregate
    is None (not (None, None) — caller checks `is not None` to
    decide whether to add the facts)."""
    a = tmp_path / "a.csv"
    a.write_text("no ts here\n")
    b = tmp_path / "b.csv"
    b.write_text("nothing here either\n")
    assert scan_files([a, b]) is None
