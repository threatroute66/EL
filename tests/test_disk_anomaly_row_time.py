"""Tests for the disk_anomaly._row_time_at + scan_text mtime mining.

The path-pattern scanner used to leave earliest_unix / latest_unix
None on every hit (only the row-wise SYSTEM_BINARY_ZERO_* detectors
populated them). On M57-Jean that meant 12 disk_forensicator anomaly
findings (SVCHOST_OUTSIDE_SYSTEM32, EXE_IN_TEMP, SCHEDULED_TASK_NONMS)
fell back to EL ingest time on the kill-chain swimlane — 18 years
late relative to the 2008-era artifact times that were literally in
the bodyfile row each pattern matched on.

Pins:
  - _row_time_at extracts the earliest non-zero column (preferring
    mtime, then ctime, then crtime, then atime)
  - scan_text propagates min/max across multiple matches into the
    PathHit's earliest_unix/latest_unix
  - graceful on non-bodyfile rows + all-zero rows
"""
from __future__ import annotations

from el.skills.disk_anomaly import PATTERNS, _row_time_at, scan_text


# ---------------------------------------------------------------------------
# _row_time_at — single-row mining
# ---------------------------------------------------------------------------

def test_row_time_at_extracts_mtime():
    """Real bodyfile row — `0|name|inode|mode|uid|gid|size|atime|mtime|
    ctime|crtime`. mtime is column 8 (0-indexed). 1209600000 =
    2008-04-30T20:00:00Z, well before the SUS year we care about."""
    line = "0|/Windows/System32/dllhost/svchost.exe|123|r/r|0|0|1024|1216000000|1216000100|1216000050|1216000000"
    text = "header\n" + line + "\nfooter"
    pos = text.index("dllhost")
    assert _row_time_at(text, pos) == 1216000000  # earliest of the four


def test_row_time_at_prefers_non_zero_columns():
    """When mtime is zero but ctime / crtime carry real values
    (SYSTEM_BINARY_ZERO_TIMESTAMPS shape — attacker zeroed the
    primary timestamps, NTFS sometimes preserves ctime), the
    helper picks the earliest non-zero column."""
    line = "0|/Windows/System32/wiped.dll|456|r/r|0|0|0|0|0|1500000000|0"
    pos = line.index("wiped")
    assert _row_time_at(line, pos) == 1500000000  # ctime is only non-zero


def test_row_time_at_returns_none_on_non_bodyfile_row():
    """Garbage / header rows / malformed lines must return None
    so callers don't pretend a timestamp exists when it doesn't."""
    assert _row_time_at("not a bodyfile row", 0) is None
    assert _row_time_at("only|five|fields|here|nope", 0) is None
    assert _row_time_at("", 0) is None


def test_row_time_at_returns_none_when_all_columns_zero():
    """SYSTEM_BINARY_ZERO_TIMESTAMPS row — attacker wiped all
    four MAC columns. No artifact time available; return None."""
    line = "0|/Windows/System32/wiped.exe|789|r/r|0|0|1024|0|0|0|0"
    assert _row_time_at(line, line.index("wiped")) is None


def test_row_time_at_handles_missing_columns_in_row():
    """Some fls outputs end the row with deleted-tag annotations
    that throw extra pipes; rows with fewer than 11 columns
    return None rather than crashing."""
    line = "short|row|3|cols"
    assert _row_time_at(line, 0) is None


def test_row_time_at_walks_to_line_boundary():
    """`pos` can land anywhere within the line — the helper finds
    the surrounding line, not just the substring at `pos`."""
    line = "0|/path/to/file|1|r/r|0|0|2048|1100000000|1100000050|1100000025|1100000000"
    text = "prelude\n" + line + "\npost"
    # pos points at the trailing crtime field
    pos = text.rindex("1100000000")
    assert _row_time_at(text, pos) == 1100000000


# ---------------------------------------------------------------------------
# scan_text — pattern hit propagates mtime into PathHit
# ---------------------------------------------------------------------------

def test_scan_text_path_pattern_now_carries_earliest_unix():
    """The exact M57-Jean shape — SCHEDULED_TASK_NONMS pattern fires
    on `Windows/Tasks/At1.job` rows that have real mtime data. The
    hit's earliest_unix must equal the smallest mtime across all
    matching lines."""
    text = (
        "0|/Windows/Tasks/At1.job|537|r/rrwxrwxrwx|0|0|364|0|1333561535|1333561535|0\n"
        "0|/Windows/Tasks/At2.job|537|r/rrwxrwxrwx|0|0|36|0|1333645134|1333645134|0\n"
    )
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    h = by_id["SCHEDULED_TASK_NONMS"]
    assert h.earliest_unix == 1333561535
    assert h.latest_unix == 1333645134


def test_scan_text_svchost_outside_system32_carries_mtime():
    """Same regression for the SVCHOST_OUTSIDE_SYSTEM32 detector —
    the masquerade pattern most M57-Jean / SRL cases use to plant
    a malicious svchost. The matched row's mtime is the most
    forensically valuable single piece of context (it's when the
    attacker dropped the file)."""
    text = (
        "0|/Windows/System32/dllhost/svchost.exe|60768|r/r|0|0|0|0|1216001000|0|0\n"
    )
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    h = by_id["SVCHOST_OUTSIDE_SYSTEM32"]
    assert h.earliest_unix == 1216001000
    assert h.latest_unix == 1216001000


def test_scan_text_skips_time_on_non_bodyfile_match():
    """When the pattern matches text that isn't pipe-delimited
    bodyfile content (e.g. an EZ Tools CSV header that happens to
    contain `mimikatz`), the helper returns None and the PathHit's
    earliest_unix stays None — no fake timestamp."""
    text = "search-results.csv: mimikatz.exe was found in catalog\n"
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    if "MIMIKATZ_NAMED_BINARY" in by_id:
        # Pattern fired but no bodyfile timestamp available
        assert by_id["MIMIKATZ_NAMED_BINARY"].earliest_unix is None


def test_scan_text_existing_rowwise_detectors_still_carry_mtime():
    """SYSTEM_BINARY_ZERO_SIZE has always had earliest_unix via the
    row-wise detector path. Make sure the new path-pattern mtime
    extraction doesn't accidentally shadow / clobber it."""
    text = (
        "0|/Windows/System32/wiped.dll|1|r/r|0|0|0|0|1200000000|0|0\n"
    )
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    assert "SYSTEM_BINARY_ZERO_SIZE" in by_id
    assert by_id["SYSTEM_BINARY_ZERO_SIZE"].earliest_unix == 1200000000


# ---------------------------------------------------------------------------
# Row-wise SYSTEM_BINARY_ZERO_SIZE: fallback to ctime / crtime when mtime
# has been wiped (anti-forensic timestamping the attacker only got to the
# primary mtime column, NTFS preserved the secondary columns)
# ---------------------------------------------------------------------------

def test_zero_size_falls_back_to_ctime_when_mtime_wiped():
    """Wiped mtime, intact ctime — the row-wise detector must record
    ctime as the artifact time so the SYSTEM_BINARY_ZERO_SIZE finding
    still lands on the swimlane near the real drop event."""
    text = (
        "0|/Windows/System32/wiped.dll|1|r/r|0|0|0|0|0|1216001000|0\n"
    )
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    assert "SYSTEM_BINARY_ZERO_SIZE" in by_id
    assert by_id["SYSTEM_BINARY_ZERO_SIZE"].earliest_unix == 1216001000


def test_zero_size_falls_back_to_crtime_when_mtime_and_ctime_wiped():
    """Worst-case: attacker zeroed both mtime AND ctime. crtime (the
    NTFS create timestamp) is harder to alter because it lives in
    $STANDARD_INFORMATION + $FILE_NAME. Falling back to it is the
    last resort but still better than dropping the finding off the
    timeline."""
    text = (
        "0|/Windows/System32/zeroed.dll|1|r/r|0|0|0|0|0|0|1216002000\n"
    )
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    assert "SYSTEM_BINARY_ZERO_SIZE" in by_id
    assert by_id["SYSTEM_BINARY_ZERO_SIZE"].earliest_unix == 1216002000


def test_zero_size_prefers_mtime_when_present():
    """When mtime IS non-zero, the detector keeps using it — the
    fallback only activates when mtime == 0. Pin the precedence."""
    text = (
        "0|/Windows/System32/normal.dll|1|r/r|0|0|0|0|1216000500|1216001000|1216002000\n"
    )
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    assert by_id["SYSTEM_BINARY_ZERO_SIZE"].earliest_unix == 1216000500


def test_zero_size_no_time_when_all_columns_wiped():
    """All four columns zeroed — true SYSTEM_BINARY_ZERO_TIMESTAMPS
    shape. earliest_unix stays None; we don't fabricate a time."""
    text = (
        "0|/Windows/System32/wiped.dll|1|r/r|0|0|0|0|0|0|0\n"
    )
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    if "SYSTEM_BINARY_ZERO_SIZE" in by_id:
        assert by_id["SYSTEM_BINARY_ZERO_SIZE"].earliest_unix is None
