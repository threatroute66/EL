"""Tests for el.skills.ewf_skew — parse Acquisition vs System dates
from `ewfinfo` stdout and compute the acquirer-vs-target clock delta.

The delta is the first calibration value DFIR analysts need — every
FAT / EXIF / Office-metadata local-time value in the case has to be
read against the target's clock state at acquisition time.

Both timestamps in the ewfinfo stdout are emitted by libewf in the
acquirer's local TZ with no TZ tag. So individually neither is
UTC-anchored, but their *delta* is TZ-independent (same TZ on both
sides, the subtraction cancels). The parser must:
  - parse both `Acquisition date` and `System date` lines
  - tolerate libewf's double-space-padded day-of-month
  - return None timestamps + None skew on malformed/missing input
  - never raise on garbage input
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from el.skills.ewf_skew import EwfSkew, parse, parse_file


# ---------------------------------------------------------------------------
# Real-world stdout shapes
# ---------------------------------------------------------------------------

M57_EWFINFO = """\
ewfinfo 20140816

Acquiry information
\tDescription:\t\tJean's hard drive from the first M57 project
\tExaminer name:\t\tDonny
\tEvidence number:\t2008-M57-Jean
\tAcquisition date:\tMon Jan 31 21:38:29 2011
\tSystem date:\t\tMon Jan 31 21:38:29 2011
\tOperating system used:\tDarwin
\tSoftware version used:\t20101104
\tPassword:\t\tN/A

EWF information
\tFile format:\t\tEnCase 6
"""


def test_m57_zero_skew():
    """M57-Jean: Donny acquired with `acquisition date == system date`
    (acquirer's clock equalled target RTC) — zero skew."""
    s = parse(M57_EWFINFO)
    assert s.skew_seconds == 0
    assert s.acquisition_dt == datetime(2011, 1, 31, 21, 38, 29)
    assert s.system_dt == datetime(2011, 1, 31, 21, 38, 29)
    assert s.have_skew


def test_target_clock_behind_acquirer_by_37_minutes():
    """Common shape — target machine's RTC has drifted behind
    UTC-synced examiner reference. Skew = (acq - sys) > 0."""
    sample = """\
Acquiry information
\tAcquisition date:\tMon Jul 20 14:00:00 2008
\tSystem date:\t\tMon Jul 20 13:23:00 2008
"""
    s = parse(sample)
    assert s.skew_seconds == 37 * 60   # +2220 = target 37 min behind
    assert s.have_skew


def test_target_clock_ahead_of_acquirer():
    """Less common — target clock is ahead of examiner reference.
    Skew < 0 by the parser's convention."""
    sample = """\
Acquiry information
\tAcquisition date:\tMon Jul 20 13:00:00 2008
\tSystem date:\t\tMon Jul 20 14:30:00 2008
"""
    s = parse(sample)
    assert s.skew_seconds == -90 * 60  # negative = target ahead


def test_double_padded_day_of_month_parses():
    """libewf prints `%a %b %e %H:%M:%S %Y` which space-pads single-
    digit days (`Jan  1` not `Jan 01`). Parser must collapse the
    extra space before strptime."""
    sample = """\
Acquiry information
\tAcquisition date:\tMon Jan  1 00:00:00 2024
\tSystem date:\t\tMon Jan  1 00:00:00 2024
"""
    s = parse(sample)
    assert s.acquisition_dt == datetime(2024, 1, 1)
    assert s.skew_seconds == 0


# ---------------------------------------------------------------------------
# Negative / defensive cases
# ---------------------------------------------------------------------------

def test_missing_acquisition_date_returns_none_skew():
    """Some old libewf / EWF-S01 images lack the Acquisition date
    header. Skew is None — caller emits insufficient finding."""
    sample = """\
Acquiry information
\tSystem date:\t\tMon Jul 20 14:00:00 2008
"""
    s = parse(sample)
    assert s.acquisition_dt is None
    assert s.system_dt is not None
    assert s.skew_seconds is None
    assert not s.have_skew


def test_missing_system_date_returns_none_skew():
    sample = """\
Acquiry information
\tAcquisition date:\tMon Jul 20 14:00:00 2008
"""
    s = parse(sample)
    assert s.system_dt is None
    assert s.skew_seconds is None


def test_garbage_date_value_returns_none_for_that_field():
    """When libewf emits a date but the format is malformed (rare,
    seen on cross-platform copies that mangle line endings)."""
    sample = """\
Acquiry information
\tAcquisition date:\tnot-a-date-at-all
\tSystem date:\t\tMon Jul 20 14:00:00 2008
"""
    s = parse(sample)
    assert s.acquisition_dt is None
    assert s.system_dt == datetime(2008, 7, 20, 14, 0, 0)
    assert s.skew_seconds is None


def test_empty_input_returns_empty_skew():
    s = parse("")
    assert s.acquisition_date_raw == ""
    assert s.system_date_raw == ""
    assert s.skew_seconds is None


def test_binary_garbage_does_not_raise():
    """Defensive — the wrapper occasionally hands us stderr-merged
    output from a borked tool. Must not crash the agent."""
    s = parse("\x00\x01\x02\x03 binary noise " * 100)
    assert s.skew_seconds is None


def test_first_occurrence_of_each_field_wins():
    """Some libewf builds emit Acquisition date twice (once in the
    EnCase header, once in the EWF segment table). Parser pins to
    the first occurrence so a 2nd value can't silently shift the
    skew computation."""
    sample = """\
Acquiry information
\tAcquisition date:\tMon Jul 20 14:00:00 2008
\tSystem date:\t\tMon Jul 20 14:00:00 2008
\tAcquisition date:\tTue Jul 21 00:00:00 2008
"""
    s = parse(sample)
    assert s.acquisition_dt == datetime(2008, 7, 20, 14, 0, 0)
    assert s.skew_seconds == 0


# ---------------------------------------------------------------------------
# parse_file convenience wrapper
# ---------------------------------------------------------------------------

def test_parse_file_reads_real_stdout(tmp_path):
    p = tmp_path / "ewfinfo.stdout"
    p.write_text(M57_EWFINFO)
    s = parse_file(p)
    assert s.skew_seconds == 0


def test_parse_file_missing_path_returns_empty(tmp_path):
    """Caller may pass a path that wasn't written (ewfinfo failed
    upstream). Helper returns empty skew, never raises."""
    s = parse_file(tmp_path / "does_not_exist.stdout")
    assert s.skew_seconds is None
    assert s.acquisition_dt is None
