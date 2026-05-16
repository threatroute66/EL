"""Tests for el.skills.time_baseline — read TimeZoneInformation +
W32Time config from a SYSTEM hive.

Two unit-level pins:
  - signed-DWORD folding for the *Bias values (Windows stores them as
    unsigned 32-bit but they're signed in semantics; -60 looks like
    4294967236 on the wire)
  - FILETIME → ISO-8601 decode for the W32Time\\Config last-write time

Integration tested against the real M57-Jean SYSTEM hive when
available (covers parse_system_hive's ControlSet resolution +
regipy plumbing end-to-end).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.skills.time_baseline import (
    TimeBaseline,
    _dword_as_signed_minutes,
    _filetime_to_iso,
    parse_system_hive,
)


# ---------------------------------------------------------------------------
# _dword_as_signed_minutes — folds Windows' unsigned-DWORD-of-signed-int
# ---------------------------------------------------------------------------

def test_dword_signed_positive_pst_offset():
    """Pacific Standard Time stores Bias = 480 (PST is 8h behind UTC,
    positive in Windows' confusing convention). Helper passes through."""
    assert _dword_as_signed_minutes(480) == 480


def test_dword_signed_zero_gmt():
    """GMT — Bias = 0."""
    assert _dword_as_signed_minutes(0) == 0


def test_dword_signed_negative_dst_active():
    """M57-Jean's M57: ActiveTimeBias = 4294967236 → -60 (BST,
    one hour ahead of UTC during summer)."""
    assert _dword_as_signed_minutes(4294967236) == -60


def test_dword_signed_jst_negative():
    """Japan Standard Time = UTC+9 → Bias stored as -540."""
    assert _dword_as_signed_minutes(0xFFFFFDE4) == -540


def test_dword_signed_none_passes_through():
    """Missing values return None — caller decides whether to
    surface an insufficient finding or stay silent."""
    assert _dword_as_signed_minutes(None) is None


# ---------------------------------------------------------------------------
# _filetime_to_iso — Windows FILETIME → ISO-8601 UTC
# ---------------------------------------------------------------------------

def test_filetime_decodes_2008_m57_w32time_config():
    """The W32Time\\Config last-write on M57-Jean was 128552217573593750
    (100-ns ticks since 1601-01-01 UTC) — should decode to a 2008
    May 14 datetime."""
    iso = _filetime_to_iso(128552217573593750)
    assert iso.startswith("2008-05-14T06:55:57")
    # Must carry tz suffix (renderer relies on naive vs aware in
    # evidence_time path)
    dt = datetime.fromisoformat(iso)
    assert dt.tzinfo == timezone.utc


def test_filetime_zero_returns_empty():
    """Some W32Time hives have key-without-LastWrite — protect
    against the 1601 epoch sentinel landing on the swimlane."""
    assert _filetime_to_iso(0) == ""


def test_filetime_negative_returns_empty():
    """Defensive — sometimes corrupted hives produce sentinel -1."""
    assert _filetime_to_iso(-1) == ""


def test_filetime_overflow_returns_empty():
    """Year > 9999 from a wildly large value would raise
    OverflowError in datetime — the helper catches it."""
    assert _filetime_to_iso(10**20) == ""


# ---------------------------------------------------------------------------
# TimeBaseline.sync_state_label — analyst-readable summary
# ---------------------------------------------------------------------------

def test_sync_state_ntp():
    tb = TimeBaseline(w32time_type="NTP",
                      w32time_ntp_server="time.windows.com,0x1")
    assert "NTP-synced" in tb.sync_state_label
    assert "time.windows.com" in tb.sync_state_label


def test_sync_state_domain():
    tb = TimeBaseline(w32time_type="NT5DS")
    assert "domain-time-sync" in tb.sync_state_label


def test_sync_state_nosync_is_drift_warning():
    """NoSync = orphan clock; drift accumulates. Forensically
    important — analyst can't trust timestamps as wall-clock."""
    tb = TimeBaseline(w32time_type="NoSync")
    assert "drift accumulates" in tb.sync_state_label


def test_sync_state_unknown_when_blank():
    tb = TimeBaseline()
    label = tb.sync_state_label.lower()
    assert "unknown" in label
    # `absent` is the placeholder for `(self.w32time_type or 'absent')`
    assert "absent" in label or "<absent>" in label


# ---------------------------------------------------------------------------
# have_anything — boolean used by the agent to decide insufficient
# ---------------------------------------------------------------------------

def test_have_anything_false_on_empty():
    assert TimeBaseline().have_anything is False


def test_have_anything_true_with_tz_only():
    tb = TimeBaseline(tz_standard_name="GMT Standard Time")
    assert tb.have_anything is True


def test_have_anything_true_with_w32time_only():
    tb = TimeBaseline(w32time_type="NTP")
    assert tb.have_anything is True


# ---------------------------------------------------------------------------
# Integration — real M57 SYSTEM hive (skip if not present)
# ---------------------------------------------------------------------------

_M57_HIVE = Path(
    "/opt/EL/cases/m57-jean-judges-r6/exports/"
    "windows-artifacts/registry/SYSTEM")


@pytest.mark.skipif(not _M57_HIVE.exists(),
                     reason="M57 SYSTEM hive not present on this host")
def test_parse_real_m57_system_hive_extracts_gmt_baseline():
    """End-to-end: ControlSet resolution via \\Select, TZ key read,
    W32Time key read, FILETIME decode. Pins the M57-Jean baseline
    so a regipy upgrade or schema rename gets caught immediately."""
    tb = parse_system_hive(_M57_HIVE)
    assert tb.have_anything
    assert tb.control_set == "ControlSet001"
    assert tb.tz_standard_name == "GMT Standard Time"
    assert tb.tz_daylight_name == "GMT Daylight Time"
    assert tb.tz_bias_minutes == 0       # GMT base offset
    # BST is active in M57's last-write window (registry written in
    # summer 2008) — ActiveTimeBias = -60 means UTC+1
    assert tb.tz_active_bias_minutes == -60
    assert tb.w32time_type == "NTP"
    assert "time.windows.com" in tb.w32time_ntp_server
    # W32Time Config last-write was May 2008 — well before the
    # July 2008 incident, so the sync state is unchanged through
    # the incident window
    assert tb.w32time_config_last_write_utc.startswith("2008-05-")


# ---------------------------------------------------------------------------
# parse_system_hive defensive
# ---------------------------------------------------------------------------

def test_parse_missing_path_returns_empty(tmp_path):
    """Hive file doesn't exist — return empty baseline, never raise."""
    tb = parse_system_hive(tmp_path / "does_not_exist")
    assert not tb.have_anything
    assert "not found" in (" ".join(tb.notes)).lower()


def test_parse_garbage_file_returns_empty(tmp_path):
    """regipy raises on non-hive data — caller catches, returns
    a TimeBaseline with notes explaining the failure."""
    p = tmp_path / "fake.hive"
    p.write_bytes(b"\x00" * 16)
    tb = parse_system_hive(p)
    assert not tb.have_anything
    assert tb.notes  # carries a diagnostic
