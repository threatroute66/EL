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
    _decode_utf16_buffer,
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
# _decode_utf16_buffer — TimeZoneKeyName regipy-overrun fix
# ---------------------------------------------------------------------------

def test_utf16_decode_simple_utc_buffer():
    """Vista+ TimeZoneKeyName comes back as a 128-byte buffer
    holding UTF-16LE "UTC" + null + uninitialised hive memory.
    Decoder must truncate at the first null."""
    raw = b"U\x00T\x00C\x00\x00\x00" + b"\xda\xff" * 60  # garbage after null
    assert _decode_utf16_buffer(raw) == "UTC"


def test_utf16_decode_eastern_standard_time():
    """Common workstation TZ — string + null + garbage padding."""
    raw = ("Eastern Standard Time".encode("utf-16-le")
           + b"\x00\x00" + b"\xff" * 80)
    assert _decode_utf16_buffer(raw) == "Eastern Standard Time"


def test_utf16_decode_already_string_passes_through():
    """XP-era StandardName arrives as a clean str — decoder must
    not mangle it. Still trim NULs in case regipy hands one back."""
    assert _decode_utf16_buffer("GMT Standard Time") == "GMT Standard Time"
    assert _decode_utf16_buffer("UTC\x00garbage") == "UTC"


def test_utf16_decode_empty_or_none():
    """Missing values shouldn't crash — return empty string so
    `have_anything` checks evaluate correctly."""
    assert _decode_utf16_buffer(None) == ""
    assert _decode_utf16_buffer(b"") == ""
    assert _decode_utf16_buffer("") == ""


def test_utf16_decode_bare_null_buffer():
    """Buffer is just nulls (uninitialised) → empty string."""
    assert _decode_utf16_buffer(b"\x00" * 128) == ""


# ---------------------------------------------------------------------------
# tz_display_name — prefer TimeZoneKeyName over MUI-indirected name
# ---------------------------------------------------------------------------

def test_display_name_prefers_tz_key_name_on_vista_plus():
    """Vista+ shape: StandardName is the unhelpful MUI ref;
    TimeZoneKeyName is the canonical identifier. Display wins on
    TimeZoneKeyName so the analyst sees 'Eastern Standard Time'
    instead of '@tzres.dll,-112'."""
    tb = TimeBaseline(tz_standard_name="@tzres.dll,-112",
                      tz_key_name="Eastern Standard Time")
    assert tb.tz_display_name == "Eastern Standard Time"


def test_display_name_falls_back_to_standard_name_on_xp():
    """XP-era hives don't have TimeZoneKeyName — StandardName IS
    the readable name. Display name falls back gracefully."""
    tb = TimeBaseline(tz_standard_name="GMT Standard Time",
                      tz_key_name="")
    assert tb.tz_display_name == "GMT Standard Time"


def test_display_name_surfaces_mui_ref_when_nothing_better():
    """Worst case — Vista+ TimeZoneKeyName absent, StandardName
    is MUI ref. Surface the raw MUI ref so the analyst at least
    sees something concrete instead of blank."""
    tb = TimeBaseline(tz_standard_name="@tzres.dll,-932",
                      tz_key_name="")
    assert tb.tz_display_name == "@tzres.dll,-932"


def test_display_name_unknown_placeholder_when_all_empty():
    tb = TimeBaseline()
    assert tb.tz_display_name == "(unknown)"


def test_have_anything_true_with_tz_key_name_alone():
    """A hive with TimeZoneKeyName but no StandardName (rare but
    possible on stripped-down Server Core builds) still counts
    as "we have something" — emit the high-confidence finding."""
    tb = TimeBaseline(tz_key_name="UTC")
    assert tb.have_anything is True


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
    # XP-era hive: TimeZoneKeyName absent → display falls back to
    # StandardName cleanly.
    assert tb.tz_display_name == "GMT Standard Time"
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


# ---------------------------------------------------------------------------
# ComputerName extraction (host identity for the Diamond Victim-Asset)
# ---------------------------------------------------------------------------

def test_timebaseline_computer_name_field_defaults_empty():
    """The new field defaults to '' so cases without a readable
    SYSTEM hive (or pre-existing sealed cases re-rendered) don't
    crash or fabricate a host name."""
    tb = TimeBaseline()
    assert tb.computer_name == ""


def test_parse_system_hive_reads_computer_name_real_hive():
    """Integration: against a real extracted SYSTEM hive, the
    persistent NetBIOS ComputerName must round-trip. Uses an SRL /
    rocba extracted hive when present; skips when no real hive is
    available on this host (CI without case data)."""
    from pathlib import Path
    candidates = [
        "/opt/EL/cases/srl-2018/devices/dc/exports/windows-artifacts/registry/SYSTEM",
    ]
    # Also accept any extracted SYSTEM hive under cases/
    import glob
    candidates += glob.glob(
        "/opt/EL/cases/**/windows-artifacts/registry/SYSTEM",
        recursive=True)
    hive = next((Path(c) for c in candidates if Path(c).is_file()), None)
    if hive is None:
        pytest.skip("no extracted SYSTEM hive available")
    tb = parse_system_hive(hive)
    # ComputerName must be a non-empty alnum/hyphen NetBIOS-shaped name
    assert tb.computer_name, "ComputerName should parse from a real hive"
    assert all(c.isalnum() or c in "-_" for c in tb.computer_name), \
        f"unexpected ComputerName shape: {tb.computer_name!r}"
