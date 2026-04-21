"""Tier-2 #1: BAM/DAM (SYSTEM hive) + Windows Timeline (ActivitiesCache.db)
parser tests.

BAM tests exercise the FILETIME decode + summarisation against a
synthetic hex payload so they don't need a real hive. ActivitiesCache
tests build a synthetic SQLite DB matching the real schema's columns
the skill reads. Agent wiring test bundles both into a fake
windows_artifact exports tree.
"""
import sqlite3
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.skills import bam_dam, win_timeline as wt


# ---------------------------------------------------------------------------
# BAM FILETIME decoder + summary
# ---------------------------------------------------------------------------

def _make_filetime(dt: datetime) -> bytes:
    """Build the 8-byte little-endian FILETIME (100-ns ticks since 1601
    UTC) that BAM stores as the first 8 bytes of its REG_BINARY."""
    delta = dt.replace(tzinfo=timezone.utc) \
            - datetime(1601, 1, 1, tzinfo=timezone.utc)
    ticks = int(delta.total_seconds() * 10_000_000)
    return struct.pack("<Q", ticks)


def test_filetime_decoder_round_trips_from_hex_string():
    dt = datetime(2024, 3, 15, 14, 30, 45, tzinfo=timezone.utc)
    # regipy hands us REG_BINARY as a hex string
    hex_value = _make_filetime(dt).hex() + "0000000000000000"
    iso = bam_dam._filetime_to_iso(hex_value)
    # Allow microsecond rounding
    recovered = datetime.fromisoformat(iso)
    assert abs((recovered - dt).total_seconds()) < 1.0


def test_filetime_decoder_accepts_bytes():
    dt = datetime(2022, 1, 1, tzinfo=timezone.utc)
    iso = bam_dam._filetime_to_iso(_make_filetime(dt))
    assert iso.startswith("2022-01-01")


def test_filetime_decoder_rejects_short_buffers():
    assert bam_dam._filetime_to_iso(b"\x00\x01") == ""
    assert bam_dam._filetime_to_iso("") == ""
    assert bam_dam._filetime_to_iso("not-hex") == ""


def test_filetime_decoder_zero_filetime_returns_empty():
    assert bam_dam._filetime_to_iso(b"\x00" * 8) == ""


def test_is_suspicious_path_matches_user_writable_markers():
    # BAM records Windows paths verbatim — backslashes only. No
    # forward-slash form to worry about at this layer (unlike the
    # more general execution_corroboration heuristic, which sees
    # SIGMA-style rule inputs).
    for p in (
        r"\Device\HarddiskVolume4\Users\alice\AppData\Local\Temp\x.exe",
        r"C:\ProgramData\Evil\z.exe",
        r"C:\Users\Public\Downloads\y.exe",
        r"\Users\bob\Downloads\script.exe",
    ):
        assert bam_dam.is_suspicious_path(p), f"missed suspicious: {p}"


def test_is_suspicious_path_ignores_system_and_program_files():
    for p in (
        r"C:\Windows\System32\cmd.exe",
        r"C:\Program Files\Microsoft\Teams\Teams.exe",
        "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy",
    ):
        assert not bam_dam.is_suspicious_path(p), \
            f"false positive on {p}"


def test_summarise_counts_per_sid_and_orders_suspicious_newest_first():
    entries = [
        bam_dam.BamEntry(sid="S-1-5-18", executable="cmd.exe",
                         last_run_utc="2024-01-01T10:00:00+00:00",
                         source_key="bam:/"),
        bam_dam.BamEntry(sid="S-1-5-21-A",
                         executable=r"C:\Users\alice\AppData\Local\Temp\a.exe",
                         last_run_utc="2024-03-01T10:00:00+00:00",
                         source_key="bam:/"),
        bam_dam.BamEntry(sid="S-1-5-21-A",
                         executable=r"C:\Users\alice\Downloads\b.exe",
                         last_run_utc="2024-02-01T10:00:00+00:00",
                         source_key="bam:/"),
    ]
    s = bam_dam.summarise(entries)
    assert s.total_entries == 3
    assert s.per_sid == {"S-1-5-18": 1, "S-1-5-21-A": 2}
    # Newest suspicious first
    assert s.suspicious[0].executable.endswith("a.exe")
    assert s.suspicious[1].executable.endswith("b.exe")


def test_parse_system_hive_returns_empty_for_missing_file(tmp_path):
    assert bam_dam.parse_system_hive(tmp_path / "nope") == []


# ---------------------------------------------------------------------------
# Real-hive sanity check (wkstn-01 SYSTEM, if present)
# ---------------------------------------------------------------------------

_SYSTEM_HIVE = Path(
    "/opt/EL/cases/srl-wkstn-01-disk-r4/exports/windows-artifacts/registry/SYSTEM"
)


@pytest.mark.skipif(not _SYSTEM_HIVE.is_file(),
                    reason="requires the SRL-2018 wkstn-01 SYSTEM hive")
def test_parse_real_wkstn01_system_hive():
    """Smoke test against the real hive we already used to validate
    the skill during development. Expect 5+ SIDs and 30+ entries —
    numbers observed on the live run."""
    entries = bam_dam.parse_system_hive(_SYSTEM_HIVE)
    assert len(entries) >= 30
    sids = {e.sid for e in entries}
    assert len(sids) >= 5
    # Every entry has a parseable timestamp
    assert all(e.last_run_utc for e in entries)


# ---------------------------------------------------------------------------
# Windows Timeline parser — synthetic ActivitiesCache.db
# ---------------------------------------------------------------------------

_ACTIVITY_COLUMNS_DDL = """
    CREATE TABLE Activity (
        Id TEXT PRIMARY KEY,
        AppId TEXT,
        PackageIdHash TEXT,
        AppActivityId TEXT,
        ActivityType INTEGER,
        ParentActivityId TEXT,
        Tag TEXT,
        "Group" TEXT,
        MatchId TEXT,
        LastModifiedTime INTEGER,
        ExpirationTime INTEGER,
        Payload TEXT,
        Priority INTEGER,
        IsLocalOnly INTEGER,
        ETag INTEGER,
        CreatedInCloud INTEGER,
        StartTime INTEGER,
        EndTime INTEGER
    )
"""


def _make_activities_cache(path: Path, rows: list[dict]) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(_ACTIVITY_COLUMNS_DDL)
    for r in rows:
        conn.execute(
            'INSERT INTO Activity (Id, AppId, ActivityType, Payload, '
            'StartTime, EndTime, LastModifiedTime) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (r["Id"], r["AppId"], r["ActivityType"], r["Payload"],
             r["StartTime"], r["EndTime"], r["LastModifiedTime"]),
        )
    conn.commit()
    conn.close()


def _appid_win32(path: str) -> str:
    import json
    return json.dumps([{"application": path, "platform": "windows_win32"}])


def _appid_packaged(name: str) -> str:
    import json
    return json.dumps([{"application": name, "platform": "packagedApplication"}])


def _payload(**kw) -> str:
    import json
    return json.dumps(kw)


def test_parse_activities_cache_extracts_win32_app_path(tmp_path):
    db = tmp_path / "ActivitiesCache.db"
    _make_activities_cache(db, [{
        "Id": "a1", "AppId": _appid_win32("C:\\Program Files\\x.exe"),
        "ActivityType": 5,
        "Payload": _payload(displayText="Do the thing",
                             description="doing", activationUri="file:///x"),
        "StartTime": 1700000000, "EndTime": 1700000060,
        "LastModifiedTime": 1700000060,
    }])
    entries = wt.parse_activities_cache(db)
    assert len(entries) == 1
    e = entries[0]
    assert e.app_path.endswith("x.exe")
    assert e.display_text == "Do the thing"
    assert e.start_time_utc.startswith("2023-11-14")
    assert e.activity_type_name == "app_in_use"


def test_parse_activities_cache_packaged_app():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "a.db"
        _make_activities_cache(db, [{
            "Id": "a2",
            "AppId": _appid_packaged("Microsoft.Windows.Photos_8wekyb3d8bbwe"),
            "ActivityType": 5,
            "Payload": _payload(displayText="Photos app"),
            "StartTime": 1700000100, "EndTime": 1700000200,
            "LastModifiedTime": 1700000200,
        }])
        entries = wt.parse_activities_cache(db)
        assert entries[0].app_id == "Microsoft.Windows.Photos_8wekyb3d8bbwe"
        assert entries[0].app_path == ""


def test_parse_activities_cache_missing_file_returns_empty(tmp_path):
    assert wt.parse_activities_cache(tmp_path / "nope.db") == []


def test_parse_activities_cache_corrupted_returns_empty(tmp_path):
    db = tmp_path / "bad.db"
    db.write_bytes(b"not an sqlite file")
    assert wt.parse_activities_cache(db) == []


def test_has_suspicious_path_fires_on_user_writable():
    e = wt.TimelineEntry(
        app_path=r"C:\Users\alice\AppData\Local\Temp\dropper.exe",
    )
    assert wt.has_suspicious_path(e)


def test_has_suspicious_path_fires_on_target_uri():
    e = wt.TimelineEntry(
        target_uri=r"file:///C:/Users/Public/Downloads/x.exe",
    )
    assert wt.has_suspicious_path(e)


def test_has_suspicious_path_silent_on_clean_path():
    e = wt.TimelineEntry(
        app_path=r"C:\Program Files\Microsoft\Teams\teams.exe",
    )
    assert not wt.has_suspicious_path(e)


def test_suspicious_entries_filters(tmp_path):
    db = tmp_path / "a.db"
    _make_activities_cache(db, [
        {"Id": "c1", "AppId": _appid_win32(r"C:\Program Files\clean.exe"),
         "ActivityType": 5, "Payload": _payload(),
         "StartTime": 1700000000, "EndTime": 0, "LastModifiedTime": 1700000000},
        {"Id": "c2", "AppId": _appid_win32(
            r"C:\Users\alice\AppData\Local\Temp\sus.exe"),
         "ActivityType": 5, "Payload": _payload(),
         "StartTime": 1700000100, "EndTime": 0, "LastModifiedTime": 1700000100},
    ])
    entries = wt.parse_activities_cache(db)
    sus = wt.suspicious_entries(entries)
    assert len(sus) == 1
    assert "sus.exe" in sus[0].app_path


# ---------------------------------------------------------------------------
# Agent-level wiring
# ---------------------------------------------------------------------------

def test_windows_artifact_agent_emits_bam_and_timeline(tmp_path, monkeypatch):
    """Synthetic artifact export tree: one SYSTEM hive (empty enough
    that parse returns zero → insufficient path), one ActivitiesCache.db
    with a suspicious Temp-path entry. Asserts both emit the right
    high-confidence Finding with the right hypothesis tags."""
    from el.agents.base import AgentContext
    from el.agents.windows_artifact import WindowsArtifactAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    input_dir = tmp_path / "artifacts"
    reg_dir = input_dir / "registry"
    reg_dir.mkdir(parents=True, exist_ok=True)
    # Minimal "SYSTEM" hive — not a real one; bam_dam returns []
    (reg_dir / "SYSTEM").write_bytes(b"\0" * 16)

    timeline_dir = input_dir / "timeline"
    timeline_dir.mkdir()
    _make_activities_cache(timeline_dir / "alice--L.alice--ActivitiesCache.db",
                            [{"Id": "s1",
                              "AppId": _appid_win32(
                                  r"C:\Users\alice\AppData\Local\Temp\evil.exe"),
                              "ActivityType": 5,
                              "Payload": _payload(
                                  displayText="ran evil.exe"),
                              "StartTime": 1700000000, "EndTime": 0,
                              "LastModifiedTime": 1700000000}])

    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-bam-timeline")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-bam-timeline",
                       case_dir=Path(m.case_dir),
                       input_path=input_dir, manifest=m.__dict__)
    findings = WindowsArtifactAgent().run(ctx)
    claims = [f.claim for f in findings]

    # BAM path produces an insufficient because the fake hive has no
    # BAM tree (that's OK — confirms the agent didn't crash on a
    # parseable-but-empty hive)
    bam_sum = [f for f in findings if "BAM/DAM" in f.claim]
    assert bam_sum, f"expected a BAM finding, got {claims}"

    # Timeline path fires the summary + the suspicious-path finding
    tl_sum = [f for f in findings if "Windows Timeline parsed" in f.claim]
    assert tl_sum and tl_sum[0].confidence == "high"
    tl_sus = [f for f in findings
              if "Windows Timeline suspicious-path" in f.claim]
    assert tl_sus, "expected a suspicious-path timeline finding"
    assert "H_APT_ESPIONAGE" in tl_sus[0].hypotheses_supported
