"""iOS sysdiagnose tarball parser.

Synthetic in-memory fixtures + an opt-in real-corpus test against
``/mnt/hgfs/hackathon/ios_13_4_1`` when the image is staged.
"""
import io
import json
import tarfile
from pathlib import Path

import pytest

from el.skills import sysdiagnose as sd


_HEADER = {
    "bug_type": "298",
    "timestamp": "2025-01-01 12:00:00.00 +0000",
    "os_version": "iPhone OS 16.5 (20F66)",
    "incident_id": "AAAA-BBBB-CCCC",
}

_JETSAM_BODY = {
    "product": "iPhone14,2",
    "build": "iPhone OS 16.5",
    "largestProcess": "Maps",
    "memoryStatus": {
        "compressorSize": 30000,
        "memoryPages": {"free": 3000, "anonymous": 40000},
    },
    "processes": [
        {"name": "Maps", "pid": 1234, "rpages": 5000},
        {"name": "Safari", "pid": 5678, "rpages": 2000},
    ],
}

_CRASH_HEADER = {
    "bug_type": "109",
    "timestamp": "2025-01-01 12:30:00.00 +0000",
    "os_version": "iPhone OS 16.5 (20F66)",
    "incident_id": "DDDD-EEEE-FFFF",
}

_CRASH_BODY = {
    "product": "iPhone14,2",
    "exception": {"type": "EXC_BAD_ACCESS"},
    "process": "MyApp",
}


def _write_ips(path: Path, header: dict, body: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(header) + "\n" + json.dumps(body))


def _make_synthetic_root(root: Path):
    """Build a minimal sysdiagnose-shaped tree with two .ips
    records + a placeholder logarchive subdir."""
    cas = root / "crashes_and_spins"
    _write_ips(cas / "JetsamEvent-2025-01-01-120000.ips",
                _HEADER, _JETSAM_BODY)
    _write_ips(cas / "MyApp-crash-2025-01-01-123000.ips",
                _CRASH_HEADER, _CRASH_BODY)
    # Apple double-fork resource files (._ prefix) — should be skipped
    (cas / "._JetsamEvent-2025-01-01-120000.ips").write_bytes(b"\x00")
    (root / "system_logs.logarchive").mkdir()
    (root / "system_logs.logarchive" / "00").mkdir()
    (root / "system_logs.logarchive" / "00" / "tracev3").write_bytes(b"x" * 4096)
    (root / "summaries").mkdir()
    (root / "summaries" / "info.txt").write_text("device summary")


# --- parse_ips ---------------------------------------------------------

def test_parse_ips_jetsam_record(tmp_path):
    p = tmp_path / "j.ips"
    _write_ips(p, _HEADER, _JETSAM_BODY)
    rec = sd.parse_ips(p)
    assert rec.parse_error == ""
    assert rec.bug_type == "298"
    assert rec.os_version == "iPhone OS 16.5 (20F66)"
    assert rec.is_jetsam is True
    assert rec.product == "iPhone14,2"
    assert rec.largest_process == "Maps"


def test_parse_ips_crash_record(tmp_path):
    p = tmp_path / "c.ips"
    _write_ips(p, _CRASH_HEADER, _CRASH_BODY)
    rec = sd.parse_ips(p)
    assert rec.is_crash is True
    assert rec.is_jetsam is False
    assert rec.body.get("exception", {}).get("type") == "EXC_BAD_ACCESS"


def test_parse_ips_handles_missing_file(tmp_path):
    rec = sd.parse_ips(tmp_path / "nope.ips")
    assert rec.parse_error
    assert rec.bug_type == ""


def test_parse_ips_handles_corrupt_header(tmp_path):
    p = tmp_path / "bad.ips"
    p.write_text("not json\n{}")
    rec = sd.parse_ips(p)
    assert rec.parse_error.startswith("header parse")


def test_parse_ips_handles_no_newline_separator(tmp_path):
    p = tmp_path / "single.ips"
    p.write_text(json.dumps(_HEADER))
    rec = sd.parse_ips(p)
    assert rec.parse_error == "no newline separating header from body"


def test_parse_ips_partial_when_body_corrupt(tmp_path):
    """Header parses but body is junk — surface header + flag the
    body error rather than failing the whole record."""
    p = tmp_path / "partial.ips"
    p.write_text(json.dumps(_HEADER) + "\nnot a json blob")
    rec = sd.parse_ips(p)
    assert rec.bug_type == "298"
    assert "body parse" in rec.parse_error


# --- index -------------------------------------------------------------

def test_index_walks_subsystems(tmp_path):
    _make_synthetic_root(tmp_path / "root")
    idx = sd.index(tmp_path / "root")
    assert "crashes_and_spins" in idx.subsystems
    # Both .ips + the AppleDouble ._ file
    assert idx.subsystems["crashes_and_spins"] == 3
    assert idx.has_logarchive is True
    assert idx.logarchive_bytes >= 4096
    # ips_files filters out the AppleDouble ._ noise
    assert len(idx.ips_files) == 2


def test_index_missing_root(tmp_path):
    idx = sd.index(tmp_path / "absent")
    assert idx.file_count == 0
    assert idx.has_logarchive is False


# --- find_*  -----------------------------------------------------------

def test_find_jetsam_events(tmp_path):
    _make_synthetic_root(tmp_path / "root")
    idx = sd.index(tmp_path / "root")
    js = sd.find_jetsam_events(idx)
    assert len(js) == 1
    assert js[0].bug_type == "298"


def test_find_crashes_excludes_jetsam(tmp_path):
    _make_synthetic_root(tmp_path / "root")
    idx = sd.index(tmp_path / "root")
    cr = sd.find_crashes(idx)
    # Only the MyApp crash IPS, not the jetsam one
    assert len(cr) == 1
    assert cr[0].bug_type == "109"


def test_device_metadata_picks_first_parseable(tmp_path):
    _make_synthetic_root(tmp_path / "root")
    idx = sd.index(tmp_path / "root")
    md = sd.device_metadata(idx)
    assert md["os_version"].startswith("iPhone OS 16.5")
    assert md["product"] == "iPhone14,2"
    # Logarchive present → unified-log replay marked unavailable
    # with a note pointing at the macOS-host requirement
    assert md["has_logarchive"] is True
    assert md["unified_log_replay_available"] is False
    assert "log show" in md["unified_log_replay_note"]


# --- extract -----------------------------------------------------------

def test_extract_round_trips(tmp_path):
    """Build a synthetic sysdiagnose-shaped tar.gz and round-trip
    it through extract()."""
    src = tmp_path / "src"
    _make_synthetic_root(src / "sysdiagnose_2025-01-01_TEST")
    tarball = tmp_path / "sd.tar.gz"
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(src / "sysdiagnose_2025-01-01_TEST",
               arcname="sysdiagnose_2025-01-01_TEST")
    out = tmp_path / "extracted"
    root = sd.extract(tarball, out)
    assert root.is_dir()
    assert root.name == "sysdiagnose_2025-01-01_TEST"
    # Re-index post-extract; counts should match
    idx = sd.index(root)
    assert len(idx.ips_files) == 2


# --- corpus smoke ------------------------------------------------------

_REAL_TARBALL = ("/mnt/hgfs/hackathon/ios_13_4_1/iOS 13.4.1 Extraction/"
                  "Sysdiagnose Logs/"
                  "sysdiagnose_2020.04.16_11-44-04-0400_iPhone-OS_iPhone_17E262.tar.gz")


@pytest.mark.skipif(not Path(_REAL_TARBALL).is_file(),
                     reason="real iOS 13.4.1 sysdiagnose corpus not present")
def test_real_sysdiagnose_index(tmp_path):
    root = sd.extract(_REAL_TARBALL, tmp_path)
    idx = sd.index(root)
    # Real corpus: 2k+ files, has Unified Log archive, has IPS records
    assert idx.file_count > 100
    assert idx.has_logarchive is True
    assert idx.ips_files                       # non-empty
    md = sd.device_metadata(idx)
    assert "13.4.1" in md["os_version"]
    assert md["product"].startswith("iPhone")
    # Jetsam events should be present in any real iOS sysdiagnose
    js = sd.find_jetsam_events(idx)
    assert len(js) >= 1
    assert js[0].is_jetsam
