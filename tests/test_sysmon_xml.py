"""Sysmon XML-stream parser.

Tests use small in-memory fixtures so the suite doesn't depend on
the multi-GB Splunk attack_data corpus. A separate corpus-driven
smoke test (gated on ``ATTACK_DATA_ROOT``) exercises the parser
against real recorded telemetry.
"""
import os
import textwrap
from pathlib import Path

import pytest

from el.skills import sysmon_xml as sx


def _write_events(path: Path, events: list[str]):
    path.write_text("\n".join(events) + "\n")


# A canonical ProcessAccess (EID 10) targeting lsass with the
# 0x1410 access mask — the T1003.001 fingerprint shape.
_LSASS_HANDLE = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Microsoft-Windows-Sysmon'/>"
    "<EventID>10</EventID>"
    "<TimeCreated SystemTime='2025-01-01T12:00:00.000Z'/>"
    "<Computer>WIN-DC-1</Computer></System>"
    "<EventData>"
    "<Data Name='SourceImage'>C:\\Tools\\mimikatz.exe</Data>"
    "<Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data>"
    "<Data Name='GrantedAccess'>0x1410</Data>"
    "<Data Name='CallTrace'>ntdll.dll+a5a94|kernel32.dll+1234</Data>"
    "</EventData></Event>"
)

# A benign-looking lsass access (0x1000 = QueryLimitedInformation)
# to confirm the detector skips ordinary handles.
_BENIGN_LSASS = _LSASS_HANDLE.replace("0x1410", "0x1000")

_PROCESS_CREATE = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><EventID>1</EventID>"
    "<TimeCreated SystemTime='2025-01-01T12:01:00.000Z'/>"
    "<Computer>WIN-DC-1</Computer></System>"
    "<EventData>"
    "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
    "<Data Name='CommandLine'>powershell -enc dABlAHMAdAA=</Data>"
    "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
    "<Data Name='User'>WIN-DC-1\\admin</Data>"
    "<Data Name='ProcessId'>4321</Data>"
    "</EventData></Event>"
)

_DNS_QUERY = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><EventID>22</EventID>"
    "<TimeCreated SystemTime='2025-01-01T12:02:00.000Z'/>"
    "<Computer>WS-1</Computer></System>"
    "<EventData>"
    "<Data Name='QueryName'>evil.example.com</Data>"
    "<Data Name='QueryStatus'>0</Data>"
    "</EventData></Event>"
)


# --- core parse --------------------------------------------------------

def test_parse_event_lsass_handle_basic():
    ev = sx.parse_event(_LSASS_HANDLE)
    assert ev is not None
    assert ev.eid == 10
    assert ev.name == "ProcessAccess"
    assert ev.computer == "WIN-DC-1"
    assert ev.ts_utc == "2025-01-01T12:00:00.000Z"
    assert ev.data["GrantedAccess"] == "0x1410"
    assert ev.target_image.endswith("lsass.exe")
    assert ev.image.endswith("mimikatz.exe")


def test_parse_event_returns_none_when_no_eid():
    assert sx.parse_event("<Event><System></System></Event>") is None


def test_parse_event_tolerates_missing_optional_fields():
    minimal = ("<Event><System><EventID>3</EventID></System>"
               "<EventData></EventData></Event>")
    ev = sx.parse_event(minimal)
    assert ev is not None
    assert ev.eid == 3
    assert ev.computer == ""
    assert ev.ts_utc == ""
    assert ev.data == {}


def test_iter_events_streams_multiple(tmp_path):
    p = tmp_path / "sysmon.log"
    _write_events(p, [_LSASS_HANDLE, _PROCESS_CREATE, _DNS_QUERY])
    events = list(sx.iter_events(p))
    assert len(events) == 3
    assert [e.eid for e in events] == [10, 1, 22]


def test_iter_events_handles_multiline_records(tmp_path):
    """Sysmon CallTrace blobs frequently wrap across lines —
    ensure the regex reassembles correctly."""
    wrapped = _LSASS_HANDLE.replace(
        "ntdll.dll+a5a94", "ntdll.dll+a5a94\n  kernelbase.dll+5eab4")
    p = tmp_path / "sysmon.log"
    p.write_text(wrapped + "\n")
    events = list(sx.iter_events(p))
    assert len(events) == 1
    assert events[0].eid == 10
    assert "kernelbase" in events[0].data["CallTrace"]


def test_iter_events_missing_file(tmp_path):
    assert list(sx.iter_events(tmp_path / "absent.log")) == []


def test_iter_events_max_cap(tmp_path):
    p = tmp_path / "sysmon.log"
    _write_events(p, [_PROCESS_CREATE] * 100)
    events = list(sx.iter_events(p, max_events=5))
    assert len(events) == 5


def test_iter_events_handles_gzip(tmp_path):
    import gzip
    p = tmp_path / "sysmon.log.gz"
    with gzip.open(p, "wt") as fh:
        fh.write(_LSASS_HANDLE + "\n")
    events = list(sx.iter_events(p))
    assert len(events) == 1
    assert events[0].eid == 10


# --- accessors ---------------------------------------------------------

def test_event_accessors():
    ev = sx.parse_event(_PROCESS_CREATE)
    assert "powershell.exe" in ev.image
    assert ev.parent_image.endswith("explorer.exe")
    assert "dABlAHMAdAA=" in ev.command_line
    assert ev.process_id == "4321"
    assert ev.user == "WIN-DC-1\\admin"


# --- aggregations ------------------------------------------------------

def test_by_eid_counts():
    parsed = [sx.parse_event(b) for b in
              (_LSASS_HANDLE, _LSASS_HANDLE, _PROCESS_CREATE,
               _DNS_QUERY)]
    assert sx.by_eid(parsed) == {10: 2, 1: 1, 22: 1}


def test_filter_eid():
    parsed = [sx.parse_event(b) for b in
              (_LSASS_HANDLE, _PROCESS_CREATE)]
    assert len(sx.filter_eid(parsed, 10)) == 1
    assert len(sx.filter_eid(parsed, 999)) == 0


# --- detectors ---------------------------------------------------------

def test_find_lsass_handles_drops_benign_access(tmp_path):
    p = tmp_path / "sysmon.log"
    _write_events(p, [_LSASS_HANDLE, _BENIGN_LSASS, _PROCESS_CREATE])
    events = sx.parse_file(p)
    hits = sx.find_lsass_handles(events)
    assert len(hits) == 1                  # benign 0x1000 dropped
    assert hits[0].data["GrantedAccess"] == "0x1410"


def test_find_lsass_handles_drops_system_source(tmp_path):
    """svchost.exe handles lsass legitimately (LSM service);
    only the mimikatz-shape source counts as T1003.001."""
    svchost_handle = _LSASS_HANDLE.replace(
        "C:\\Tools\\mimikatz.exe",
        "C:\\Windows\\System32\\svchost.exe")
    p = tmp_path / "sysmon.log"
    _write_events(p, [svchost_handle])
    events = sx.parse_file(p)
    assert sx.find_lsass_handles(events) == []


def test_find_lsass_handles_strict_mask_filters_uncommon_masks(tmp_path):
    """Default strict_mask=True rejects access masks not in the
    canonical creddump set even when the source is non-system."""
    odd_mask = _LSASS_HANDLE.replace("0x1410", "0x1400")
    p = tmp_path / "sysmon.log"
    _write_events(p, [odd_mask])
    events = sx.parse_file(p)
    assert sx.find_lsass_handles(events) == []
    # Non-strict mode accepts the wider net
    assert len(sx.find_lsass_handles(events, strict_mask=False)) == 1


def test_find_lsass_handles_skips_non_lsass_target(tmp_path):
    """Process access that isn't targeting lsass shouldn't fire."""
    other = _LSASS_HANDLE.replace(
        "lsass.exe", "explorer.exe")
    p = tmp_path / "sysmon.log"
    _write_events(p, [other])
    events = sx.parse_file(p)
    assert sx.find_lsass_handles(events) == []


def test_find_process_creates_filters():
    parsed = [sx.parse_event(_PROCESS_CREATE)]
    assert sx.find_process_creates(parsed,
                                     image_substr="powershell")
    assert sx.find_process_creates(parsed, cmdline_substr="-enc")
    assert not sx.find_process_creates(parsed,
                                          image_substr="cmd.exe")


def test_find_dns_queries_filters():
    parsed = [sx.parse_event(_DNS_QUERY)]
    assert sx.find_dns_queries(parsed, query_substr="evil")
    assert not sx.find_dns_queries(parsed,
                                      query_substr="microsoft")


# --- corpus smoke ------------------------------------------------------

@pytest.mark.skipif(
    not os.environ.get("ATTACK_DATA_ROOT")
    or not Path(os.environ.get("ATTACK_DATA_ROOT", ""),
                "datasets/attack_techniques/T1003.001/"
                "atomic_red_team/windows-sysmon.log").is_file(),
    reason="ATTACK_DATA_ROOT not set or T1003.001 sample missing",
)
def test_real_t1003_001_sample_has_lsass_handles():
    root = Path(os.environ["ATTACK_DATA_ROOT"])
    p = (root / "datasets" / "attack_techniques" / "T1003.001"
         / "atomic_red_team" / "windows-sysmon.log")
    events = sx.parse_file(p, max_events=10_000)
    assert events, "expected events from real Sysmon corpus"
    eid_counts = sx.by_eid(events)
    # ProcessAccess dominates the T1003.001 corpus
    assert eid_counts.get(10, 0) > 0
    hits = sx.find_lsass_handles(events)
    assert hits, "expected LSASS-handle hits in T1003.001 corpus"
