"""CrowdStrike Falcon JSON-line parser.

In-memory fixtures + an opt-in corpus smoke test (gated on
``ATTACK_DATA_ROOT``) against the real Splunk attack_data Falcon
captures.
"""
import gzip
import json
import os
from pathlib import Path

import pytest

from el.skills import falcon_logs as fl


def _write_lines(path: Path, events: list[dict]):
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")


_PROCESS_ROLLUP = {
    "event_simpleName": "ProcessRollup2",
    "ImageFileName": "\\Device\\HarddiskVolume1\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell -enc dABlAHMAdAA=",
    "ParentBaseFileName": "explorer.exe",
    "GrandParentBaseFileName": "userinit.exe",
    "RawProcessId": 4036,
    "UserSid": "S-1-5-21-1-1-1-1000",
    "SHA256HashData": "ab" * 32,
    "aid": "f0778584e83c4efc9cf026bc1e7f0489",
    "cid": "124cb22314bf4f519be84bce582e7a6b",
    "timestamp": "1658918561056",
}

_LSASS_HANDLE = {
    "event_simpleName": "ProcessHandleOpDetectInfo",
    "TargetProcessImageFileName": "\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe",
    "ContextImageFileName": "\\Device\\HarddiskVolume1\\Tools\\mimikatz.exe",
    "GrantedAccess": "0x1410",
    "ContextProcessId": "987654",
    "aid": "f0778584e83c4efc9cf026bc1e7f0489",
    "ContextTimeStamp": "1658918559.957",
}

_BENIGN_LSASS = {**_LSASS_HANDLE, "GrantedAccess": "0x1000"}

_DUMP_FILE = {
    "event_simpleName": "DmpFileWritten",
    "TargetFileName": "\\Device\\HarddiskVolume1\\Windows\\Temp\\lsass-xordump.dmp",
    "ContextProcessId": "332855234",
    "aid": "f0778584e83c4efc9cf026bc1e7f0489",
    "ContextTimeStamp": "1658918559.957",
}

_DNS = {
    "event_simpleName": "DnsRequest",
    "DomainName": "evil.example.com",
    "RequestType": "1",
    "ContextTimeStamp": "1658918560.000",
}

_NOT_AN_EVENT = {"foo": "bar"}            # missing event_simpleName


# --- core parse --------------------------------------------------------

def test_parse_event_basic():
    line = json.dumps(_PROCESS_ROLLUP)
    ev = fl.parse_event(line)
    assert ev is not None
    assert ev.event_name == "ProcessRollup2"
    assert "powershell.exe" in ev.image
    assert ev.parent_image == "explorer.exe"
    assert ev.process_id == "4036"
    assert ev.sha256 == "ab" * 32
    assert ev.aid.startswith("f0778584")


def test_parse_event_returns_none_on_garbage():
    assert fl.parse_event("not json") is None
    assert fl.parse_event("") is None
    assert fl.parse_event(json.dumps(_NOT_AN_EVENT)) is None
    # JSON arrays are not events
    assert fl.parse_event("[1, 2, 3]") is None


def test_parse_event_timestamp_ms_to_seconds():
    """Falcon `timestamp` field is milliseconds; we normalise to
    seconds (Unix epoch) for the ts_unix field so all skills use the
    same scale."""
    ev = fl.parse_event(json.dumps(_PROCESS_ROLLUP))
    # 1658918561056 ms → 1658918561.056 s
    assert 1658918561.0 < ev.ts_unix < 1658918562.0


def test_parse_event_context_timestamp_seconds():
    """ContextTimeStamp is already in seconds; don't double-divide."""
    ev = fl.parse_event(json.dumps(_LSASS_HANDLE))
    assert 1658918559.0 < ev.ts_unix < 1658918560.0


def test_iter_events_streams(tmp_path):
    p = tmp_path / "falcon.log"
    _write_lines(p, [_PROCESS_ROLLUP, _LSASS_HANDLE, _DNS])
    events = list(fl.iter_events(p))
    assert [e.event_name for e in events] == [
        "ProcessRollup2", "ProcessHandleOpDetectInfo", "DnsRequest"]


def test_iter_events_skips_invalid_lines(tmp_path):
    p = tmp_path / "falcon.log"
    p.write_text("\n".join([
        json.dumps(_PROCESS_ROLLUP),
        "definitely not json",
        "",
        json.dumps(_NOT_AN_EVENT),
        json.dumps(_DNS),
    ]))
    events = list(fl.iter_events(p))
    assert len(events) == 2


def test_iter_events_max_cap(tmp_path):
    p = tmp_path / "falcon.log"
    _write_lines(p, [_PROCESS_ROLLUP] * 100)
    events = list(fl.iter_events(p, max_events=5))
    assert len(events) == 5


def test_iter_events_missing_file(tmp_path):
    assert list(fl.iter_events(tmp_path / "absent.log")) == []


def test_iter_events_handles_gzip(tmp_path):
    p = tmp_path / "falcon.log.gz"
    with gzip.open(p, "wt") as fh:
        fh.write(json.dumps(_LSASS_HANDLE) + "\n")
    events = list(fl.iter_events(p))
    assert len(events) == 1


# --- aggregations ------------------------------------------------------

def test_by_event_name_counts():
    parsed = [fl.parse_event(json.dumps(d)) for d in
              (_PROCESS_ROLLUP, _LSASS_HANDLE, _LSASS_HANDLE, _DNS)]
    assert fl.by_event_name(parsed) == {
        "ProcessRollup2": 1,
        "ProcessHandleOpDetectInfo": 2,
        "DnsRequest": 1,
    }


# --- detectors ---------------------------------------------------------

def test_find_lsass_handles_drops_benign():
    parsed = [fl.parse_event(json.dumps(d)) for d in
              (_LSASS_HANDLE, _BENIGN_LSASS, _PROCESS_ROLLUP)]
    hits = fl.find_lsass_handles(parsed)
    assert len(hits) == 1
    assert hits[0].granted_access == "0x1410"


def test_find_lsass_handles_drops_system_source():
    """A handle-op against lsass from svchost is the LSM service —
    benign background, not credential dumping."""
    svchost = {**_LSASS_HANDLE,
               "ContextImageFileName":
                   "\\Device\\HarddiskVolume1\\Windows\\System32\\svchost.exe"}
    ev = fl.parse_event(json.dumps(svchost))
    assert fl.find_lsass_handles([ev]) == []


def test_find_lsass_handles_skips_non_lsass_target():
    other = {**_LSASS_HANDLE,
             "TargetProcessImageFileName":
                 "\\Device\\HarddiskVolume1\\Windows\\explorer.exe"}
    ev = fl.parse_event(json.dumps(other))
    assert fl.find_lsass_handles([ev]) == []


def test_find_lsass_dump_files_matches_dmp_with_lsass_substring():
    parsed = [fl.parse_event(json.dumps(_DUMP_FILE))]
    hits = fl.find_lsass_dump_files(parsed)
    assert len(hits) == 1
    assert "lsass" in hits[0].target_file.lower()


def test_find_lsass_dump_files_skips_unrelated_files():
    other = {**_DUMP_FILE,
             "TargetFileName": "\\Device\\HarddiskVolume1\\Temp\\benign.dmp"}
    parsed = [fl.parse_event(json.dumps(other))]
    assert fl.find_lsass_dump_files(parsed) == []


def test_find_process_creates_filters():
    parsed = [fl.parse_event(json.dumps(_PROCESS_ROLLUP))]
    assert fl.find_process_creates(parsed,
                                     image_substr="powershell")
    assert fl.find_process_creates(parsed, cmdline_substr="-enc")
    assert not fl.find_process_creates(parsed,
                                          image_substr="cmd.exe")


def test_find_dns_queries_filter():
    parsed = [fl.parse_event(json.dumps(_DNS))]
    assert fl.find_dns_queries(parsed, query_substr="evil")
    assert not fl.find_dns_queries(parsed,
                                      query_substr="microsoft")


# --- corpus smoke ------------------------------------------------------

@pytest.mark.skipif(
    not os.environ.get("ATTACK_DATA_ROOT")
    or not Path(os.environ.get("ATTACK_DATA_ROOT", ""),
                "datasets/attack_techniques/T1003.001/atomic_red_team/"
                "crowdstrike_falcon.log").is_file(),
    reason="ATTACK_DATA_ROOT not set or T1003.001 Falcon sample missing",
)
def test_real_t1003_001_falcon_sample_has_lsass_indicators():
    root = Path(os.environ["ATTACK_DATA_ROOT"])
    p = (root / "datasets" / "attack_techniques" / "T1003.001"
         / "atomic_red_team" / "crowdstrike_falcon.log")
    events = fl.parse_file(p)
    assert events, "expected events from real Falcon corpus"
    counts = fl.by_event_name(events)
    # ProcessHandleOpDetectInfo or DmpFileWritten should fire on this T-ID
    assert (counts.get("ProcessHandleOpDetectInfo", 0) > 0
            or counts.get("DmpFileWritten", 0) > 0)
    has_lsass_evidence = (
        bool(fl.find_lsass_handles(events))
        or bool(fl.find_lsass_dump_files(events))
    )
    assert has_lsass_evidence, (
        "expected LSASS-handle or LSASS-dump-file hits on T1003.001")
