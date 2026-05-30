"""Tests for the eCAR / Cisco ASA / Snort fast-alert log parsers."""
import json
from pathlib import Path

import pytest

from el.skills import cisco_asa, ecar
from el.skills import snort_alert as sn


# --- eCAR -------------------------------------------------------------------

_ECAR_LINES = [
    {"timestamp_ms": 1715688000884, "hostname": "DC-BO-01", "object": "MODULE",
     "action": "LOAD", "pid": 5828, "properties": {"image_path": "x.exe",
     "file_path": "gdi32.dll"}},
    {"timestamp_ms": 1715688007000, "hostname": "DC-BO-01", "object": "PROCESS",
     "action": "CREATE", "pid": 99, "ppid": 4, "principal": "SYSTEM",
     "properties": {"command_line": "powershell -enc ZZ", "image_path": "ps.exe"}},
    {"timestamp_ms": 1715688008000, "hostname": "DC-BO-01", "object": "FLOW",
     "action": "CONNECT", "properties": {"src_ip": "10.44.30.10",
     "src_port": "5000", "dst_ip": "8.8.8.8", "dst_port": "443",
     "protocol": "tcp"}},
    {"timestamp_ms": 1715688009000, "hostname": "DC-BO-01", "object": "THREAD",
     "action": "REMOTE_CREATE", "properties": {"target_pid": 1234,
     "image_path": "inj.exe"}},
]


def _write_ecar(tmp_path: Path) -> Path:
    p = tmp_path / "ecar.json"
    with p.open("w") as f:
        for d in _ECAR_LINES:
            f.write(json.dumps(d) + "\n")
        f.write("THIS IS NOT JSON\n")           # malformed -> skipped
    return p


def test_ecar_parse_and_taxonomy(tmp_path):
    run = ecar.parse(_write_ecar(tmp_path), output_dir=tmp_path / "out")
    assert run.total == 4 and run.skipped == 1
    assert run.by_object_action()["FLOW/CONNECT"] == 1
    assert len(run.processes()) == 1
    assert run.processes()[0].command_line == "powershell -enc ZZ"
    assert len(run.network_flows()) == 1
    assert run.network_flows()[0].dst_ip == "8.8.8.8"
    assert len(run.remote_thread_creations()) == 1


def test_ecar_time_and_find(tmp_path):
    run = ecar.parse(_write_ecar(tmp_path))
    assert run.events[0].timestamp_utc == "2024-05-14 12:00:00"
    assert run.find("8.8.8.8") and run.find("powershell")
    assert run.hosts() == ["DC-BO-01"]
    ev = run.as_evidence()
    assert ev.extracted_facts["remote_thread_creations"] == 1
    assert ev.tool == "el.ecar"


def test_ecar_missing_raises(tmp_path):
    with pytest.raises(ecar.ECARError):
        ecar.parse(tmp_path / "nope.json")


# --- Cisco ASA --------------------------------------------------------------

_ASA = """\
<166>May 14 12:00:00 FW-BO-EDGE %ASA-6-302013: Built outbound TCP connection 1206825 for dmz:10.44.30.10/46681 (10.44.30.10/46681) to inside:10.44.10.25/135 (10.44.10.25/135)
<166>May 14 12:00:03 FW-BO-EDGE %ASA-6-302014: Teardown TCP connection 1206825 for dmz:10.44.30.10/46681 to inside:10.44.10.25/135 duration 0:00:02 bytes 11338 TCP FINs
<164>May 14 12:01:00 FW-BO-EDGE %ASA-4-106023: Deny tcp src dmz:45.83.220.5/4444 dst inside:10.44.10.25/3389 by access-group "outside_in"
this line is not an ASA message
"""


def test_asa_parse_connections_and_denies(tmp_path):
    p = tmp_path / "cisco_asa.log"; p.write_text(_ASA)
    run = cisco_asa.parse(p, output_dir=tmp_path / "out")
    assert run.total == 3 and run.skipped == 1
    built = [e for e in run.events if e.action == "Built"][0]
    assert built.protocol == "TCP" and built.src_ip == "10.44.30.10"
    assert built.dst_ip == "10.44.10.25" and built.dst_port == "135"
    teardown = [e for e in run.events if e.action == "Teardown"][0]
    assert teardown.bytes == 11338
    assert len(run.denies()) == 1
    d = run.denies()[0]
    assert d.severity == 4 and d.dst_port == "3389" and d.src_ip == "45.83.220.5"


def test_asa_by_msgid_and_find(tmp_path):
    p = tmp_path / "cisco_asa.log"; p.write_text(_ASA)
    run = cisco_asa.parse(p)
    assert run.by_msg_id()["302013"] == 1
    assert len(run.find_ip("10.44.10.25")) == 3
    assert run.as_evidence().extracted_facts["deny_count"] == 1


def test_asa_missing_raises(tmp_path):
    with pytest.raises(cisco_asa.CiscoASAError):
        cisco_asa.parse(tmp_path / "nope.log")


# --- Snort ------------------------------------------------------------------

_SNORT = """\
05/14-12:00:28.844 [**] [1:384:1] PROTOCOL-ICMP PING [**] [Classification: icmp-event] [Priority: 3] {ICMP} 37.75.195.175 -> 45.83.220.5
05/14-12:24:36.404 [**] [1:2000419:8] ET EXPLOIT Suspicious Inbound [**] [Classification: attempted-admin] [Priority: 1] {TCP} 45.33.74.51:51514 -> 45.83.220.5:3389
05/14-12:28:15.045 [**] [1:366:1] PROTOCOL-ICMP PING [**] [Priority: 3] {ICMP} 38.186.148.245 -> 45.83.220.5
garbage line
"""


def test_snort_parse_fields(tmp_path):
    p = tmp_path / "snort_alert.log"; p.write_text(_SNORT)
    run = sn.parse(p, output_dir=tmp_path / "out")
    assert run.total == 3 and run.skipped == 1
    a = [x for x in run.alerts if x.priority == 1][0]
    assert a.rule == "1:2000419:8" and a.protocol == "TCP"
    assert a.src_ip == "45.33.74.51" and a.src_port == "51514"
    assert a.dst_ip == "45.83.220.5" and a.dst_port == "3389"
    assert a.classification == "attempted-admin"


def test_snort_priority_class_signatures(tmp_path):
    p = tmp_path / "snort_alert.log"; p.write_text(_SNORT)
    run = sn.parse(p)
    assert run.by_priority() == {1: 1, 3: 2}
    assert len(run.high_priority()) == 1
    assert run.find_ip("45.33.74.51")
    assert run.by_classification()["(none)"] == 1     # the no-class ICMP line
    ev = run.as_evidence()
    assert ev.extracted_facts["high_priority_count"] == 1
    assert ev.tool == "el.snort_alert"


def test_snort_missing_raises(tmp_path):
    with pytest.raises(sn.SnortAlertError):
        sn.parse(tmp_path / "nope.log")


# --- real-data smokes (skip-gated on the Northstar log corpus) --------------

_CORPUS = Path("/mnt/hgfs/logs/data")


@pytest.mark.skipif(not _CORPUS.is_dir(), reason="Northstar log corpus absent")
def test_real_corpus_parsers():
    e = ecar.parse(_CORPUS / "DC-BO-01.northstar-branch.local" / "ecar.json")
    assert e.total > 1000 and e.skipped == 0 and e.remote_thread_creations()
    a = cisco_asa.parse(_CORPUS / "FW-BO-EDGE" / "cisco_asa.log")
    assert a.total > 1000 and a.skipped == 0 and a.denies()
    s = sn.parse(_CORPUS / "IDS-BO-EDGE" / "snort_alert.log")
    assert s.total > 10 and s.skipped == 0 and s.high_priority()
