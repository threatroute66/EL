"""Tests for the Zeek-JSON ingester and the Windows Event XML parser."""
import json
from pathlib import Path

import pytest

from el.skills import evtx_xml as ex
from el.skills import zeek_json as zj


# --- Zeek JSON --------------------------------------------------------------

def _make_zeek(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    conn = [{"ts": 1715688000.4, "uid": "C1", "id.orig_h": "10.44.30.10",
             "id.resp_h": "10.44.10.25", "id.resp_p": 135, "proto": "tcp"}]
    dns = [{"ts": 1715688001.0, "query": "evil.example.com",
            "answers": ["1.2.3.4"], "qtype_name": "A"}]
    http = [{"ts": 1715688002.0, "host": "portal.northstarclaims.net",
             "method": "GET", "uri": "/login", "status_code": 200,
             "user_agent": "curl/8.0"}]
    for name, recs in (("conn.json", conn), ("dns.json", dns),
                       ("http.json", http)):
        with (d / name).open("w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
            if name == "conn.json":
                f.write("MALFORMED\n")           # lenient skip


def test_zeek_parse_dir_and_counts(tmp_path):
    zd = tmp_path / "zeek"
    _make_zeek(zd)
    run = zj.parse_dir(zd, output_dir=tmp_path / "out")
    assert run.counts() == {"conn": 1, "dns": 1, "http": 1}
    assert run.total == 3
    assert run.connections()[0]["id.resp_p"] == 135
    assert run.connections()[0]["_ts_utc"] == "2024-05-14 12:00:00"


def test_zeek_views_and_find(tmp_path):
    zd = tmp_path / "zeek"
    _make_zeek(zd)
    run = zj.parse_dir(zd)
    assert run.dns_queries()[0]["query"] == "evil.example.com"
    assert run.http_requests()[0]["host"] == "portal.northstarclaims.net"
    # find across all logs (answers list + query string)
    assert run.find("evil.example.com")
    assert run.find("1.2.3.4")                    # inside dns answers list
    assert run.find("portal", logtype="http")
    ev = run.as_evidence()
    assert ev.extracted_facts["logs"]["dns"] == 1
    assert ev.tool == "el.zeek_json"


def test_zeek_find_logs_and_missing(tmp_path):
    zd = tmp_path / "zeek"
    _make_zeek(zd)
    found = zj.find_zeek_logs(zd)
    assert set(found) == {"conn", "dns", "http"}
    with pytest.raises(zj.ZeekJsonError):
        zj.parse_log(tmp_path / "nope.json")


# --- Windows Event XML ------------------------------------------------------

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_XML = f"""<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="{_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2024-05-14T12:00:07.6293825Z"/>
    <Computer>DC-BO-01.northstar-branch.local</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">nina.kapoor</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.44.30.10</Data>
  </EventData>
</Event>
<Event xmlns="{_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2024-05-14T12:01:00.0Z"/>
    <Computer>DC-BO-01.northstar-branch.local</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
  </EventData>
</Event>
</Events>
"""


def test_evtx_xml_parse(tmp_path):
    p = tmp_path / "sec.xml"
    p.write_text(_XML)
    run = ex.parse(p, output_dir=tmp_path / "out")
    assert run.total == 2
    assert run.by_event_id() == {"4624": 1, "4688": 1}
    e = run.with_id("4624")[0]
    assert e.time_utc == "2024-05-14 12:00:07"
    assert e.computer == "DC-BO-01.northstar-branch.local"
    assert e.provider == "Microsoft-Windows-Security-Auditing"
    assert e.data["TargetUserName"] == "nina.kapoor"
    assert e.data["IpAddress"] == "10.44.30.10"


def test_evtx_xml_views_and_find(tmp_path):
    p = tmp_path / "sec.xml"
    p.write_text(_XML)
    run = ex.parse(p)
    assert len(run.logons()) == 1 and run.logons()[0].event_id == "4624"
    assert len(run.process_creations()) == 1
    assert run.find("nina.kapoor")
    assert run.find("cmd.exe")
    assert run.date_range() == ("2024-05-14 12:00:07", "2024-05-14 12:01:00")
    ev = run.as_evidence()
    assert ev.extracted_facts["logon_events"] == 1
    assert ev.tool == "el.evtx_xml"


def test_evtx_xml_missing_raises(tmp_path):
    with pytest.raises(ex.EvtxXmlError):
        ex.parse(tmp_path / "nope.xml")


# --- real-data smokes (skip-gated on the Northstar log corpus) --------------

_CORPUS = Path("/mnt/hgfs/logs/data")


@pytest.mark.skipif(not (_CORPUS / "ZEEK-BO-CORE").is_dir(),
                    reason="Northstar log corpus absent")
def test_real_zeek_and_evtx():
    z = zj.parse_dir(_CORPUS / "ZEEK-BO-CORE")
    assert z.total > 1000 and "conn" in z.counts() and z.http_requests()
    sec = ex.parse(_CORPUS / "DC-BO-01.northstar-branch.local"
                   / "windows_event_security.xml")
    assert sec.total > 1000 and sec.logons()
    assert "4624" in sec.by_event_id()
