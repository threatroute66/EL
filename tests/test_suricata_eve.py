"""Tests for el.skills.suricata_eve — standalone EVE JSON parser.

Pins the single-pass parser's contract:
  - signature detection (`is_suricata_eve`) requires both
    `event_type` field AND a known event-type value
  - alert clustering by (sig_id, msg)
  - fileinfo capture (sha256 + filename + magic)
  - HTTP / DNS / TLS / Anomaly rollups
  - row cap with `truncated=True` marker
  - graceful on malformed JSONL (drops bad lines, continues)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from el.skills.suricata_eve import (
    EveSummary,
    EveAlertCluster,
    is_suricata_eve,
    parse_eve_json,
)


def _eve(*rows: dict) -> str:
    """Build a JSONL string from event dicts."""
    return "\n".join(json.dumps(r) for r in rows) + "\n"


# ---------------------------------------------------------------------------
# is_suricata_eve — signature detection for triage
# ---------------------------------------------------------------------------

def test_is_suricata_eve_recognises_alert_event(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text(_eve({
        "event_type": "alert", "timestamp": "2026-05-19T08:00:00Z",
        "alert": {"signature_id": 2200000, "signature": "ET TEST"},
    }))
    assert is_suricata_eve(p)


def test_is_suricata_eve_recognises_flow_only(tmp_path):
    """A capture might be flow-only (no alerts fired); still EVE."""
    p = tmp_path / "eve.json"
    p.write_text(_eve({"event_type": "flow",
                         "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8"}))
    assert is_suricata_eve(p)


def test_is_suricata_eve_rejects_unrelated_json(tmp_path):
    """A JSONL file with an `event_type` field that isn't a
    Suricata canonical value must NOT trigger. Guards against
    triaging arbitrary structured logs as EVE."""
    p = tmp_path / "other.json"
    p.write_text(_eve({"event_type": "user_login",
                         "user": "alice"}))
    assert not is_suricata_eve(p)


def test_is_suricata_eve_rejects_missing_event_type(tmp_path):
    p = tmp_path / "anon.json"
    p.write_text(_eve({"foo": "bar"}))
    assert not is_suricata_eve(p)


def test_is_suricata_eve_handles_malformed_first_lines(tmp_path):
    """Trailing newlines / corrupted leading lines / mixed garbage
    at file head must not crash the detector. Falls back to False
    only after exhausting the scan window."""
    p = tmp_path / "messy.json"
    p.write_text(
        "garbage line\n"
        "\n"
        + json.dumps({"event_type": "alert"}) + "\n"
    )
    assert is_suricata_eve(p)


def test_is_suricata_eve_empty_file(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("")
    assert not is_suricata_eve(p)


def test_is_suricata_eve_missing_file(tmp_path):
    assert not is_suricata_eve(tmp_path / "absent.json")


# ---------------------------------------------------------------------------
# parse_eve_json — alert clustering
# ---------------------------------------------------------------------------

def test_parse_clusters_alerts_by_signature_id(tmp_path):
    """Same SID firing 3× from the same source must collapse to
    one EveAlertCluster with count=3, both timestamps captured."""
    rows = [
        {"event_type": "alert", "timestamp": "2026-05-19T08:00:00Z",
         "src_ip": "10.0.0.5", "dest_ip": "8.8.8.8", "dest_port": 53,
         "alert": {"signature_id": 2200000, "signature": "DNS query",
                    "severity": 2, "category": "test"}},
        {"event_type": "alert", "timestamp": "2026-05-19T08:00:30Z",
         "src_ip": "10.0.0.5", "dest_ip": "8.8.4.4", "dest_port": 53,
         "alert": {"signature_id": 2200000, "signature": "DNS query",
                    "severity": 2, "category": "test"}},
        {"event_type": "alert", "timestamp": "2026-05-19T08:01:00Z",
         "src_ip": "10.0.0.5", "dest_ip": "1.1.1.1", "dest_port": 53,
         "alert": {"signature_id": 2200000, "signature": "DNS query",
                    "severity": 2, "category": "test"}},
    ]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    assert len(s.alert_clusters) == 1
    c = s.alert_clusters[0]
    assert c.signature_id == 2200000
    assert c.count == 3
    assert c.first_seen == "2026-05-19T08:00:00Z"
    assert c.last_seen == "2026-05-19T08:01:00Z"
    assert sorted(c.dest_ips) == ["1.1.1.1", "8.8.4.4", "8.8.8.8"]
    assert c.dest_ports == [53]
    assert c.severity == 2


def test_parse_distinct_sigs_become_distinct_clusters(tmp_path):
    rows = [
        {"event_type": "alert", "timestamp": "2026-05-19T08:00:00Z",
         "alert": {"signature_id": 1000, "signature": "A"}},
        {"event_type": "alert", "timestamp": "2026-05-19T08:00:01Z",
         "alert": {"signature_id": 1001, "signature": "B"}},
    ]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    assert len(s.alert_clusters) == 2


def test_parse_clusters_sorted_by_count_desc(tmp_path):
    """Top signature (highest count) must appear first in the
    list — drives the "top N signatures" claim shape."""
    rows = (
        [{"event_type": "alert", "timestamp": "2026-05-19T08:00:00Z",
          "alert": {"signature_id": 100, "signature": "rare"}}]
        + [{"event_type": "alert", "timestamp": "2026-05-19T08:00:00Z",
            "alert": {"signature_id": 200, "signature": "common"}}] * 5
    )
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    assert s.alert_clusters[0].signature_id == 200
    assert s.alert_clusters[0].count == 5
    assert s.alert_clusters[1].signature_id == 100


def test_parse_extracts_attack_techniques_from_metadata(tmp_path):
    """ET-Open rules carry ATT&CK technique IDs in
    `alert.metadata.mitre_technique_id`. Parser must surface them."""
    p = tmp_path / "eve.json"; p.write_text(_eve({
        "event_type": "alert", "timestamp": "2026-05-19T08:00:00Z",
        "alert": {"signature_id": 2200000, "signature": "ET TEST",
                   "metadata": {"mitre_technique_id": ["T1059", "T1071"]}},
    }))
    s = parse_eve_json(p, tmp_path / "out")
    assert s.alert_clusters[0].attack_techniques == ["T1059", "T1071"]


# ---------------------------------------------------------------------------
# parse_eve_json — fileinfo + HTTP / DNS / TLS / Anomaly
# ---------------------------------------------------------------------------

def test_parse_collects_fileinfo_with_sha256(tmp_path):
    """fileinfo events that DON'T carry sha256 (transient/in-flight
    files) are dropped — the sha256 is the load-bearing IOC."""
    rows = [
        {"event_type": "fileinfo", "timestamp": "2026-05-19T08:00:00Z",
         "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
         "fileinfo": {"sha256": "a"*64, "filename": "evil.exe",
                       "magic": "PE32", "size": 1024, "stored": True}},
        {"event_type": "fileinfo", "timestamp": "2026-05-19T08:00:01Z",
         "fileinfo": {"filename": "no-hash.txt"}},   # no sha256 → dropped
    ]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    assert len(s.fileinfo) == 1
    assert s.fileinfo[0]["sha256"] == "a"*64
    assert s.fileinfo[0]["filename"] == "evil.exe"


def test_parse_aggregates_http_hosts_and_uas(tmp_path):
    rows = [
        {"event_type": "http", "http": {"hostname": "evil.example",
                                         "http_user_agent": "curl/7.0"}},
        {"event_type": "http", "http": {"hostname": "evil.example",
                                         "http_user_agent": "curl/7.0"}},
        {"event_type": "http", "http": {"hostname": "good.example",
                                         "http_user_agent": "Mozilla"}},
    ]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    assert s.http_hosts == {"evil.example": 2, "good.example": 1}
    assert s.http_uas["curl/7.0"] == 2


def test_parse_aggregates_dns_queries(tmp_path):
    """DNS event with query field (type=query or rrname) collected.
    Answers are NOT collected — they'd duplicate via the case's
    DNS-enrichment skill that reads Zeek dns.log."""
    rows = [
        {"event_type": "dns", "dns": {"type": "query",
                                       "rrname": "evil.example"}},
        {"event_type": "dns", "dns": {"type": "answer",
                                       "rrname": "evil.example",
                                       "rdata": "1.2.3.4"}},
    ]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    assert "evil.example" in s.dns_queries


def test_parse_aggregates_tls_sni(tmp_path):
    p = tmp_path / "eve.json"; p.write_text(_eve(
        {"event_type": "tls", "tls": {"sni": "secure.example"}},
        {"event_type": "tls", "tls": {"sni": "secure.example"}},
    ))
    s = parse_eve_json(p, tmp_path / "out")
    assert s.tls_snis == {"secure.example": 2}


def test_parse_aggregates_anomaly_types(tmp_path):
    """Anomaly events surface decode-layer weirdness that isn't
    rule-based — often the most-overlooked signal."""
    rows = [
        {"event_type": "anomaly", "anomaly": {"event": "INVALID_TCP_FLAGS"}},
        {"event_type": "anomaly", "anomaly": {"event": "INVALID_TCP_FLAGS"}},
        {"event_type": "anomaly", "anomaly": {"event": "MALFORMED_DNS"}},
    ]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    assert s.anomaly_types == {"INVALID_TCP_FLAGS": 2, "MALFORMED_DNS": 1}


# ---------------------------------------------------------------------------
# parse_eve_json — counters + caps + defensive
# ---------------------------------------------------------------------------

def test_parse_event_type_counter(tmp_path):
    rows = [
        {"event_type": "alert"} for _ in range(3)
    ] + [
        {"event_type": "flow"} for _ in range(5)
    ] + [
        {"event_type": "dns", "dns": {"type": "query"}} for _ in range(2)
    ]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    assert s.by_event_type == {"alert": 3, "flow": 5, "dns": 2}
    assert s.total_events == 10


def test_parse_respects_max_events_cap(tmp_path):
    rows = [{"event_type": "flow", "src_ip": f"10.0.0.{i % 250}"}
            for i in range(100)]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out", max_events=10)
    assert s.total_events == 10
    assert s.truncated is True


def test_parse_skips_malformed_jsonl_lines(tmp_path):
    """A bad-JSON line mid-file must not abort the parse — drop
    that line and keep going. The Suricata file emitter sometimes
    breaks mid-write on rotation; we recover."""
    content = (
        json.dumps({"event_type": "alert",
                     "alert": {"signature_id": 1, "signature": "A"}}) + "\n"
        + "{this is not valid json\n"
        + json.dumps({"event_type": "alert",
                       "alert": {"signature_id": 2, "signature": "B"}}) + "\n"
    )
    p = tmp_path / "eve.json"; p.write_text(content)
    s = parse_eve_json(p, tmp_path / "out")
    assert s.total_events == 2
    assert len(s.alert_clusters) == 2


def test_parse_missing_file_returns_empty_summary(tmp_path):
    s = parse_eve_json(tmp_path / "absent.json", tmp_path / "out")
    assert s.total_events == 0
    assert s.alert_clusters == []


def test_parse_writes_summary_json(tmp_path):
    """The summary JSON written to disk is the load-bearing
    evidence-chain anchor — analysts re-read it during report
    review. Pin its presence + key fields."""
    p = tmp_path / "eve.json"; p.write_text(_eve(
        {"event_type": "alert",
         "alert": {"signature_id": 1, "signature": "A"}}))
    s = parse_eve_json(p, tmp_path / "out")
    written = json.loads(s.out_path.read_text())
    assert written["total_events"] == 1
    assert written["alert_clusters"][0]["signature_id"] == 1


# ---------------------------------------------------------------------------
# EveSummary.as_evidence — wraps the summary in an EvidenceItem
# ---------------------------------------------------------------------------

def test_evidence_carries_top_signatures(tmp_path):
    rows = (
        [{"event_type": "alert",
          "alert": {"signature_id": 1, "signature": "A"}}] * 3
        + [{"event_type": "alert",
            "alert": {"signature_id": 2, "signature": "B"}}] * 7
    )
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out")
    ev = s.as_evidence()
    facts = ev.extracted_facts
    assert facts["alert_count"] == 10
    assert facts["unique_signatures"] == 2
    # B (count=7) should be top
    assert facts["top_signatures"][0]["sid"] == 2
    assert facts["top_signatures"][0]["count"] == 7
    assert facts["phase"] == "suricata_eve_parse"


def test_evidence_truncation_flag_round_trips(tmp_path):
    rows = [{"event_type": "flow"} for _ in range(20)]
    p = tmp_path / "eve.json"; p.write_text(_eve(*rows))
    s = parse_eve_json(p, tmp_path / "out", max_events=5)
    ev = s.as_evidence()
    assert ev.extracted_facts["truncated"] is True
