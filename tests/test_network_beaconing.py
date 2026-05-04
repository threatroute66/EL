"""Statistical beaconing skill — unit tests.

Synthetic Zeek conn.log fixtures verify the algorithm scores periodic flows
above the threshold and bursty/random flows below it.
"""
import gzip
import json
from pathlib import Path

import pytest

from el.skills import network_beaconing as bcn


# --- _score_intervals -------------------------------------------------

def test_score_intervals_perfect_periodic():
    """Perfectly regular 60s intervals → score ~ 1.0 on both sub-scores."""
    timestamps = [1000.0 + i * 60 for i in range(20)]
    bs, ts, ds, mean, stdev = bcn._score_intervals(timestamps)
    assert mean == pytest.approx(60.0)
    assert stdev == pytest.approx(0.0, abs=0.01)
    assert ts == pytest.approx(1.0, abs=0.01)
    assert ds == pytest.approx(1.0, abs=0.01)
    assert bs == pytest.approx(1.0, abs=0.01)


def test_score_intervals_high_jitter_low_score():
    """Highly irregular intervals → score should be well below 0.5."""
    # Mix of 1s, 60s, 600s, 3600s gaps — clearly non-beacon-shaped.
    timestamps = [0, 1, 61, 661, 4261, 4262, 4322, 7922, 11522, 15122]
    bs, ts, ds, mean, _ = bcn._score_intervals(timestamps)
    assert bs < 0.5


def test_score_intervals_too_few_returns_zero():
    """Fewer than 5 intervals can't be statistically scored."""
    bs, ts, ds, _, _ = bcn._score_intervals([0, 1, 2, 3])
    assert bs == 0.0


# --- _flow_key extraction ---------------------------------------------

def test_flow_key_normal_row():
    row = {"id.orig_h": "10.0.0.5", "id.resp_h": "1.2.3.4",
           "id.resp_p": "443", "proto": "tcp"}
    assert bcn._flow_key(row) == ("10.0.0.5", "1.2.3.4", 443, "tcp")


def test_flow_key_supports_underscore_form():
    """Some Zeek emitters use id_orig_h instead of id.orig_h."""
    row = {"id_orig_h": "10.0.0.5", "id_resp_h": "1.2.3.4",
           "id_resp_p": "443", "proto": "tcp"}
    assert bcn._flow_key(row) == ("10.0.0.5", "1.2.3.4", 443, "tcp")


def test_flow_key_returns_none_on_missing_ip():
    assert bcn._flow_key({"id.resp_h": "1.2.3.4", "id.resp_p": "443"}) is None


def test_flow_key_returns_none_on_bad_port():
    row = {"id.orig_h": "10.0.0.5", "id.resp_h": "1.2.3.4",
           "id.resp_p": "n/a", "proto": "tcp"}
    assert bcn._flow_key(row) is None


# --- _ts_value extraction ---------------------------------------------

def test_ts_value_parses_float():
    assert bcn._ts_value({"ts": "1700000000.5"}) == 1700000000.5


def test_ts_value_handles_missing_or_dash():
    assert bcn._ts_value({}) is None
    assert bcn._ts_value({"ts": "-"}) is None
    assert bcn._ts_value({"ts": ""}) is None


def test_ts_value_handles_garbage():
    assert bcn._ts_value({"ts": "not-a-number"}) is None


# --- score_conn_log: end-to-end on synthetic TSV ---------------------

def _write_tsv_conn_log(path: Path, rows: list[dict]):
    fields = ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto"]
    lines = ["#fields\t" + "\t".join(fields)]
    for row in rows:
        lines.append("\t".join(str(row.get(f, "-")) for f in fields))
    path.write_text("\n".join(lines) + "\n")


def test_score_conn_log_finds_beaconing_pair(tmp_path):
    rows = []
    # Beacon: 20 connections, evenly spaced 60s apart from .5 to 1.2.3.4:443
    for i in range(20):
        rows.append({"ts": 1000 + i * 60.0, "id.orig_h": "10.0.0.5",
                      "id.resp_h": "1.2.3.4", "id.resp_p": 443, "proto": "tcp"})
    # Noise: 5 random connections from .6 to a different host (below min_conn)
    for i in range(5):
        rows.append({"ts": 1000 + i * 7.0, "id.orig_h": "10.0.0.6",
                      "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp"})
    log = tmp_path / "conn.log"
    _write_tsv_conn_log(log, rows)

    result = bcn.score_conn_log(log)
    assert result.flow_count == 25
    assert len(result.hits) >= 1
    top = result.hits[0]
    assert top.src == "10.0.0.5"
    assert top.dst == "1.2.3.4"
    assert top.score >= 0.85
    assert top.connection_count == 20


def test_score_conn_log_no_hits_for_random_traffic(tmp_path):
    """Bursty/random traffic shouldn't score above the threshold."""
    rows = []
    # 12 highly irregular connections from one client to one server
    times = [1, 2, 5, 100, 105, 130, 700, 702, 1500, 3600, 3700, 7200]
    for ts in times:
        rows.append({"ts": ts, "id.orig_h": "10.0.0.5",
                      "id.resp_h": "1.2.3.4", "id.resp_p": 443, "proto": "tcp"})
    log = tmp_path / "conn.log"
    _write_tsv_conn_log(log, rows)

    result = bcn.score_conn_log(log)
    assert result.flow_count == 12
    assert result.candidate_pairs == 1   # we evaluated this pair
    assert result.hits == []             # but didn't score it


def test_score_conn_log_handles_json_form(tmp_path):
    """Zeek can emit conn.log as JSON-per-line; parser must auto-detect."""
    log = tmp_path / "conn.log"
    rows = []
    for i in range(15):
        rows.append({
            "ts": 1000 + i * 30.0,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "1.2.3.4",
            "id.resp_p": 443,
            "proto": "tcp",
        })
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    result = bcn.score_conn_log(log)
    assert result.flow_count == 15
    assert len(result.hits) == 1


def test_score_conn_log_handles_gzip(tmp_path):
    """Gzip-compressed conn.log.gz should work too."""
    log = tmp_path / "conn.log.gz"
    rows = []
    fields = ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto"]
    body_lines = ["#fields\t" + "\t".join(fields)]
    for i in range(15):
        body_lines.append(
            f"{1000 + i * 30.0}\t10.0.0.5\t1.2.3.4\t443\ttcp"
        )
    with gzip.open(log, "wt") as f:
        f.write("\n".join(body_lines) + "\n")

    result = bcn.score_conn_log(log)
    assert result.flow_count == 15
    assert len(result.hits) == 1


def test_score_conn_log_raises_for_missing_file(tmp_path):
    with pytest.raises(bcn.BeaconingError):
        bcn.score_conn_log(tmp_path / "nope.log")


# --- as_evidence shape -----------------------------------------------

def test_as_evidence_shape(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text("#fields\tts\n")
    hit = bcn.BeaconingHit(
        src="10.0.0.5", dst="1.2.3.4", dport=443, proto="tcp",
        connection_count=20, duration_seconds=1140,
        mean_interval_seconds=60, interval_stdev_seconds=0.5,
        score=0.99, timestamp_score=0.99, dispersion_score=0.99,
    )
    result = bcn.BeaconingResult(
        conn_log_path=log, flow_count=20,
        candidate_pairs=1, hits=[hit], threshold=0.85,
        output_sha256="e" * 64,
    )
    ev = result.as_evidence()
    assert ev.tool == "el.network_beaconing"
    assert ev.output_sha256 == "e" * 64
    assert ev.extracted_facts["beacon_hit_count"] == 1
    assert ev.extracted_facts["top_hits"][0]["score"] == 0.99
