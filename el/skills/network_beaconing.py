"""Statistical beaconing detection over Zeek conn.log.

Implements a lightweight version of the RITA / AC-Hunter beaconing algorithm
(Hill & Bestard et al., Active Countermeasures, 2018-2024) directly in Python
rather than wrapping the rita CLI. Rationale (per docs/enhancement_proposals.md
Tier 2.3 pivot): RITA v5 requires Docker + ClickHouse + Ansible deployment,
which is operationally impractical for per-case forensic analysis. The
algorithm itself is published research and ~150 lines of Python.

Scoring (from the RITA paper):
  timestamp_score = 1 - (mad_intervals / mean_interval)   # how regular?
  dispersion_score = 1 - (sigma_intervals / mean_interval) # how tight?
  beacon_score    = mean(timestamp_score, dispersion_score) clamped [0..1]

A beacon_score >= 0.85 with sufficient connections per pair (>= 10 for the
sliding scan window) is the operational threshold AC-Hunter publishes.

Inputs: a Zeek conn.log (TSV or JSON form) — produced by ``el.skills.zeek``.
Outputs: per-(src,dst,dport,proto) BeaconingHit records with score + interval
metadata, ready for emission as Findings.

This is NOT a full RITA/AC-Hunter port — it deliberately implements only the
beaconing axis (not long-conn / DNS-tunnel / threat-feed checking, which EL
already covers via network_anomaly + zeek). Beaconing is the gap that
strengthens H_C2_BEACONING beyond the current heuristic-port detector.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from el.schemas.finding import EvidenceItem


class BeaconingError(Exception):
    pass


@dataclass
class BeaconingHit:
    """A flow tuple with beacon-shaped inter-arrival timing."""
    src: str
    dst: str
    dport: int
    proto: str
    connection_count: int
    duration_seconds: float
    mean_interval_seconds: float
    interval_stdev_seconds: float
    score: float
    timestamp_score: float
    dispersion_score: float
    sample_intervals: list[float] = field(default_factory=list)


@dataclass
class BeaconingResult:
    conn_log_path: Path
    flow_count: int
    candidate_pairs: int
    hits: list[BeaconingHit]
    threshold: float
    output_sha256: str = ""
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        # Build a compact summary of the top hits for the evidence record.
        top_hit_summary = [
            {
                "src": h.src, "dst": h.dst, "dport": h.dport,
                "proto": h.proto, "score": round(h.score, 3),
                "connections": h.connection_count,
                "mean_interval_s": round(h.mean_interval_seconds, 2),
            }
            for h in sorted(self.hits, key=lambda x: -x.score)[:10]
        ]
        return EvidenceItem(
            tool="el.network_beaconing",
            version="0.1.0",
            command=f"score_conn_log({self.conn_log_path.name}, "
                     f"threshold={self.threshold})",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.conn_log_path),
            extracted_facts={
                "flow_count_total": self.flow_count,
                "candidate_pair_count": self.candidate_pairs,
                "beacon_hit_count": len(self.hits),
                "score_threshold": self.threshold,
                "top_hits": top_hit_summary,
                "note": self.note,
                **extra,
            },
        )


def _open_maybe_gz(path: Path):
    """Open a Zeek log that may be gzip-compressed."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _iter_conn_log_tsv(path: Path) -> Iterator[dict]:
    """Yield row dicts from a Zeek TSV conn.log.

    Zeek TSV has a `#fields` header line that names the columns. We use it
    to build a dict per row. Empty values appear as ``-``; we leave them as
    strings — callers cast.
    """
    fields: list[str] = []
    with _open_maybe_gz(path) as f:
        for line in f:
            if line.startswith("#fields"):
                # `#fields\tcol1\tcol2\t...`
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not fields:
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != len(fields):
                continue
            yield dict(zip(fields, parts))


def _iter_conn_log_json(path: Path) -> Iterator[dict]:
    """Yield row dicts from a Zeek JSON conn.log (one JSON object per line)."""
    with _open_maybe_gz(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _iter_conn_rows(conn_log: Path) -> Iterator[dict]:
    """Auto-detect TSV vs JSON form of conn.log."""
    if not conn_log.is_file():
        raise BeaconingError(f"conn.log not found: {conn_log}")
    # Peek the first non-comment line.
    with _open_maybe_gz(conn_log) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if line.startswith("{"):
                yield from _iter_conn_log_json(conn_log)
            else:
                yield from _iter_conn_log_tsv(conn_log)
            return


def _ts_value(row: dict) -> float | None:
    """Extract Zeek's connection start timestamp ('ts' field) as float seconds."""
    ts = row.get("ts")
    if ts in (None, "", "-"):
        return None
    try:
        return float(ts)
    except (TypeError, ValueError):
        return None


def _flow_key(row: dict) -> tuple[str, str, int, str] | None:
    src = row.get("id.orig_h") or row.get("id_orig_h") or ""
    dst = row.get("id.resp_h") or row.get("id_resp_h") or ""
    proto = row.get("proto") or ""
    dport_raw = row.get("id.resp_p") or row.get("id_resp_p") or ""
    if not src or not dst:
        return None
    try:
        dport = int(dport_raw)
    except (TypeError, ValueError):
        return None
    return (src, dst, dport, proto)


def _score_intervals(timestamps: list[float]) -> tuple[float, float, float, float, float]:
    """Compute (beacon_score, ts_score, disp_score, mean_interval, stdev_interval).

    Beacon score follows the RITA paper's mean(ts_score, disp_score) approach.
    Both subscores are clamped to [0, 1] — perfectly periodic flows score 1.0.
    """
    intervals = sorted(b - a for a, b in zip(timestamps[:-1], timestamps[1:]))
    if len(intervals) < 5:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    mean_interval = statistics.fmean(intervals)
    if mean_interval <= 0:
        return 0.0, 0.0, 0.0, mean_interval, 0.0
    # MAD (median absolute deviation) — what the RITA paper uses for ts_score.
    median_interval = statistics.median(intervals)
    mad = statistics.fmean(abs(x - median_interval) for x in intervals)
    ts_score = max(0.0, min(1.0, 1.0 - (mad / mean_interval)))
    # Standard deviation for dispersion.
    try:
        stdev = statistics.stdev(intervals)
    except statistics.StatisticsError:
        stdev = 0.0
    disp_score = max(0.0, min(1.0, 1.0 - (stdev / mean_interval)))
    beacon_score = (ts_score + disp_score) / 2.0
    return beacon_score, ts_score, disp_score, mean_interval, stdev


def score_conn_log(
    conn_log: Path,
    *,
    threshold: float = 0.85,
    min_connections: int = 10,
    max_pairs: int = 50000,
) -> BeaconingResult:
    """Score every (src,dst,dport,proto) tuple in *conn_log* for beacon shape.

    Args:
        conn_log: Zeek conn.log (TSV or JSON, optionally gzip-compressed).
        threshold: minimum beacon_score for a hit to be retained.
        min_connections: minimum number of connections per tuple required to
            score it. Below 5 timing pairs we'd have no statistical power.
        max_pairs: hard cap to bound memory on extremely large logs.
    """
    conn_log = Path(conn_log)

    flow_timestamps: dict[tuple, list[float]] = {}
    flow_count = 0
    for row in _iter_conn_rows(conn_log):
        flow_count += 1
        key = _flow_key(row)
        if key is None:
            continue
        ts = _ts_value(row)
        if ts is None:
            continue
        flow_timestamps.setdefault(key, []).append(ts)
        if len(flow_timestamps) > max_pairs:
            break

    candidate_count = 0
    hits: list[BeaconingHit] = []
    for (src, dst, dport, proto), timestamps in flow_timestamps.items():
        if len(timestamps) < min_connections:
            continue
        candidate_count += 1
        timestamps.sort()
        beacon_score, ts_score, disp_score, mean_int, stdev_int = \
            _score_intervals(timestamps)
        if beacon_score < threshold:
            continue
        intervals = [b - a for a, b in zip(timestamps[:-1], timestamps[1:])]
        hits.append(BeaconingHit(
            src=src, dst=dst, dport=dport, proto=proto,
            connection_count=len(timestamps),
            duration_seconds=max(0.0, timestamps[-1] - timestamps[0]),
            mean_interval_seconds=mean_int,
            interval_stdev_seconds=stdev_int,
            score=beacon_score,
            timestamp_score=ts_score,
            dispersion_score=disp_score,
            sample_intervals=[round(i, 2) for i in intervals[:10]],
        ))

    sha = ""
    if conn_log.is_file():
        h = hashlib.sha256()
        with _open_maybe_gz(conn_log) as f:
            for chunk in iter(lambda: f.read(65536), ""):
                h.update(chunk.encode("utf-8", errors="ignore"))
        sha = h.hexdigest()

    return BeaconingResult(
        conn_log_path=conn_log,
        flow_count=flow_count,
        candidate_pairs=candidate_count,
        hits=sorted(hits, key=lambda h: -h.score),
        threshold=threshold,
        output_sha256=sha,
        note=("Algorithmic implementation inspired by RITA / AC-Hunter "
              "(Hill & Bestard, Active Countermeasures). Not a rita-CLI "
              "wrapper — RITA v5 requires Docker + ClickHouse, which is "
              "impractical for per-case forensic analysis."),
    )
