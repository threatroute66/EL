"""Skill: Suricata EVE JSON parser.

Suricata writes events to `eve.json` (JSON-Lines, one event per
line). Twelve event types cover most cases — `alert`, `flow`, `dns`,
`http`, `tls`, `ssh`, `fileinfo`, `anomaly`, `netflow`, `stats`,
`drop`, `smb`. EL today only consumes the `alert_count` summary
that `el.skills.network_extra.replay_pcap` produces; the rest of
the events are sitting in the file untouched.

This skill closes that gap. Walks an eve.json file once, classifies
events by type, surfaces high-signal subsets:

  - **Alerts** clustered by signature (signature_id + msg) — the
    same SID firing 100+ times is C2 beaconing / scan / DoS. We
    surface the top-N signatures + their first/last seen times.
  - **FileInfo** events that carried a sha256 (Suricata can extract
    files from HTTP/SMB/FTP streams) — high-signal IOCs we can
    cross-reference against the case's malware-triage tier.
  - **HTTP / DNS / TLS** rollups — host / query / SNI sets that
    feed the existing IOC extractor + cross-case knowledge store.
  - **Anomaly** events — protocol-layer weirdness flagged by
    Suricata's decode engine, often the most under-rated signal
    in EVE because it doesn't depend on rule coverage.

The skill also exposes `is_suricata_eve(path)` for triage so a
standalone eve.json file (operator brings the EVE log without the
source pcap) gets recognised + routed to the same parser.

Caps: 200k events per file by default; counts past the cap stop
being collected but `truncated = True` is recorded. Real-world
SOC tap eve.jsons can reach millions of events; 200k is enough to
characterise the case window without OOM risk.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


@dataclass
class EveAlertCluster:
    """One row per (signature_id, signature) tuple — Suricata's
    natural grouping for "same detection firing N times"."""
    signature_id: int
    signature: str
    severity: int = 3                # 1 = high, 3 = low (Suricata convention)
    category: str = ""
    count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    src_ips: list[str] = field(default_factory=list)    # up to 10 unique
    dest_ips: list[str] = field(default_factory=list)
    dest_ports: list[int] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)  # T-IDs


@dataclass
class EveSummary:
    out_path: Path
    eve_path: Path
    total_events: int = 0
    by_event_type: dict[str, int] = field(default_factory=dict)
    alert_clusters: list[EveAlertCluster] = field(default_factory=list)
    fileinfo: list[dict] = field(default_factory=list)
    http_hosts: dict[str, int] = field(default_factory=dict)
    http_uas: dict[str, int] = field(default_factory=dict)
    dns_queries: dict[str, int] = field(default_factory=dict)
    tls_snis: dict[str, int] = field(default_factory=dict)
    anomaly_types: dict[str, int] = field(default_factory=dict)
    src_ips: dict[str, int] = field(default_factory=dict)
    dest_ips: dict[str, int] = field(default_factory=dict)
    truncated: bool = False

    @property
    def alert_count(self) -> int:
        return self.by_event_type.get("alert", 0)

    @property
    def unique_signatures(self) -> int:
        return len(self.alert_clusters)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = "0" * 64
        try:
            sha = hashlib.sha256(
                self.eve_path.read_bytes()[:4 * 1024 * 1024]
            ).hexdigest()
        except OSError:
            pass
        merged = {
            "total_events": self.total_events,
            "by_event_type": self.by_event_type,
            "alert_count": self.alert_count,
            "unique_signatures": self.unique_signatures,
            "top_signatures": [
                {"sid": c.signature_id, "msg": c.signature, "count": c.count,
                 "severity": c.severity}
                for c in self.alert_clusters[:10]
            ],
            "fileinfo_count": len(self.fileinfo),
            "http_host_count": len(self.http_hosts),
            "dns_query_count": len(self.dns_queries),
            "tls_sni_count": len(self.tls_snis),
            "anomaly_count": sum(self.anomaly_types.values()),
            "src_ip_count": len(self.src_ips),
            "dest_ip_count": len(self.dest_ips),
            "truncated": self.truncated,
            "phase": "suricata_eve_parse",
        }
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="el.suricata_eve", version="0.1.0",
            command=f"parse_eve_json({self.eve_path.name})",
            output_sha256=sha, output_path=str(self.eve_path),
            extracted_facts=merged,
        )


# ---------------------------------------------------------------------------
# Signature detection — for triage
# ---------------------------------------------------------------------------

# Markers that uniquely identify a Suricata EVE row vs other JSONL
# log formats. We require BOTH `"event_type":` (Suricata's canonical
# field) AND one of the canonical event-type values present in the
# first few lines — guards against generic JSONL with an
# `event_type` field that happens to mean something else.
_EVE_TYPES = ("alert", "flow", "dns", "http", "tls", "ssh",
              "fileinfo", "anomaly", "netflow", "stats",
              "drop", "smb")


def is_suricata_eve(path: Path, max_lines: int = 10) -> bool:
    """Read the first `max_lines` of a JSONL-shaped file and look for
    canonical Suricata EVE event markers. Triage uses this to route
    standalone eve.json files to the eve parser."""
    try:
        with Path(path).open("r", errors="ignore") as fh:
            for _ in range(max_lines):
                line = fh.readline()
                if not line:
                    return False
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                et = (obj.get("event_type") or "").lower()
                if et in _EVE_TYPES:
                    return True
    except OSError:
        return False
    return False


# ---------------------------------------------------------------------------
# Parser — walks the file in one pass
# ---------------------------------------------------------------------------

def _coerce_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _update_str_counter(d: dict[str, int], value, cap: int = 1000) -> None:
    if not value:
        return
    s = str(value)[:200]
    if len(d) >= cap and s not in d:
        return
    d[s] = d.get(s, 0) + 1


def parse_eve_json(eve_path: Path, out_dir: Path,
                    max_events: int = 200_000) -> EveSummary:
    """Walk an EVE JSON file and produce an EveSummary. Single
    pass — memory bounded to per-event-type aggregates, not the
    full event list. Returns the summary even on early termination
    (e.g. file truncated mid-line) so the caller can emit findings
    from whatever was successfully read.
    """
    eve_path = Path(eve_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "suricata_eve_summary.json"
    summary = EveSummary(out_path=summary_path, eve_path=eve_path)

    by_type: Counter = Counter()
    # Alert clustering: (sid, msg) → aggregate
    cluster_keys: dict[tuple[int, str], dict] = {}
    fileinfo: list[dict] = []
    anomaly_types: Counter = Counter()

    try:
        fh = eve_path.open("r", errors="ignore")
    except OSError:
        return summary

    try:
        for i, line in enumerate(fh):
            if summary.total_events >= max_events:
                summary.truncated = True
                break
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            summary.total_events += 1
            et = (ev.get("event_type") or "").lower()
            by_type[et] += 1
            _update_str_counter(summary.src_ips, ev.get("src_ip"))
            _update_str_counter(summary.dest_ips, ev.get("dest_ip"))

            if et == "alert":
                a = ev.get("alert") or {}
                sid = _coerce_int(a.get("signature_id")) or 0
                msg = str(a.get("signature") or "")
                key = (sid, msg)
                rec = cluster_keys.get(key)
                if rec is None:
                    rec = {
                        "signature_id": sid, "signature": msg,
                        "severity": _coerce_int(a.get("severity")) or 3,
                        "category": str(a.get("category") or ""),
                        "count": 0,
                        "first_seen": ev.get("timestamp") or "",
                        "last_seen": ev.get("timestamp") or "",
                        "src_ips": set(), "dest_ips": set(),
                        "dest_ports": set(), "attack_techniques": set(),
                    }
                    cluster_keys[key] = rec
                rec["count"] += 1
                ts = ev.get("timestamp")
                if ts:
                    if not rec["first_seen"] or ts < rec["first_seen"]:
                        rec["first_seen"] = ts
                    if not rec["last_seen"] or ts > rec["last_seen"]:
                        rec["last_seen"] = ts
                if (s := ev.get("src_ip")):
                    rec["src_ips"].add(str(s))
                if (d := ev.get("dest_ip")):
                    rec["dest_ips"].add(str(d))
                if (dp := _coerce_int(ev.get("dest_port"))) is not None:
                    rec["dest_ports"].add(dp)
                # ATT&CK technique IDs ride in `metadata.mitre_technique_id`
                # (Suricata's ET ruleset injects them on each rule).
                md = a.get("metadata") or {}
                for k in ("mitre_technique_id",
                          "mitre_attack_technique_id"):
                    for tid in md.get(k, []) or []:
                        rec["attack_techniques"].add(str(tid))
            elif et == "fileinfo":
                f = ev.get("fileinfo") or {}
                sha256 = f.get("sha256") or ""
                if sha256:
                    fileinfo.append({
                        "sha256": sha256,
                        "filename": (f.get("filename") or "")[:200],
                        "magic": (f.get("magic") or "")[:80],
                        "size": _coerce_int(f.get("size")),
                        "stored": bool(f.get("stored")),
                        "src_ip": str(ev.get("src_ip") or ""),
                        "dest_ip": str(ev.get("dest_ip") or ""),
                        "timestamp": ev.get("timestamp") or "",
                    })
            elif et == "http":
                h = ev.get("http") or {}
                _update_str_counter(summary.http_hosts, h.get("hostname"))
                _update_str_counter(summary.http_uas, h.get("http_user_agent"))
            elif et == "dns":
                d = ev.get("dns") or {}
                # Suricata emits both queries + answers under `dns`
                if d.get("type") == "query" or d.get("query") is not None:
                    q = d.get("rrname") or d.get("query")
                    _update_str_counter(summary.dns_queries, q)
            elif et == "tls":
                t = ev.get("tls") or {}
                _update_str_counter(summary.tls_snis, t.get("sni"))
            elif et == "anomaly":
                ay = ev.get("anomaly") or {}
                event = ay.get("event") or ay.get("type") or ""
                if event:
                    anomaly_types[str(event)] += 1
    finally:
        fh.close()

    summary.by_event_type = dict(by_type)
    summary.fileinfo = fileinfo[:200]   # cap on uniques — extracted-file
                                         # count is the load-bearing signal
    summary.anomaly_types = dict(anomaly_types)
    # Project alert clusters into the dataclass list, sorted by count desc
    clusters = sorted(cluster_keys.values(),
                       key=lambda r: (-r["count"], r["signature_id"]))
    summary.alert_clusters = [
        EveAlertCluster(
            signature_id=r["signature_id"],
            signature=r["signature"],
            severity=r["severity"],
            category=r["category"],
            count=r["count"],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            src_ips=sorted(r["src_ips"])[:10],
            dest_ips=sorted(r["dest_ips"])[:10],
            dest_ports=sorted(r["dest_ports"])[:10],
            attack_techniques=sorted(r["attack_techniques"]),
        )
        for r in clusters
    ]

    # Write the on-disk summary so re-renders have a stable evidence file.
    summary_path.write_text(json.dumps({
        "eve_path": str(eve_path),
        "total_events": summary.total_events,
        "by_event_type": summary.by_event_type,
        "alert_clusters": [
            {**vars(c)} for c in summary.alert_clusters[:50]
        ],
        "fileinfo": summary.fileinfo[:50],
        "http_hosts_top": sorted(summary.http_hosts.items(),
                                  key=lambda kv: -kv[1])[:50],
        "http_uas_top": sorted(summary.http_uas.items(),
                                key=lambda kv: -kv[1])[:50],
        "dns_queries_top": sorted(summary.dns_queries.items(),
                                   key=lambda kv: -kv[1])[:50],
        "tls_snis_top": sorted(summary.tls_snis.items(),
                                key=lambda kv: -kv[1])[:50],
        "anomaly_types": summary.anomaly_types,
        "src_ips_top": sorted(summary.src_ips.items(),
                               key=lambda kv: -kv[1])[:50],
        "dest_ips_top": sorted(summary.dest_ips.items(),
                                key=lambda kv: -kv[1])[:50],
        "truncated": summary.truncated,
    }, indent=2, default=str))
    return summary


__all__ = [
    "EveAlertCluster",
    "EveSummary",
    "is_suricata_eve",
    "parse_eve_json",
]
