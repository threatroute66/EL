"""Skill: AWS VPC Flow Logs.

AWS VPC Flow Logs capture IP-layer accept/reject records between ENI
pairs. Exported as text with space-separated columns (v2/v3/v4 default
format). Common fields:

  version account-id interface-id srcaddr dstaddr srcport dstport
  protocol packets bytes start end action log-status

V5 adds fields like tcp-flags, region, vpc-id. Our parser anchors on
the positional mapping for the first 13 columns which has been stable
since 2015.

V1 detectors:

1. `detect_denied_inbound_scan` — single external src producing
   ≥N distinct dst-ports of REJECT action. Port-scan shape.
2. `detect_exfil_large_bytes` — outbound flow from internal src to
   external dst with bytes ≥ threshold. Rarely a single flow; we
   aggregate per (internal_src, external_dst) pair.
3. `detect_outbound_admin_port` — outbound flows to external IPs on
   admin ports (22/3389/5985) — bastion-pivot shape.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class VpcFlowHit:
    technique: str
    subtechnique: str = ""
    description: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    top_dests: list[tuple[str, int]] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


_EXFIL_BYTES_THRESHOLD = 10 * 1024 * 1024   # 10 MB per (src, dst) pair
_SCAN_DISTINCT_PORTS_MIN = 20
_ADMIN_PORTS = {"22", "3389", "5985", "5986"}


def _is_internal(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def parse_vpc_flow_log(path: Path) -> list[dict]:
    """Parse a VPC Flow Log (space-separated text). Returns row dicts
    keyed by the standard v2 column names. Silent on unreadable /
    malformed lines."""
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return []

    cols_v2 = ("version", "account_id", "interface_id", "srcaddr",
                "dstaddr", "srcport", "dstport", "protocol", "packets",
                "bytes", "start", "end", "action", "log_status")

    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < len(cols_v2):
            continue
        row = {cols_v2[i]: parts[i] for i in range(len(cols_v2))}
        rows.append(row)
    return rows


def _ts(row: dict) -> str:
    return str(row.get("end") or row.get("start") or "")


def detect_denied_inbound_scan(rows: list[dict]) -> list[VpcFlowHit]:
    by_src: dict[str, set[str]] = defaultdict(set)
    count_by_src: dict[str, int] = defaultdict(int)
    rows_by_src: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if (r.get("action") or "").upper() != "REJECT":
            continue
        src = str(r.get("srcaddr") or "").strip()
        dport = str(r.get("dstport") or "").strip()
        if not src or not dport:
            continue
        if _is_internal(src):
            continue
        by_src[src].add(dport)
        count_by_src[src] += 1
        rows_by_src[src].append(r)

    flagged = [(s, len(ports)) for s, ports in by_src.items()
               if len(ports) >= _SCAN_DISTINCT_PORTS_MIN]
    if not flagged:
        return []
    flagged.sort(key=lambda kv: -kv[1])
    stamps = sorted(_ts(r) for s, _ in flagged
                    for r in rows_by_src[s] if _ts(r))
    return [VpcFlowHit(
        technique="denied_inbound_scan",
        subtechnique="external_source_multi_port_reject",
        description=(f"AWS VPC Flow: {len(flagged)} external "
                     f"source IP(s) each REJECTED on "
                     f"≥{_SCAN_DISTINCT_PORTS_MIN} distinct "
                     f"destination port(s). Port-scan / recon shape. "
                     f"Top: {flagged[0][0]} × {flagged[0][1]} ports."),
        event_count=sum(count_by_src[s] for s, _ in flagged),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_sources=flagged[:10],
        attack=[("T1046", "Network Service Discovery")],
    )]


def detect_exfil_large_bytes(rows: list[dict]) -> list[VpcFlowHit]:
    pair_bytes: dict[tuple[str, str], int] = defaultdict(int)
    pair_rows: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        if (r.get("action") or "").upper() != "ACCEPT":
            continue
        src = str(r.get("srcaddr") or "")
        dst = str(r.get("dstaddr") or "")
        if not (src and dst):
            continue
        if not _is_internal(src) or _is_internal(dst):
            continue          # outbound only
        try:
            b = int(r.get("bytes") or 0)
        except (TypeError, ValueError):
            continue
        pair_bytes[(src, dst)] += b
        pair_rows[(src, dst)].append(r)

    flagged = [((s, d), b) for (s, d), b in pair_bytes.items()
               if b >= _EXFIL_BYTES_THRESHOLD]
    if not flagged:
        return []
    flagged.sort(key=lambda kv: -kv[1])
    stamps = sorted(_ts(r) for pair, _ in flagged
                    for r in pair_rows[pair] if _ts(r))
    top = [(f"{s}→{d}", b) for (s, d), b in flagged[:10]]
    return [VpcFlowHit(
        technique="exfil_large_bytes",
        subtechnique="internal_to_external_bulk_upload",
        description=(f"AWS VPC Flow: {len(flagged)} "
                     f"(internal→external) flow pair(s) each "
                     f"transferred ≥{_EXFIL_BYTES_THRESHOLD // (1024*1024)} MB. "
                     f"Data-exfiltration shape. Top: "
                     f"{flagged[0][0][0]} → {flagged[0][0][1]} "
                     f"({flagged[0][1]:,} bytes)."),
        event_count=sum(len(pair_rows[p]) for p, _ in flagged),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_dests=top,
        attack=[("T1041", "Exfiltration Over C2 Channel"),
                ("T1567", "Exfiltration Over Web Service")],
    )]


def detect_outbound_admin_port(rows: list[dict]) -> list[VpcFlowHit]:
    hits = []
    for r in rows:
        if (r.get("action") or "").upper() != "ACCEPT":
            continue
        src = str(r.get("srcaddr") or "")
        dst = str(r.get("dstaddr") or "")
        if not (src and dst):
            continue
        if not _is_internal(src) or _is_internal(dst):
            continue
        dport = str(r.get("dstport") or "")
        if dport in _ADMIN_PORTS:
            hits.append(r)
    if not hits:
        return []
    by_pair: Counter = Counter((r.get("srcaddr", ""), r.get("dstaddr", ""),
                                  r.get("dstport", "")) for r in hits)
    stamps = sorted(_ts(r) for r in hits if _ts(r))
    top = [(f"{s} → {d}:{p}", n) for (s, d, p), n in by_pair.most_common(10)]
    return [VpcFlowHit(
        technique="outbound_admin_port",
        subtechnique="internal_to_external_ssh_rdp_winrm",
        description=(f"AWS VPC Flow: {len(hits)} ACCEPT flow(s) from "
                     f"internal source to EXTERNAL destination on an "
                     f"admin port (SSH/RDP/WinRM). Bastion-pivot or "
                     f"attacker-controlled external jump host."),
        event_count=len(hits),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_dests=top,
        attack=[("T1021", "Remote Services")],
    )]


ALL_DETECTORS = (
    detect_denied_inbound_scan,
    detect_exfil_large_bytes,
    detect_outbound_admin_port,
)


def run_all(path: Path) -> tuple[int, list[VpcFlowHit]]:
    rows = parse_vpc_flow_log(path)
    if not rows:
        return 0, []
    hits: list[VpcFlowHit] = []
    for fn in ALL_DETECTORS:
        hits.extend(fn(rows))
    return len(rows), hits


def looks_like_vpc_flow_log(sample: bytes) -> bool:
    """First non-comment line should look like a v2 flow log row.
    Header detection: the column-header line starts with 'version' or
    'account-id'. Data row check: starts with the version number (2,
    3, or 4) and has ≥14 whitespace-separated tokens."""
    lines = sample.splitlines()
    for line in lines[:5]:
        decoded = line.decode("utf-8", errors="ignore").strip()
        if not decoded or decoded.startswith("#"):
            continue
        parts = decoded.split()
        if parts and parts[0] in ("version", "2", "3", "4") and len(parts) >= 13:
            return True
    return False


__all__ = [
    "VpcFlowHit",
    "parse_vpc_flow_log", "run_all", "looks_like_vpc_flow_log",
    "detect_denied_inbound_scan",
    "detect_exfil_large_bytes",
    "detect_outbound_admin_port",
    "ALL_DETECTORS",
]
