"""Skill: inbound RDP brute-force detection from a vol3 NetScan dump.

The Rocba memory image surfaced this signal in the original case: 113
inbound TCP connection attempts to ``192.168.1.5:3389`` (the host's
public-facing RDP server) from four foreign VPS providers in a
6-minute window, with **3 ESTABLISHED** sessions out of the cluster —
classic password-spray + breach pattern.

The default ``MemoryForensicatorAgent`` already runs
``windows.netscan.NetScan`` and writes the JSONL output; this skill
just walks that file and computes per-source-IP rollups. No new
external dependencies; reads the same JSONL the existing
``netscan_triage.py`` consumes for outbound beacon detection.

Detection criteria
------------------
* Filter to TCP connections with ``LocalPort == 3389``.
* Drop ``LISTENING`` rows (the server-side socket itself, not a
  remote attempt) and any row with no ``ForeignAddr``.
* Drop RFC1918 / link-local source IPs — internal RDP between hosts
  on the same network is the lateral-movement story, handled by
  ``lateral_movement_analyst``. We only score the *external* edge.
* Group by ``ForeignAddr``. For each external source:
    - ``MIN_CLUSTER_CONNECTIONS`` rows ⇒ "brute-force pattern"
    - ANY ``ESTABLISHED`` row in the cluster ⇒ "successful auth"
* Sources below the threshold are returned in ``other_external``
  for the analyst to inspect manually but are NOT scored as brute
  force on their own (one or two probe rows is reconnaissance,
  not a credentialled attack).

Pure-function skill. Returns dataclasses with an ``as_evidence()``
method on the top-level ``RDPBruteForceReport`` so the agent can
embed the JSONL path + sha256 directly into the Finding.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from el.schemas.finding import EvidenceItem


# Tuneables -----------------------------------------------------------------
RDP_PORT = 3389

# A single source-IP needs at least this many connections to local 3389
# to count as a brute-force cluster. Set to 10 to filter idle scan noise
# (a single port-scan probe can produce 1-2 SYN_RCVD/CLOSED rows).
MIN_CLUSTER_CONNECTIONS = 10


# Data shapes ---------------------------------------------------------------

@dataclass
class RDPSourceCluster:
    foreign_ip: str
    total_connections: int
    closed_count: int
    syn_rcvd_count: int
    established_count: int
    other_state_count: int
    earliest_created_utc: str = ""
    latest_created_utc: str = ""
    duration_seconds: float = 0.0

    @property
    def is_breach(self) -> bool:
        """ESTABLISHED ⇒ at least one TCP handshake completed AND the
        Windows side accepted the RDP/CredSSP exchange. That doesn't
        prove successful logon (TLS handshake completes before
        credentials are checked), but it's the strongest in-memory
        signal we have without the Security event log."""
        return self.established_count > 0


@dataclass
class RDPBruteForceReport:
    netscan_path: Path
    inbound_3389_total: int
    external_clusters: list[RDPSourceCluster] = field(default_factory=list)
    breach_clusters: list[RDPSourceCluster] = field(default_factory=list)
    other_external: list[RDPSourceCluster] = field(default_factory=list)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        try:
            sha = hashlib.sha256(self.netscan_path.read_bytes()).hexdigest()
        except OSError:
            sha = ""
        merged = {
            "rdp_port": RDP_PORT,
            "min_cluster_connections": MIN_CLUSTER_CONNECTIONS,
            "inbound_3389_total": self.inbound_3389_total,
            "external_brute_force_clusters": len(self.external_clusters),
            "external_breach_clusters": len(self.breach_clusters),
            "external_other_sources": len(self.other_external),
        }
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="rdp_brute_force",
            version="1",
            command=f"walk(windows.netscan.NetScan.jsonl, port={RDP_PORT})",
            output_sha256=sha,
            output_path=str(self.netscan_path),
            extracted_facts=merged,
        )


# Helpers -------------------------------------------------------------------

def _is_external_ip(addr: str) -> bool:
    """Return True for routable, non-RFC1918 IPv4/IPv6 addresses."""
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _parse_iso(s: str) -> datetime | None:
    if not s:
        return None
    try:
        # vol3 emits "2020-11-16T02:34:58+00:00" form
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _iter_netscan(path: Path):
    """Stream rows from a vol3 jsonl netscan dump. Tolerant of
    blank lines + malformed rows (matches the streaming-mode output
    of ``el.skills.vol3.iter_rows``)."""
    if not path.is_file():
        return
    with path.open("r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# Public entry point --------------------------------------------------------

def analyze_netscan(netscan_path: str | Path) -> RDPBruteForceReport:
    """Walk a vol3 netscan JSONL output and return inbound-RDP rollups.

    Empty/missing input is non-fatal — returns an empty report so
    the caller can decide whether to emit an "insufficient" Finding
    or skip silently."""
    netscan_path = Path(netscan_path)
    rollup: dict[str, dict] = defaultdict(lambda: {
        "total": 0, "closed": 0, "syn_rcvd": 0, "established": 0,
        "other": 0, "earliest": None, "latest": None,
    })
    inbound_total = 0

    for r in _iter_netscan(netscan_path):
        proto = (r.get("Proto") or "").upper()
        if not proto.startswith("TCP"):
            continue
        try:
            local_port = int(r.get("LocalPort") or 0)
        except (TypeError, ValueError):
            continue
        if local_port != RDP_PORT:
            continue
        state = (r.get("State") or "").strip().upper()
        if state in {"LISTENING", ""}:
            # LISTENING is the server socket itself; "" is incomplete pool
            # data we can't classify. Neither is an inbound attempt.
            continue
        foreign = (r.get("ForeignAddr") or "").strip()
        if not foreign:
            continue
        if not _is_external_ip(foreign):
            continue

        inbound_total += 1
        slot = rollup[foreign]
        slot["total"] += 1
        if state == "CLOSED":
            slot["closed"] += 1
        elif state == "SYN_RCVD":
            slot["syn_rcvd"] += 1
        elif state == "ESTABLISHED":
            slot["established"] += 1
        else:
            slot["other"] += 1
        ts = _parse_iso(r.get("Created") or "")
        if ts:
            if slot["earliest"] is None or ts < slot["earliest"]:
                slot["earliest"] = ts
            if slot["latest"] is None or ts > slot["latest"]:
                slot["latest"] = ts

    clusters: list[RDPSourceCluster] = []
    for ip, s in rollup.items():
        earliest = s["earliest"]
        latest = s["latest"]
        duration = (
            (latest - earliest).total_seconds()
            if earliest and latest else 0.0
        )
        clusters.append(RDPSourceCluster(
            foreign_ip=ip,
            total_connections=s["total"],
            closed_count=s["closed"],
            syn_rcvd_count=s["syn_rcvd"],
            established_count=s["established"],
            other_state_count=s["other"],
            earliest_created_utc=earliest.isoformat() if earliest else "",
            latest_created_utc=latest.isoformat() if latest else "",
            duration_seconds=duration,
        ))
    # Sort hot to cool so the Finding's claim text leads with the
    # noisiest source.
    clusters.sort(key=lambda c: (-c.total_connections, c.foreign_ip))

    bf = [c for c in clusters
          if c.total_connections >= MIN_CLUSTER_CONNECTIONS]
    breach = [c for c in bf if c.is_breach]
    other = [c for c in clusters
             if c.total_connections < MIN_CLUSTER_CONNECTIONS]

    return RDPBruteForceReport(
        netscan_path=netscan_path,
        inbound_3389_total=inbound_total,
        external_clusters=bf,
        breach_clusters=breach,
        other_external=other,
    )


__all__ = [
    "MIN_CLUSTER_CONNECTIONS", "RDP_PORT",
    "RDPBruteForceReport", "RDPSourceCluster",
    "analyze_netscan",
]
