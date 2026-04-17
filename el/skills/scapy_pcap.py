"""Skill: pcap parsing via scapy.

Pure Python — no tshark/zeek required. Extracts flow tuples, DNS queries,
HTTP host headers, TLS SNI hints, suspicious-port flags.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


@dataclass
class PcapSummary:
    pcap_path: Path
    summary_path: Path
    packet_count: int
    flows: dict[tuple[str, str, int, int, str], int] = field(default_factory=dict)
    dns_queries: list[str] = field(default_factory=list)
    http_hosts: list[str] = field(default_factory=list)
    tls_sni: list[str] = field(default_factory=list)
    suspicious_dports: Counter = field(default_factory=Counter)

    def as_evidence(self) -> EvidenceItem:
        sha = hashlib.sha256(self.summary_path.read_bytes()).hexdigest()
        return EvidenceItem(
            tool="el.scapy_pcap", version="0.1.0",
            command=f"scapy.rdpcap({self.pcap_path})",
            output_sha256=sha, output_path=str(self.summary_path),
            extracted_facts={
                "packet_count": self.packet_count,
                "flow_count": len(self.flows),
                "dns_query_count": len(self.dns_queries),
                "http_host_count": len(self.http_hosts),
                "tls_sni_count": len(self.tls_sni),
                "unique_dns": sorted(set(self.dns_queries))[:50],
                "unique_hosts": sorted(set(self.http_hosts))[:50],
                "unique_sni": sorted(set(self.tls_sni))[:50],
            },
        )


SUSPICIOUS_PORTS = {4444, 4445, 1337, 6666, 6667, 8888, 9001, 31337, 5555}


def summarize(pcap_path: Path, out_dir: Path) -> PcapSummary:
    out_dir.mkdir(parents=True, exist_ok=True)
    from scapy.all import rdpcap
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    try:
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import TLS_Ext_ServerName
        TLS_OK = True
    except Exception:
        TLS_OK = False

    pkts = rdpcap(str(pcap_path))
    summary = PcapSummary(pcap_path=pcap_path,
                          summary_path=out_dir / "pcap_summary.json",
                          packet_count=len(pkts))

    flows: dict[tuple[str, str, int, int, str], int] = defaultdict(int)
    for p in pkts:
        l3 = p.getlayer(IP) or p.getlayer(IPv6)
        if not l3:
            continue
        proto = "tcp" if p.haslayer(TCP) else "udp" if p.haslayer(UDP) else "other"
        l4 = p.getlayer(TCP) or p.getlayer(UDP)
        if not l4:
            continue
        flows[(l3.src, l3.dst, int(l4.sport), int(l4.dport), proto)] += 1
        if proto in ("tcp", "udp") and int(l4.dport) in SUSPICIOUS_PORTS:
            summary.suspicious_dports[int(l4.dport)] += 1
        if p.haslayer(DNS) and p.haslayer(DNSQR):
            try:
                q = p[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                summary.dns_queries.append(q)
            except Exception:
                pass
        if proto == "tcp" and (int(l4.dport) == 80 or int(l4.sport) == 80):
            payload = bytes(l4.payload)
            if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE"):
                for line in payload.split(b"\r\n"):
                    if line.lower().startswith(b"host:"):
                        summary.http_hosts.append(line.split(b":", 1)[1].strip().decode(errors="ignore"))
        if TLS_OK:
            try:
                from scapy.layers.tls.handshake import TLSClientHello as _CH
                from scapy.layers.tls.extensions import TLS_Ext_ServerName as _SNI
                if p.haslayer(_CH):
                    for ext in p[_CH].ext or []:
                        if isinstance(ext, _SNI):
                            for sn in ext.servernames or []:
                                summary.tls_sni.append(sn.servername.decode(errors="ignore"))
            except Exception:
                pass

    summary.flows = dict(flows)
    serialised = {
        "pcap_path": str(pcap_path),
        "packet_count": summary.packet_count,
        "flow_count": len(summary.flows),
        "flows": [{"src": k[0], "dst": k[1], "sport": k[2], "dport": k[3], "proto": k[4], "packets": v}
                  for k, v in sorted(summary.flows.items(), key=lambda x: -x[1])[:200]],
        "dns_queries": sorted(set(summary.dns_queries)),
        "http_hosts": sorted(set(summary.http_hosts)),
        "tls_sni": sorted(set(summary.tls_sni)),
        "suspicious_dport_hits": dict(summary.suspicious_dports),
    }
    summary.summary_path.write_text(json.dumps(serialised, indent=2))
    return summary
