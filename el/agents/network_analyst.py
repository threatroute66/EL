"""Network Analyst — pcap triage via scapy.

Pure Python; no system tools required. Populates the case graph with
NetworkFlow / IPAddress / Domain nodes so cross-agent correlation works.
"""
from __future__ import annotations

import hashlib

from el.agents.base import Agent, AgentContext
from el.evidence.graph import open_graph
from el.schemas.finding import Finding
from el.skills import scapy_pcap


def _esc(s: str) -> str:
    return s.replace("'", "''")


class NetworkAnalystAgent(Agent):
    name = "network_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        kind = ctx.shared.get("evidence_kind") or ""
        if "pcap" not in kind:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Network agent does not apply: evidence_kind='{kind}'",
            ))]

        try:
            s = scapy_pcap.summarize(ctx.input_path, analysis)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"pcap parse failed: {e}",
            ))]

        ev = s.as_evidence()
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"Parsed {s.packet_count} packets across {len(s.flows)} unique flows; "
                  f"{len(set(s.dns_queries))} DNS query name(s), "
                  f"{len(set(s.http_hosts))} HTTP Host header(s), "
                  f"{len(set(s.tls_sni))} TLS SNI(s)",
            evidence=[ev], hypotheses_supported=["H_NETWORK_TRAFFIC_OBSERVED"],
        )))

        if s.suspicious_dports:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=f"Connections observed to suspicious destination ports: "
                      f"{dict(s.suspicious_dports)}",
                evidence=[ev], hypotheses_supported=["H_C2_OR_REVERSE_SHELL"],
            )))

        try:
            db, conn = open_graph(ctx.case_dir)
            for ip in {f[0] for f in s.flows} | {f[1] for f in s.flows}:
                conn.execute(f"MERGE (:IPAddress {{addr: '{_esc(ip)}', version: {6 if ':' in ip else 4}}})")
            for q in set(s.dns_queries):
                conn.execute(f"MERGE (:Domain {{name: '{_esc(q.lower())}'}})")
            for sni in set(s.tls_sni):
                conn.execute(f"MERGE (:Domain {{name: '{_esc(sni.lower())}'}})")
            for (src, dst, sport, dport, proto), packets in s.flows.items():
                fid = hashlib.sha256(f"{src}|{dst}|{sport}|{dport}|{proto}".encode()).hexdigest()[:16]
                conn.execute(
                    f"MERGE (f:NetworkFlow {{flow_id: '{fid}'}}) "
                    f"SET f.src='{_esc(src)}', f.dst='{_esc(dst)}', "
                    f"f.sport={sport}, f.dport={dport}, f.proto='{proto}', f.bytes={packets}"
                )
                conn.execute(f"MATCH (f:NetworkFlow {{flow_id:'{fid}'}}), (i:IPAddress {{addr:'{_esc(src)}'}}) MERGE (f)-[:FLOW_SRC]->(i)")
                conn.execute(f"MATCH (f:NetworkFlow {{flow_id:'{fid}'}}), (i:IPAddress {{addr:'{_esc(dst)}'}}) MERGE (f)-[:FLOW_DST]->(i)")
        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Graph population partially failed: {e}", evidence=[ev],
            )))

        return out
