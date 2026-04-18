"""Network Analyst — pcap triage via scapy.

Pure Python; no system tools required. Populates the case graph with
NetworkFlow / IPAddress / Domain nodes so cross-agent correlation works.
"""
from __future__ import annotations

import hashlib

from el.agents.base import Agent, AgentContext
from el.evidence.graph import open_graph
from el.schemas.finding import Finding
from el.skills import network_extra as nx, scapy_pcap


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

        # Suricata IDS: replay the pcap with the system ruleset and surface
        # named alerts. Falls back silently if Suricata isn't installed.
        out.extend(self._run_suricata(ctx, analysis))
        return out

    def _run_suricata(self, ctx: AgentContext, analysis) -> list[Finding]:
        out: list[Finding] = []
        try:
            r = nx.replay_pcap(ctx.input_path, analysis / "suricata", timeout=1800)
        except nx.SuricataError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Suricata unavailable or failed: {e}",
            )))
            return out
        if r.alert_count == 0:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim="Suricata replay: 0 alerts — neither corroborates nor refutes "
                      "(rules may not cover the traffic, or capture has no malicious flows)",
                evidence=[r.as_evidence()],
            )))
            return out
        # Pick out malware-family signatures and classify
        tags: list[str] = []
        for sig, _ in r.sig_hits.items():
            sl = sig.lower()
            if any(fam in sl for fam in ("trojan", "trickbot", "qakbot", "emotet",
                                          "hancitor", "icedid", "bazarloader",
                                          "remcos", "njrat", "ransomware",
                                          "cobalt strike", "meterpreter", "metasploit")):
                tags.append("H_C2_OR_REVERSE_SHELL")
                tags.append("H_OPPORTUNISTIC_COMMODITY")
            if "exploit" in sl or "et exploit" in sl:
                tags.append("H_C2_OR_REVERSE_SHELL")
            if "scan" in sl or "policy" in sl:
                pass  # don't lift on policy / scan noise
        tags = sorted(set(tags))
        top = ", ".join(s for s, _ in
                        sorted(r.sig_hits.items(), key=lambda kv: -kv[1])[:3])
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Suricata IDS: {r.alert_count} alert(s) across "
                   f"{len(r.sig_hits)} unique signature(s). Top: {top}"),
            evidence=[r.as_evidence()],
            hypotheses_supported=tags,
        )))
        return out
