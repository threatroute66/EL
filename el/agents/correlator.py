"""Correlator — cross-agent graph queries.

Queries the per-case Kùzu graph for entities (IPs, domains, processes,
files) that are touched by more than one investigation lane. Emits
'correlation' Findings — observations that no single agent would have
made on its own, only the join.

Locard's exchange principle in action: every contact leaves a trace; the
graph is where traces meet.
"""
from __future__ import annotations

from el.agents.base import Agent, AgentContext
from el.evidence.graph import open_graph
from el.schemas.finding import EvidenceItem, Finding


# RFC1918 / loopback / link-local / multicast prefixes — any IP starting
# with one of these is an internal or non-routable address. We keep them
# in a separate top-destination line so the analyst sees them without
# letting an internal victim host bury the real C2 destination.
_INTERNAL_IPV4_PREFIXES = (
    "10.",
    "127.",
    "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "224.",           # multicast
    "255.",           # broadcast
    "0.",             # 0.0.0.0/8
)


def _is_internal_ipv4(addr: str) -> bool:
    return any(addr.startswith(p) for p in _INTERNAL_IPV4_PREFIXES)


class CorrelatorAgent(Agent):
    name = "correlator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        try:
            db, conn = open_graph(ctx.case_dir)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Cannot open case graph: {e}",
            ))]

        ev_path = ctx.case_dir / "analysis" / self.name
        ev_path.mkdir(parents=True, exist_ok=True)
        report_path = ev_path / "correlation.json"
        notes: list[str] = []

        try:
            r = conn.execute(
                "MATCH (i:IPAddress)<-[:FLOW_DST]-(f:NetworkFlow) "
                "RETURN i.addr AS addr, count(f) AS hits ORDER BY hits DESC LIMIT 20"
            )
            top_dst = []
            while r.has_next():
                row = r.get_next()
                top_dst.append({"addr": row[0], "flows": row[1]})
            if top_dst:
                # Split internal (RFC1918/loopback/link-local/multicast) from
                # external. On a typical pcap the "top destination by flows"
                # is an RFC1918 victim host receiving response traffic — if
                # we report that as THE top destination, the real external
                # C2 gets buried. Surface both: external first (what the
                # analyst usually wants), then internal as secondary. See
                # batch-1 corpus signal: 18/18 cases had an RFC1918 at the
                # top before this split.
                external = [d for d in top_dst if not _is_internal_ipv4(d["addr"])]
                internal = [d for d in top_dst if _is_internal_ipv4(d["addr"])]

                notes.append(f"top destination IPs by flow count: {top_dst}")

                if external:
                    claim = (f"Top external destination IP by flows: "
                             f"{external[0]['addr']} ({external[0]['flows']} flow(s))")
                    if internal:
                        claim += (f". Internal top: {internal[0]['addr']} "
                                  f"({internal[0]['flows']} flow(s)) — likely "
                                  f"the victim host receiving response traffic")
                    out.append(self._emit_correlation(
                        ctx, claim, "medium", [], report_path))
                elif internal:
                    # Pcap contained only internal traffic — note it but
                    # don't pretend we found a C2 destination.
                    claim = (f"All observed destination IPs are internal "
                             f"(RFC1918 / loopback). Top: "
                             f"{internal[0]['addr']} "
                             f"({internal[0]['flows']} flow(s)). No external "
                             f"destination surfaced from flows.")
                    out.append(self._emit_correlation(
                        ctx, claim, "low", [], report_path))
        except Exception as e:
            notes.append(f"top-dst query failed: {e}")

        try:
            r = conn.execute(
                "MATCH (h:Host)<-[:RUNS_ON]-(p:Process), (h2:Host)<-[:RUNS_ON]-(p2:Process) "
                "WHERE h.name <> h2.name AND p.name = p2.name "
                "RETURN p.name AS proc, h.name AS h1, h2.name AS h2 LIMIT 20"
            )
            shared_procs = []
            while r.has_next():
                row = r.get_next()
                shared_procs.append({"process": row[0], "host_a": row[1], "host_b": row[2]})
            if shared_procs:
                notes.append(f"processes seen across multiple hosts: {len(shared_procs)} pair(s)")
                claim = f"Same process name observed on multiple hosts: {shared_procs[0]['process']}"
                out.append(self._emit_correlation(ctx, claim, "medium",
                                                  ["H_LATERAL_MOVEMENT"], report_path))
        except Exception as e:
            notes.append(f"cross-host process query failed: {e}")

        try:
            r = conn.execute("MATCH (d:Domain) RETURN count(d) AS n")
            n_dom = r.get_next()[0] if r.has_next() else 0
            r = conn.execute("MATCH (i:IPAddress) RETURN count(i) AS n")
            n_ip = r.get_next()[0] if r.has_next() else 0
            r = conn.execute("MATCH (p:Process) RETURN count(p) AS n")
            n_proc = r.get_next()[0] if r.has_next() else 0
            notes.append(f"graph entity counts: domains={n_dom} ips={n_ip} processes={n_proc}")
            if n_dom + n_ip + n_proc > 0:
                out.append(self._emit_correlation(
                    ctx,
                    f"Graph populated with {n_dom} domain(s), {n_ip} IP(s), {n_proc} process(es) "
                    "across all investigators",
                    "high", [], report_path,
                ))
        except Exception as e:
            notes.append(f"entity count query failed: {e}")

        # Case-local DNS cross-reference enrichment. Builds an index
        # of (domain ↔ IP) from the case's own Zeek dns.log (if
        # NetworkAnalyst ran) and writes RESOLVED_TO edges into the
        # graph for the pairs it learned. Air-gap-safe — no external
        # resolver is queried.
        try:
            from el.skills.dns_enrichment import build_case_index
            idx = build_case_index(ctx.case_dir)
            if idx.record_count > 0:
                edges_written = self._write_resolved_to_edges(conn, idx)
                top_pairs = []
                # Surface the busiest IPs (most domains pointing at them)
                # in the finding's claim so the analyst sees a digestible
                # sample, not a 500-row dump.
                ip_breadth = sorted(
                    idx.ip_to_domains.items(),
                    key=lambda kv: -len(kv[1]))[:5]
                for ip, doms in ip_breadth:
                    top_pairs.append(
                        f"{ip} ← {', '.join(sorted(doms)[:3])}"
                        f"{' …' if len(doms) > 3 else ''}")
                notes.append(
                    f"dns enrichment: {idx.record_count} answer(s) from "
                    f"{len(idx.source_files)} zeek log(s); "
                    f"{edges_written} RESOLVED_TO edge(s) written")
                out.append(self._emit_correlation(
                    ctx,
                    f"DNS cross-reference (case-local): "
                    f"{len(idx.ip_to_domains)} IP(s) ↔ "
                    f"{len(idx.domain_to_ips)} domain(s) from "
                    f"{len(idx.source_files)} Zeek log(s). Top by "
                    f"breadth: {'; '.join(top_pairs)}",
                    "medium", [], report_path,
                ))
        except Exception as e:
            notes.append(f"dns enrichment failed: {e}")

        report_path.write_text("\n".join(notes))

        if not out:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="Correlator ran but no cross-agent overlaps were observed in the graph",
            ))]
        return out

    def _write_resolved_to_edges(self, conn,
                                   idx: "DnsIndex") -> int:
        """Persist the case-local DNS index into the Kùzu graph via
        RESOLVED_TO edges (Domain → IPAddress, already in the schema).
        MERGE keeps the writes idempotent across re-investigations.
        Returns the number of edges materialised.

        Single-quote escaping is the only injection vector here — the
        index values come from EL's own Zeek output, but a malicious
        pcap could try to smuggle a single quote into a TXT-record-
        shaped DNS answer. Escape defensively."""
        def _esc(s: str) -> str:
            return (s or "").replace("'", "''").replace("\\", "\\\\")
        written = 0
        for domain, ips in idx.domain_to_ips.items():
            try:
                conn.execute(
                    f"MERGE (:Domain {{name: '{_esc(domain)}'}})")
            except Exception:
                continue
            for ip in ips:
                version = 6 if ":" in ip else 4
                try:
                    conn.execute(
                        f"MERGE (:IPAddress "
                        f"{{addr: '{_esc(ip)}', version: {version}}})")
                    conn.execute(
                        f"MATCH (d:Domain {{name: '{_esc(domain)}'}}), "
                        f"      (i:IPAddress {{addr: '{_esc(ip)}'}}) "
                        f"MERGE (d)-[:RESOLVED_TO]->(i)")
                    written += 1
                except Exception:
                    continue
        return written

    def _emit_correlation(self, ctx: AgentContext, claim: str, confidence: str,
                          hyps: list[str], report_path) -> Finding:
        import hashlib
        try:
            sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
        except Exception:
            sha = "0" * 64
        ev = EvidenceItem(
            tool="el.correlator", version="0.1.0",
            command="kuzu cypher graph queries",
            output_sha256=sha, output_path=str(report_path),
        )
        return self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            claim=claim, confidence=confidence,
            evidence=[ev], hypotheses_supported=hyps,
        ))
