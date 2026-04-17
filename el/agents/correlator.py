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
                notes.append(f"top destination IPs by flow count: {top_dst}")
                claim = (f"Top destination IP by flows: {top_dst[0]['addr']} "
                         f"({top_dst[0]['flows']} flow(s))")
                out.append(self._emit_correlation(ctx, claim, "medium",
                                                  ["H_C2_OR_REVERSE_SHELL"], report_path))
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

        report_path.write_text("\n".join(notes))

        if not out:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="Correlator ran but no cross-agent overlaps were observed in the graph",
            ))]
        return out

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
