"""Endpoint Analyst — Velociraptor / EDR collection bundles.

Routes on evidence_kind = 'velociraptor-collection' (set by Triage when it
detects multiple Velociraptor artifact filenames in a directory input).

Emits per-artifact Findings + populates the case graph with Process /
NetworkFlow / IPAddress nodes pulled from Pslist + Netstat artifacts.
"""
from __future__ import annotations

import hashlib

from el.agents.base import Agent, AgentContext
from el.evidence.graph import open_graph
from el.schemas.finding import Finding
from el.skills import velociraptor


def _esc(s: str) -> str:
    return (s or "").replace("'", "''")


class EndpointAnalystAgent(Agent):
    name = "endpoint_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        if ctx.shared.get("evidence_kind") != "velociraptor-collection":
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Endpoint agent does not apply: "
                      f"evidence_kind='{ctx.shared.get('evidence_kind')}'",
            ))]

        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        try:
            s = velociraptor.parse(ctx.input_path, analysis)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Velociraptor parse failed: {e}",
            ))]

        ev = s.as_evidence()
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Velociraptor collection parsed: {len(s.artifact_files)} artifact file(s); "
                   f"{s.process_count} process row(s), {s.netstat_count} netstat row(s), "
                   f"{s.autorun_count} autorun row(s)"),
            evidence=[ev], hypotheses_supported=["H_ENDPOINT_COLLECTION"],
        )))

        if "pslist" in s.parsed:
            out.extend(self._populate_processes(ctx, s.parsed["pslist"], ev))
        if "netstat" in s.parsed:
            out.extend(self._populate_network(ctx, s.parsed["netstat"], ev))
        if "autoruns" in s.parsed and s.autorun_count:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=f"Autoruns artifact present: {s.autorun_count} entries — review for "
                      "unsigned / non-baseline persistence",
                evidence=[ev], hypotheses_supported=["H_PERSISTENCE_SERVICE"],
            )))

        return out

    def _populate_processes(self, ctx, rows, ev) -> list[Finding]:
        out: list[Finding] = []
        try:
            db, conn = open_graph(ctx.case_dir)
            host_field = next((r.get("Hostname") or r.get("ClientId") for r in rows
                                if isinstance(r, dict)), None)
            host = host_field or "endpoint_unknown"
            conn.execute(f"MERGE (:Host {{name: '{_esc(host)}', os: 'windows'}})")
            n = 0
            for row in rows:
                if not isinstance(row, dict):
                    continue
                pid = row.get("Pid") or row.get("PID")
                ppid = row.get("Ppid") or row.get("PPID")
                name = (row.get("Name") or row.get("ImageFileName") or "").lower()
                cmdline = row.get("CommandLine") or row.get("Cmdline") or ""
                if pid is None:
                    continue
                conn.execute(
                    f"MERGE (p:Process {{pid: {int(pid)}}}) "
                    f"SET p.ppid = {int(ppid) if ppid is not None else 0}, "
                    f"p.name = '{_esc(name)}', "
                    f"p.cmdline = '{_esc(cmdline)[:512]}', "
                    f"p.host = '{_esc(host)}'"
                )
                n += 1
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"Populated {n} Process node(s) from Velociraptor Pslist on host '{host}'",
                evidence=[ev],
            )))
        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Process graph population partially failed: {e}",
                evidence=[ev],
            )))
        return out

    def _populate_network(self, ctx, rows, ev) -> list[Finding]:
        out: list[Finding] = []
        suspicious_dports = []
        try:
            db, conn = open_graph(ctx.case_dir)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                raddr = row.get("RemoteAddr") or row.get("Raddr")
                rport = row.get("RemotePort") or row.get("Rport")
                if raddr and ":" not in str(raddr) and not str(raddr).startswith(("0.", "127.")):
                    conn.execute(f"MERGE (:IPAddress {{addr: '{_esc(raddr)}', version: 4}})")
                if rport in (4444, 4445, 1337, 6666, 31337):
                    suspicious_dports.append({"raddr": raddr, "rport": rport})
        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Network graph population partially failed: {e}",
                evidence=[ev],
            )))

        if suspicious_dports:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=f"Velociraptor Netstat: connections to suspicious ports observed: "
                      f"{suspicious_dports[:10]}",
                evidence=[ev],
                hypotheses_supported=["H_C2_OR_REVERSE_SHELL"],
            )))
        return out
