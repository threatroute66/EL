"""Log Analyst — EVTX parsing via EvtxECmd, generic regex log scan.

Routes on evidence_kind. EVTX → EvtxECmd; otherwise emits insufficient
with a clear note explaining what would unlock the agent.
"""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import ezt


HIGH_VALUE_EIDS = {
    4624: "logon",
    4625: "logon_failed",
    4672: "special_privileges",
    4688: "process_creation",
    4697: "service_install",
    4698: "scheduled_task",
    4720: "user_created",
    4732: "added_to_local_group",
    4769: "kerberos_tgs",
    4776: "ntlm_auth",
    7045: "service_install_legacy",
    1102: "audit_log_cleared",
}


class LogAnalystAgent(Agent):
    name = "log_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        kind = ctx.shared.get("evidence_kind") or ""
        if "EVTX" not in kind:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Log agent does not apply: evidence_kind='{kind}' "
                      "(currently only EVTX inputs are wired)",
            ))]

        try:
            run = ezt.run_evtxecmd(ctx.input_path, analysis, timeout=1800)
        except ezt.EztError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"EvtxECmd unavailable or failed: {e}",
            ))]

        ev = run.as_evidence({"phase": "evtx_parse"})
        if run.rc != 0:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"EvtxECmd returned rc={run.rc}; see {run.stderr_path.name}",
            ))]

        csv_path = analysis / "evtx_parsed.csv"
        if not csv_path.exists() or csv_path.stat().st_size == 0:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="EvtxECmd ran but produced no parsed CSV output",
            ))]

        eid_counts: Counter = Counter()
        try:
            with csv_path.open() as f:
                rd = csv.DictReader(f)
                for row in rd:
                    try:
                        eid_counts[int(row.get("EventId") or row.get("EventID") or 0)] += 1
                    except (TypeError, ValueError):
                        continue
        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Could not iterate parsed EVTX CSV: {e}", evidence=[ev],
            )))
            return out

        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"EvtxECmd parsed {sum(eid_counts.values())} event(s) into {csv_path.name}",
            evidence=[ev], hypotheses_supported=["H_LOGS_AVAILABLE"],
        )))

        for eid, label in HIGH_VALUE_EIDS.items():
            n = eid_counts.get(eid, 0)
            if n == 0:
                continue
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"Event ID {eid} ({label}) observed {n} time(s)",
                evidence=[ev],
                hypotheses_supported=[f"H_EID_{eid}"],
            )))
        return out
