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
from el.skills import ezt, hayabusa as hb


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

        # Hayabusa: Sigma rules → named ATT&CK techniques. Lifts LogAnalyst
        # from "we counted EIDs" to "we matched named TTPs". Falls back
        # silently if hayabusa isn't installed.
        out.extend(self._run_hayabusa(ctx, ctx.input_path, analysis))
        return out

    def _run_hayabusa(self, ctx: AgentContext, target, analysis) -> list[Finding]:
        out: list[Finding] = []
        try:
            r = hb.csv_timeline(target, analysis / "hayabusa", timeout=1800)
        except hb.HayabusaError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Hayabusa unavailable or failed: {e}",
            )))
            return out
        if r.detection_count == 0:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Hayabusa Sigma sweep: 0 detections — neither corroborates nor refutes",
                evidence=[r.as_evidence()],
            )))
            return out
        # Map ATT&CK technique IDs to hypothesis tags (same scheme as capa)
        tags: list[str] = []
        for tid in r.attack_techniques:
            if tid.startswith("T1055"):
                tags.append("H_PROCESS_INJECTION")
            elif tid.startswith("T1003"):
                tags.append("H_CREDENTIAL_ACCESS")
            elif tid.startswith("T1059") or tid.startswith("T1218"):
                tags.append("H_LIVING_OFF_THE_LAND")
            elif tid.startswith("T1543") or tid.startswith("T1547"):
                tags.append("H_PERSISTENCE_SERVICE")
            elif tid.startswith("T1053"):
                tags.append("H_PERSISTENCE_SCHEDULED_TASK")
            elif tid.startswith("T1021") or tid.startswith("T1569"):
                tags.append("H_LATERAL_MOVEMENT")
            elif tid.startswith("T1486"):
                tags.append("H_RANSOMWARE")
            elif tid.startswith("T1110"):
                tags.append("H_BRUTE_FORCE")
        tags = sorted(set(tags))
        sev_summary = ", ".join(f"{k}={v}" for k, v in sorted(r.severity_counts.items()))
        top_rules = ", ".join(name for name, _ in
                              sorted(r.rule_hits.items(), key=lambda kv: -kv[1])[:3])
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Hayabusa Sigma sweep: {r.detection_count} detection(s); "
                   f"{len(r.attack_techniques)} unique ATT&CK technique(s). "
                   f"Severity: {sev_summary}. Top rules: {top_rules}"),
            evidence=[r.as_evidence()],
            hypotheses_supported=tags,
        )))
        return out
