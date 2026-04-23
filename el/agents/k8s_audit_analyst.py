"""K8sAuditAnalyst — wraps the k8s_audit skill, emits Findings.

Consumes a Kubernetes API-server audit log (`audit.k8s.io/v1` NDJSON)
and surfaces the control-plane-abuse signals the skill library defines.

The volume finding always fires (parsed N events across T minutes).
Each anomaly the skill emits becomes its own Finding with the anomaly's
hypotheses_supported and ATT&CK techniques carried through.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import k8s_audit as k8s


class K8sAuditAnalystAgent(Agent):
    name = "k8s_audit_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        p = Path(ctx.input_path)
        if not p.is_file():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"K8sAuditAnalyst expects a file; got {p}",
            ))]

        run = k8s.run_all(p)
        out: list[Finding] = []

        # Volume finding
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Kubernetes audit log parsed ({p.name}): "
                   f"{run.total_events:,} event(s), "
                   f"time range {run.time_min} → {run.time_max}. "
                   f"Top users: "
                   f"{', '.join(list(run.user_counts)[:3])}"),
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_CLOUD_LOG_PARSED"],
        )))

        # Per-anomaly finding
        for a in run.anomalies:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence=a.confidence,
                claim=f"K8s audit anomaly [{a.anomaly_id}]: {a.summary}",
                evidence=[run.as_evidence(facts={
                    "anomaly_id": a.anomaly_id,
                    "attack": [f"{t}:{n}" for t, n in a.attack],
                    "sample_audit_ids": a.sample_audit_ids,
                    **a.facts,
                })],
                hypotheses_supported=a.hypotheses,
            )))
        return out
