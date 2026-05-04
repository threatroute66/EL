"""Container / Kubernetes forensicator agent.

Consumes Falco event-JSONL streams (and, in the future, container-explorer
offline state) to surface container-escape and K8s-privilege-escalation
behaviours. Tags ``H_CONTAINER_ESCAPE`` / ``H_K8S_PRIVILEGE_ESCALATION``
on the relevant findings so ACH can score them.

Routing: triage assigns ``falco-events`` evidence_kind to .jsonl files
that look like Falco output (first line has ``rule`` + ``priority`` keys).

Today this agent is Falco-only. ``container-explorer`` (Google) for offline
runc/containerd state is a non-trivial Go-binary install — slated for a
follow-up commit. The forensic chain is unaffected: when EL is given runc
state without an analyzer, the existing TriageAgent will fall through with
``directory-unclassified`` rather than mis-routing.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import falco_events as fe


class ContainerForensicatorAgent(Agent):
    name = "container_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        try:
            result = fe.parse_jsonl(ctx.input_path)
        except fe.FalcoEventsError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Falco event JSONL parse failed: {e}",
            ))]

        ev = result.as_evidence()
        if result.event_count == 0:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="low",
                claim=("Falco event JSONL parsed but contained 0 events — "
                       "either an empty capture or non-Falco JSONL"),
                evidence=[ev],
            ))]

        # Headline summary.
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Falco events parsed: {result.event_count:,} event(s) "
                   f"across {len(result.rule_hits)} rule(s); "
                   f"{result.distinct_containers} container(s), "
                   f"{result.distinct_k8s_pods} K8s pod(s); "
                   f"priorities: "
                   + ", ".join(f"{k}×{v}" for k, v
                               in sorted(result.priority_counts.items()))),
            evidence=[ev],
        )))

        # Container-escape rule cluster.
        if result.container_escape_hits > 0:
            sample_event = next(
                (e for e in result.events if e.is_container_escape()),
                None,
            )
            sample_text = (
                f" — sample: rule='{sample_event.rule}' "
                f"container={sample_event.container_name or sample_event.container_id[:12]}"
                if sample_event else ""
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Falco container-escape rule hits: "
                       f"{result.container_escape_hits} event(s){sample_text}"),
                evidence=[ev],
                hypotheses_supported=["H_CONTAINER_ESCAPE"],
                hypotheses_refuted=["H_BENIGN_NO_INCIDENT"],
            )))

        # K8s privilege-escalation rule cluster.
        if result.k8s_privesc_hits > 0:
            sample_event = next(
                (e for e in result.events if e.is_k8s_privesc()),
                None,
            )
            sample_text = (
                f" — sample: rule='{sample_event.rule}' "
                f"pod={sample_event.k8s_namespace}/{sample_event.k8s_pod}"
                if sample_event else ""
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Falco K8s privilege-escalation rule hits: "
                       f"{result.k8s_privesc_hits} event(s){sample_text}"),
                evidence=[ev],
                hypotheses_supported=["H_K8S_PRIVILEGE_ESCALATION"],
                hypotheses_refuted=["H_BENIGN_NO_INCIDENT"],
            )))

        # High-priority events get individually surfaced (capped) to give
        # the analyst diagnostic detail.
        for event in result.high_priority_events(max_count=10):
            tail = (f" container={event.container_name or event.container_id[:12]}"
                    if event.container_id else "")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Falco {event.priority}: {event.rule}"
                       + tail
                       + (f" — {event.proc_cmdline[:120]!r}"
                          if event.proc_cmdline else "")),
                evidence=[ev],
            )))

        return out
