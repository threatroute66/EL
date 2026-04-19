"""LateralMovementAnalyst — detect Hunt-Evil lateral-movement techniques.

Input: a case directory that already has an EvtxECmd CSV output under
  <case>/analysis/windows_artifact/evtx/evtx_parsed.csv

For each of the 7 Hunt-Evil destination-side techniques (PsExec, Scheduled
Task, Service Install, WMI persistence, PowerShell Remoting, RDP, +
security-log-cleared anti-forensic) the el.skills.evtx_triage detectors
return per-technique hit summaries; we turn each hit into a Finding with
confidence set by the event-count × channel-diversity × presence of
corroborating signals, and MITRE ATT&CK techniques mapped straight from
the detector.

Design notes:
  - This agent NEVER opens an EVTX file directly. The EZ-Tools
    EvtxECmd wrapper in windows_artifact already does that; we consume
    its normalized CSV. Same pattern as Plaso → psort.
  - Confidence tiers:
      high   — ≥2 channels corroborate the same technique OR anti-
               forensic 1102 fires anywhere
      medium — single-channel evidence only
      low    — below a detector's own floor (currently unused)
  - All findings lift H_LATERAL_MOVEMENT. PsExec, RDP, and PSRemoting
    additionally lift H_C2_OR_REVERSE_SHELL (remote command channel).
    WMI subscription lifts H_PERSISTENCE_SERVICE (sibling persistence
    mechanism) plus H_LATERAL_MOVEMENT.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import evtx_triage as evt


# Map each technique → extra hypothesis tags beyond H_LATERAL_MOVEMENT.
_TECHNIQUE_HYPOTHESES: dict[str, list[str]] = {
    "psexec":          ["H_LATERAL_MOVEMENT", "H_C2_OR_REVERSE_SHELL"],
    "scheduled_task":  ["H_LATERAL_MOVEMENT", "H_PERSISTENCE_SCHEDULED_TASK"],
    "service_install": ["H_LATERAL_MOVEMENT", "H_PERSISTENCE_SERVICE"],
    "wmi":             ["H_LATERAL_MOVEMENT", "H_PERSISTENCE_SERVICE"],
    "ps_remoting":     ["H_LATERAL_MOVEMENT", "H_C2_OR_REVERSE_SHELL",
                         "H_LIVING_OFF_THE_LAND"],
    "rdp":             ["H_LATERAL_MOVEMENT", "H_C2_OR_REVERSE_SHELL"],
    "anti_forensic":   ["H_EID_1102"],
}


class LateralMovementAnalystAgent(Agent):
    name = "lateral_movement_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        csv_path = (ctx.case_dir / "analysis" / "windows_artifact"
                    / "evtx" / "evtx_parsed.csv")
        if not csv_path.is_file():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"LateralMovementAnalyst: no EvtxECmd CSV at "
                       f"{csv_path.relative_to(ctx.case_dir)} — upstream "
                       f"windows_artifact must have run first and produced "
                       f"event-log output."),
            ))]

        try:
            hits = evt.run_all(csv_path)
        except evt.EvtxTriageError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"LateralMovementAnalyst: CSV parse failed — {e}",
            ))]

        # Bookkeep how many technique families fired for the aggregate finding.
        techniques_fired = {h.technique for h in hits}

        if not hits:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"LateralMovementAnalyst: parsed "
                       f"{csv_path.name} but none of the 7 Hunt-Evil "
                       f"lateral-movement techniques fired. Absence of "
                       f"evidence is not evidence of absence — this is "
                       f"expected on many single-host memory captures."),
            ))]

        csv_sha = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        for h in hits:
            # Multi-source corroboration bumps to high. For anti-forensic
            # 1102 we always emit at high because log clearing is the only
            # common-case reason any real case produces it.
            diversity = len({e.channel for e in h.sample_events})
            if h.technique == "anti_forensic":
                confidence = "high"
            elif diversity >= 2 or h.event_count >= 5:
                confidence = "high"
            else:
                confidence = "medium"

            hyps = _TECHNIQUE_HYPOTHESES.get(h.technique, ["H_LATERAL_MOVEMENT"])
            facts = {
                "technique": h.technique,
                "subtechnique": h.subtechnique,
                "event_count": h.event_count,
                "first_seen_utc": h.first_seen,
                "last_seen_utc": h.last_seen,
                "channels_involved": sorted({e.channel for e in h.sample_events}),
                "attack_techniques": [tid for tid, _ in h.attack],
                "sample_eids": [e.event_id for e in h.sample_events],
            }
            if h.source_ip:
                facts["source_ip"] = h.source_ip
            ev = EvidenceItem(
                tool="el.evtx_triage", version="0.1.0",
                command=f"evtx_triage.run_all({csv_path.name})",
                output_sha256=csv_sha, output_path=str(csv_path),
                extracted_facts=facts,
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=f"Lateral movement [{h.technique}/{h.subtechnique}] — {h.description}",
                evidence=[ev],
                hypotheses_supported=hyps,
            )))

        # Aggregate finding if 2+ techniques fired — that's the strongest
        # possible LM signal (ATT&CK chain across multiple techniques).
        if len(techniques_fired) >= 2:
            ev = EvidenceItem(
                tool="el.lateral_movement_analyst", version="0.1.0",
                command="aggregate_across_techniques",
                output_sha256=csv_sha, output_path=str(csv_path),
                extracted_facts={
                    "techniques_fired": sorted(techniques_fired),
                    "hit_count": len(hits),
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Multi-technique lateral-movement chain detected: "
                       f"{len(techniques_fired)} technique(s) across "
                       f"{len(hits)} detector hit(s) — "
                       f"{', '.join(sorted(techniques_fired))}. "
                       f"Classic intrusion kill-chain shape."),
                evidence=[ev],
                hypotheses_supported=["H_LATERAL_MOVEMENT", "H_APT_ESPIONAGE"],
            )))
        return out
