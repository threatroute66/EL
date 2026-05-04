"""dfTimewolf dispatcher agent — provenance + sub-artifact inventory.

Triage routes ``dftimewolf-bundle`` evidence here. We do NOT re-implement
the analysis paths for the bundle's sub-artifacts (Plaso storage, CloudTrail
JSON, etc.) — those have their own EL agents. This agent records the
*provenance* (which dfTimewolf recipe + modules produced the bundle) and
emits one finding per sub-artifact bucket so the analyst sees a coherent
inventory before re-running EL on the relevant sub-paths individually.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import dftimewolf_bundle as dftw


# Per-kind suggested follow-up command. The analyst can re-run EL with the
# specific artifact path; this skill stays small and doesn't try to re-
# orchestrate the coordinator on its own (that risks recursion).
_FOLLOWUP_HINT = {
    "plaso":         "el report on the Plaso .plaso storage directly",
    "pcap":          "el investigate <pcap> — NetworkAnalyst",
    "evtx":          "el investigate <evtx> — LogAnalyst",
    "cloudtrail":    "el investigate <json> — CloudForensicator",
    "azure_signin":  "el investigate <json> — CloudForensicator",
    "k8s_audit":     "el investigate <json> — K8sAuditAnalyst",
    "ewf":           "el investigate <e01> — DiskForensicator",
    "raw_disk":      "el investigate <raw> — DiskForensicator",
    "vhdx":          "el investigate <vhdx> — DiskForensicator",
    "vmdk":          "el investigate <vmdk> — DiskForensicator",
    "aff4":          "el investigate <aff4> — DiskForensicator (after raw conversion)",
}


class DFTimewolfDispatcherAgent(Agent):
    name = "dftimewolf_dispatcher"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []

        # The triage step parsed the bundle and stashed it in shared state.
        bundle = ctx.shared.get("dftimewolf_bundle")
        if bundle is None:
            # Cold-routed direct to this agent — re-parse from input_path.
            try:
                bundle = dftw.parse_bundle(Path(ctx.input_path))
            except dftw.DFTimewolfError as e:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"Input not a parseable dfTimewolf output "
                           f"directory: {e}"),
                ))]

        ev = bundle.as_evidence()
        recipe_name = bundle.recipe.name if bundle.recipe else "(unknown)"
        recipe_modules = (bundle.recipe.module_names if bundle.recipe else [])

        # Provenance finding — the headline output of this agent. Tells the
        # analyst what dfTimewolf actually did, deterministically, with the
        # recipe + module list as evidence.
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"dfTimewolf bundle parsed: recipe='{recipe_name}' "
                   f"({len(recipe_modules)} module(s) declared); "
                   f"{len(bundle.artifact_files)} sub-artifact(s) across "
                   f"{len(bundle.artifact_kinds)} kind(s)"),
            evidence=[ev],
        )))

        # Per-kind inventory + follow-up hints.
        hints = bundle.routing_hints()
        for kind, paths in sorted(hints.items()):
            sample = [str(p.relative_to(bundle.bundle_root)) for p in paths[:5]]
            followup = _FOLLOWUP_HINT.get(kind, "")
            tail = (f" — re-run via: {followup}" if followup else "")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"dfTimewolf sub-artifacts of kind '{kind}': "
                       f"{len(paths)} file(s) (sample: {sample}){tail}"),
                evidence=[ev],
            )))

        # No sub-artifact rec? Still useful — make that explicit so the
        # operator sees we ran but didn't find route-able files.
        if not hints:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"dfTimewolf bundle '{bundle.bundle_root.name}' "
                       f"contained no recognised sub-artifact kinds "
                       f"(.plaso / .pcap / .evtx / cloudtrail JSON / etc.) "
                       f"— recipe ran but produced nothing EL routes "
                       f"automatically."),
                evidence=[ev],
            )))
        return out
