"""IOSForensicator — primary investigator for iOS filesystem tree inputs.

iOS cases arrive as already-extracted filesystem trees (checkm8 /
GrayKey / Cellebrite / advanced-logical extraction), not as block
images. No mount needed — the agent walks the input dir, runs
`extract_ios_artifacts` to produce the sealed exports subtree, then
runs `ios_triage.run_all` for detection.

Routed from Triage when `ctx.shared["evidence_kind"] == "ios-fs-dir"`
(parallel to how `android-fs-dir` routes to AndroidForensicatorAgent
and `windows-artifacts-dir` routes to WindowsArtifactAgent).

Confidence tiers:
  jailbreak_indicator → medium (informational — jailbroken ≠ compromised,
    but flips the threat model; iOS sandbox is weakened or absent)
  sideloaded_app → high (on iOS the only non-App-Store path is
    enterprise provisioning / TestFlight / dev signing — each a
    deliberate threat-model shift)
  provisioning_profile → medium (stock consumer iOS has none;
    presence = enterprise MDM or dev/sideload tooling)
  messenger_presence → low (purely informational pivot)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import ios_artifacts as ia
from el.skills import ios_triage as it


_CONFIDENCE_BY_FAMILY = {
    "jailbreak_indicator":    "medium",
    "sideloaded_app":         "high",
    "provisioning_profile":   "medium",
    "messenger_presence":     "low",
}


class IOSForensicatorAgent(Agent):
    name = "ios_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        src = ctx.input_path
        if not src.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("IOSForensicator: input is not a directory. "
                       "iOS cases arrive as file-system trees "
                       "(checkm8 / GrayKey / Cellebrite output), "
                       "not as block images."),
            ))]

        exports = ctx.case_dir / "exports" / "ios-artifacts"
        try:
            counts = ia.extract_ios_artifacts(src, exports)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"iOS extraction errored: {e}",
            ))]

        out: list[Finding] = []
        if not counts:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"IOSForensicator: walked {src.name} but no iOS "
                       f"artifacts recognised (no System/Library/"
                       f"CoreServices/SystemVersion.plist, no /private/"
                       f"var/mobile/Library/ DBs, no /private/var/"
                       f"containers/Bundle/Application/ bundles). "
                       f"Likely not an iOS filesystem tree."),
            )))
            return out

        listing = "\n".join(sorted(
            str(p.relative_to(exports))
            for p in exports.rglob("*") if p.is_file()))
        listing_path = exports / "MANIFEST.txt"
        listing_path.parent.mkdir(parents=True, exist_ok=True)
        listing_path.write_text(listing)
        summary_ev = EvidenceItem(
            tool="el.ios_artifacts", version="0.1.0",
            command=f"extract_ios_artifacts({src.name})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=counts,
        )
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"iOS artifacts extracted from {src.name}: {summary}"),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        hits = it.run_all(exports)
        for h in hits:
            confidence = _CONFIDENCE_BY_FAMILY.get(h.family, "medium")
            ev = EvidenceItem(
                tool="el.ios_triage", version="0.1.0",
                command=f"run_all({exports.name}, family={h.family})",
                output_sha256=summary_ev.output_sha256,
                output_path=str(listing_path),
                extracted_facts={
                    "family": h.family,
                    "matched_pattern": h.matched_pattern,
                    "event_count": h.event_count,
                    "source_files": h.source_files[:5],
                    "attack_techniques": [t for t, _ in h.attack],
                    "sample_text_head": h.sample_text[:200],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence=confidence,
                claim=(f"iOS {h.family}: {h.event_count} signal(s); "
                       f"{h.matched_pattern}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"),
                evidence=[ev],
                hypotheses_supported=it.hypotheses_for(h.family)
                                       or ["H_DISK_ARTIFACTS"],
            )))
        return out
