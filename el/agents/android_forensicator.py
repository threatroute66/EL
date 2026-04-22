"""AndroidForensicator — primary investigator for Android filesystem
tree inputs.

Android cases typically arrive as already-extracted file-system
trees (Belkasoft output / UFED Reader export / adb pull of /data
and /storage). No mounting needed — the agent walks the input dir,
runs `extract_android_artifacts` to produce the sealed exports
subtree, then runs `android_triage.run_all` for detection.

Routed from Triage when `ctx.shared["evidence_kind"] == "android-fs-dir"`
(parallel to how `windows-artifacts-dir` routes to
WindowsArtifactAgent).

Confidence tiers:
  rooted_device → medium (informational — rooted ≠ compromised, but
    flips the threat model)
  sideloaded_apk → high (the primary delivery vector for Android
    malware in the wild)
  data_local_tmp_executable → high (attacker shell staging)
  messenger_presence → low (purely informational)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import android_artifacts as aa
from el.skills import android_triage as at


_CONFIDENCE_BY_FAMILY = {
    "rooted_device":              "medium",
    "sideloaded_apk":             "high",
    "data_local_tmp_executable":  "high",
    "messenger_presence":         "low",
}


class AndroidForensicatorAgent(Agent):
    name = "android_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        src = ctx.input_path
        if not src.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("AndroidForensicator: input is not a directory. "
                       "Android cases arrive as file-system trees "
                       "(Belkasoft / UFED / adb-pull), not as block "
                       "images."),
            ))]

        exports = ctx.case_dir / "exports" / "android-artifacts"
        try:
            counts = aa.extract_android_artifacts(src, exports)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Android extraction errored: {e}",
            ))]
        out: list[Finding] = []
        if not counts:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"AndroidForensicator: walked {src.name} but no "
                       f"Android artifacts recognised (no data/system/"
                       f"packages.xml, no data/data/ per-app dirs, no "
                       f"data/adb/, no data/local/tmp/). Likely not an "
                       f"Android filesystem tree."),
            )))
            return out

        listing = "\n".join(sorted(
            str(p.relative_to(exports))
            for p in exports.rglob("*") if p.is_file()))
        listing_path = exports / "MANIFEST.txt"
        listing_path.parent.mkdir(parents=True, exist_ok=True)
        listing_path.write_text(listing)
        summary_ev = EvidenceItem(
            tool="el.android_artifacts", version="0.1.0",
            command=f"extract_android_artifacts({src.name})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=counts,
        )
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Android artifacts extracted from {src.name}: "
                   f"{summary}"),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        hits = at.run_all(exports)
        for h in hits:
            confidence = _CONFIDENCE_BY_FAMILY.get(h.family, "medium")
            ev = EvidenceItem(
                tool="el.android_triage", version="0.1.0",
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
                claim=(f"Android {h.family}: {h.event_count} "
                       f"signal(s); {h.matched_pattern}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"),
                evidence=[ev],
                hypotheses_supported=at.hypotheses_for(h.family)
                                       or ["H_DISK_ARTIFACTS"],
            )))
        return out
