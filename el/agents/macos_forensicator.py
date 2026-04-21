"""MacOSForensicator — consume the exports dir DiskForensicator emits
for APFS disk images, run the macos_triage detector suite, promote
hits into Findings.

Chained from the coordinator after DiskForensicator when
`ctx.shared["macos_artifacts_dir"]` is set (parallel to how
LinuxForensicatorAgent handles ext4 and WindowsArtifactAgent handles
NTFS).

Confidence tier:
  launch_persistence_suspicious → high (plist in /tmp is unambiguous)
  shell_history_*_credential_access → high
  shell_history_*_reverse_shell → high
  everything else → medium
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import macos_triage as mt


_HIGH_FAMILIES = {
    "launch_persistence_suspicious",
    "shell_history_reverse_shell",
    "shell_history_credential_access",
    "shell_history_defense_evasion",
    "shell_history_persistence_ssh",
    "shell_history_persistence_cron",
}


class MacOSForensicatorAgent(Agent):
    name = "macos_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        exports = ctx.shared.get("macos_artifacts_dir")
        if not exports:
            default = ctx.case_dir / "exports" / "macos-artifacts"
            if default.is_dir() and any(default.rglob("*")):
                exports = default
            else:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=("MacOSForensicator: no macOS artifacts "
                           "directory produced by upstream "
                           "DiskForensicator. This case either isn't "
                           "a macOS/APFS disk image or the extraction "
                           "failed."),
                ))]
        exports = Path(exports)

        hits = mt.run_all(exports)
        if not hits:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"MacOSForensicator: walked extracted artifacts "
                       f"at {exports.name}/ — no malicious-pattern / "
                       f"persistence-plist / quarantine-anomaly / "
                       f"download-plist-suspicious hits. Absence of "
                       f"evidence; not evidence of absence."),
            ))]

        manifest = exports / "MANIFEST.txt"
        sha = "0" * 64
        if manifest.is_file():
            sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

        out: list[Finding] = []
        for h in hits:
            confidence = "high" if h.family in _HIGH_FAMILIES else "medium"
            facts = {
                "family": h.family,
                "matched_pattern": h.matched_pattern,
                "event_count": h.event_count,
                "source_files": h.source_files[:5],
                "attack_techniques": [t for t, _ in h.attack],
                "sample_text_head": h.sample_text[:200],
            }
            ev = EvidenceItem(
                tool="el.macos_triage", version="0.1.0",
                command=f"run_all({exports.name})",
                output_sha256=sha, output_path=str(manifest),
                extracted_facts=facts,
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence=confidence,
                claim=(f"macOS {h.family}: {h.event_count} "
                       f"event(s) matched pattern {h.matched_pattern!r}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"),
                evidence=[ev],
                hypotheses_supported=mt.hypotheses_for(h.family)
                                       or ["H_APT_ESPIONAGE"],
            )))
        return out
