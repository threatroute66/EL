"""LinuxForensicator — consume the exports dir DiskForensicator
emits for Linux disk images, run the triage-detector suite, promote
hits into Findings.

Chained from the coordinator after DiskForensicator when
`ctx.shared["linux_artifacts_dir"]` is set (parallel to how
WindowsArtifactAgent is chained off `artifacts_dir`).

Confidence tiering per family:
  reverse_shell / credential_access / ld_so_preload — always high
    (single hit is unambiguous)
  ssh_brute / ssh_spray — high when the detector fires (thresholds
    already filter noise)
  persistence_{ssh,cron} / defense_evasion — high
  download_cradle / base64_pipe / priv_esc — medium (can be
    legitimate admin activity in isolation)
  cron_suspicious_path — medium
  ssh_authorized_keys_anomaly — medium (pentester-comment signal is
    strong; sheer key count can be noisy on shared hosts)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import linux_triage as lt


_HIGH_FAMILIES = {
    "reverse_shell", "credential_access", "ld_so_preload",
    "ssh_brute", "ssh_spray", "persistence_ssh", "persistence_cron",
    "defense_evasion",
}


class LinuxForensicatorAgent(Agent):
    name = "linux_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        exports = ctx.shared.get("linux_artifacts_dir")
        if not exports:
            # Also try a direct path the coordinator may have created
            # without going through shared-context plumbing
            default = ctx.case_dir / "exports" / "linux-artifacts"
            if default.is_dir() and any(default.rglob("*")):
                exports = default
            else:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=("LinuxForensicator: no Linux artifacts "
                           "directory produced by upstream "
                           "DiskForensicator. This case either isn't a "
                           "Linux disk image or the extraction failed."),
                ))]
        exports = Path(exports)

        hits = lt.run_all(exports)
        if not hits:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"LinuxForensicator: walked extracted artifacts at "
                       f"{exports.name}/ — no malicious-pattern / "
                       f"brute-force / preload / authorized-key / "
                       f"cron-suspicious hits. Absence of evidence; not "
                       f"evidence of absence."),
            ))]

        # Shared evidence — hash the MANIFEST.txt the extractor wrote
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
                "top_users": h.top_users,
                "source_files": h.source_files[:5],
                "attack_techniques": [t for t, _ in h.attack],
                "sample_text_head": h.sample_text[:200],
            }
            ev = EvidenceItem(
                tool="el.linux_triage", version="0.1.0",
                command=f"run_all({exports.name})",
                output_sha256=sha, output_path=str(manifest),
                extracted_facts=facts,
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Linux {h.family}: {h.event_count} event(s) "
                       f"matched pattern {h.matched_pattern!r}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"
                       + (f" (users: {', '.join(h.top_users[:3])})"
                          if h.top_users else "")),
                evidence=[ev],
                hypotheses_supported=lt.hypotheses_for(h.family)
                                       or ["H_APT_ESPIONAGE"],
            )))
        return out
