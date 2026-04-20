"""CredentialAnalystAgent — detect credential-access + brute-force
patterns in the EvtxECmd CSV.

Parallel to LateralMovementAnalystAgent: consumes the same parsed CSV
produced by WindowsArtifactAgent's EvtxECmd step, but routes findings
into H_CREDENTIAL_ACCESS / H_BRUTE_FORCE hypotheses instead of
H_LATERAL_MOVEMENT. Runs after the lateral-movement / execution
analysts; silent-insufficient when the CSV is missing so the chain is
robust on non-Windows cases.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import credential_triage as ct


# Per-technique hypothesis tags. Every credential-access finding also
# lifts H_APT_ESPIONAGE at a weaker weight (handled downstream by the
# hypothesis scorer) because credential theft is a high-specificity
# signal for targeted activity.
_TECHNIQUE_HYPOTHESES: dict[str, list[str]] = {
    "brute_force":    ["H_BRUTE_FORCE", "H_CREDENTIAL_ACCESS"],
    "password_spray": ["H_BRUTE_FORCE", "H_CREDENTIAL_ACCESS"],
    "kerberoasting":  ["H_CREDENTIAL_ACCESS", "H_APT_ESPIONAGE"],
    "ntlm_spray":     ["H_BRUTE_FORCE", "H_CREDENTIAL_ACCESS"],
}


class CredentialAnalystAgent(Agent):
    name = "credential_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        csv_path = (ctx.case_dir / "analysis" / "windows_artifact"
                    / "evtx" / "evtx_parsed.csv")
        if not csv_path.is_file():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"CredentialAnalyst: no EvtxECmd CSV at "
                       f"{csv_path.relative_to(ctx.case_dir)} — upstream "
                       f"windows_artifact must have run first."),
            ))]

        try:
            hits = ct.run_all(csv_path)
        except ct.EvtxTriageError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"CredentialAnalyst: CSV parse failed — {e}",
            ))]

        if not hits:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"CredentialAnalyst: parsed {csv_path.name} but "
                       f"no credential-access pattern crossed threshold "
                       f"(brute-force ≥10/target, password-spray "
                       f"≥5 targets/source, Kerberoasting ≥3 RC4 TGS, "
                       f"NTLM spray ≥5 targets/workstation). Absence of "
                       f"evidence; not evidence of absence."),
            ))]

        csv_sha = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        out: list[Finding] = []
        for h in hits:
            # Kerberoasting is unambiguous on an AES-by-default AD → high.
            # Brute-force / spray: high when ≥3 distinct entities (multi-
            # target or multi-source) OR ≥50 events total; else medium.
            if h.technique == "kerberoasting":
                confidence = "high"
            elif (len(h.top_targets) >= 3 or len(h.top_sources) >= 3
                  or h.event_count >= 50):
                confidence = "high"
            else:
                confidence = "medium"

            facts = {
                "technique": h.technique,
                "subtechnique": h.subtechnique,
                "event_count": h.event_count,
                "first_seen_utc": h.first_seen,
                "last_seen_utc": h.last_seen,
                "top_targets": [(t, n) for t, n in h.top_targets[:5]],
                "top_sources": [(s, n) for s, n in h.top_sources[:5]],
                "attack_techniques": [tid for tid, _ in h.attack],
            }
            ev = EvidenceItem(
                tool="el.credential_triage", version="0.1.0",
                command=f"credential_triage.run_all({csv_path.name})",
                output_sha256=csv_sha, output_path=str(csv_path),
                extracted_facts=facts,
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=f"Credential access [{h.technique}/{h.subtechnique}] — {h.description}",
                evidence=[ev],
                hypotheses_supported=_TECHNIQUE_HYPOTHESES.get(
                    h.technique, ["H_CREDENTIAL_ACCESS"]),
            )))
        return out
