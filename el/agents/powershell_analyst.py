"""PowerShellAnalystAgent — pattern-match decoded ScriptBlockLogging content.

Sits alongside `credential_analyst` and `lateral_movement_analyst`;
they count EID 4104, this agent looks inside the payload. Most
attacker PowerShell is obfuscated (base64, gzip+base64,
string-split / tick-escape Invoke-Obfuscation variants); we decode
what we can and pattern-match both the raw and decoded script text
against a curated library of family markers.

Confidence tier:
  mimikatz / c2_framework — high (match on a single event is
    unambiguous)
  amsi_bypass / encoded_command — high when count ≥3 OR any
    decoded variant hit; otherwise medium
  download_cradle / persistence / obfuscation — medium
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import powershell_triage as pst


_HIGH_FAMILIES = {"mimikatz", "c2_framework"}


class PowerShellAnalystAgent(Agent):
    name = "powershell_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        csv_path = (ctx.case_dir / "analysis" / "windows_artifact"
                    / "evtx" / "evtx_parsed.csv")
        if not csv_path.is_file():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"PowerShellAnalyst: no EvtxECmd CSV at "
                       f"{csv_path.relative_to(ctx.case_dir)} — upstream "
                       f"windows_artifact must have run first."),
            ))]

        try:
            hits = pst.run(csv_path)
        except Exception as e:     # noqa: BLE001
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"PowerShellAnalyst: CSV scan failed: {e}",
            ))]

        if not hits:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"PowerShellAnalyst: EID 4104 events present but "
                       f"none matched the malicious-pattern library "
                       f"(mimikatz / amsi_bypass / download cradles / "
                       f"encoded-command / C2 framework strings / "
                       f"obfuscation markers). Absence of evidence; "
                       f"not evidence of absence."),
            ))]

        csv_sha = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        out: list[Finding] = []
        for h in hits:
            if h.family in _HIGH_FAMILIES:
                confidence = "high"
            elif h.family in ("amsi_bypass", "encoded_command") and (
                    h.event_count >= 3 or h.decoded_samples):
                confidence = "high"
            else:
                confidence = "medium"

            facts = {
                "family": h.family,
                "matched_pattern": h.matched_pattern,
                "event_count": h.event_count,
                "first_seen_utc": h.first_seen,
                "last_seen_utc": h.last_seen,
                "top_computers": h.top_computers,
                "top_users": h.top_users,
                "attack_techniques": [t for t, _ in h.attack],
                "decoded_samples_present": bool(h.decoded_samples),
                "sample_text_head": h.sample_text[:200],
            }
            ev = EvidenceItem(
                tool="el.powershell_triage", version="0.1.0",
                command=f"run({csv_path.name}, family={h.family})",
                output_sha256=csv_sha, output_path=str(csv_path),
                extracted_facts=facts,
            )
            decoded_clip = ""
            if h.decoded_samples:
                decoded_clip = (
                    f" | decoded-sample: "
                    f"{h.decoded_samples[0][:120].replace(chr(10), ' ')}"
                )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"PowerShell 4104 [{h.family}]: {h.event_count} "
                       f"ScriptBlockLogging event(s) matched pattern "
                       f"{h.matched_pattern!r}. "
                       f"ATT&CK: {', '.join(t for t, _ in h.attack) or '-'}. "
                       f"first={h.first_seen or '?'}, "
                       f"last={h.last_seen or '?'}.{decoded_clip}"),
                evidence=[ev],
                hypotheses_supported=pst.hypotheses_for(h.family)
                                       or ["H_APT_ESPIONAGE"],
            )))
        return out
