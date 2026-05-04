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
        # Three input modes (mirrors LinuxForensicatorAgent):
        # (1) Chained from DiskForensicator with `macos_artifacts_dir`
        #     set in shared context (existing wiring)
        # (2) Triage routed evidence_kind == "macos-fs-dir" → use
        #     `ctx.input_path` directly as the extracted FS root
        # (3) Default fallback to `<case_dir>/exports/macos-artifacts`
        kind = ctx.shared.get("evidence_kind") or ""
        exports = ctx.shared.get("macos_artifacts_dir")
        if not exports and kind == "macos-fs-dir":
            exports = ctx.input_path
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

        # Tier 4.3 — macOS Unified Logs (tracev3) deep-dive via Mandiant's
        # Rust parser. Walks for a .logarchive bundle or a Persist tracev3
        # tree under the extracted filesystem; runs unifiedlog_iterator;
        # emits a high-signal-event summary finding when something fires.
        out.extend(self._run_unified_logs(ctx, exports))
        return out

    def _run_unified_logs(self, ctx: AgentContext,
                            exports: Path) -> list[Finding]:
        """Drive macos_unifiedlogs against any tracev3 / .logarchive found
        under *exports*. No-op silently if the parser isn't installed or
        no unified-log artifacts are present."""
        from el.skills import macos_unifiedlogs as mul
        out: list[Finding] = []
        target = mul.find_unified_logs(exports)
        if target is None:
            return out
        analysis = ctx.case_dir / "analysis" / self.name / "unified_logs"
        try:
            run = mul.parse(target, analysis)
        except (mul.MacOSUnifiedLogsError, OSError, TypeError, ValueError) as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"macOS Unified Logs parse skipped: {e}",
            )))
            return out

        ev = run.as_evidence()
        if run.event_count == 0:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"macOS Unified Logs: parser ran on {target.name} "
                       f"with rc={run.rc} and produced 0 events"
                       + (f" — note: {run.note}" if run.note else "")),
                evidence=[ev],
            )))
            return out

        # Headline summary.
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"macOS Unified Logs parsed: "
                   f"{run.event_count:,} event(s) across "
                   f"{run.distinct_processes} process(es) and "
                   f"{len(run.by_subsystem)} subsystem(s); "
                   f"{run.high_signal_count} high-signal event(s) "
                   "(TCC / AMFI / Gatekeeper / Sandbox / kextd)"),
            evidence=[ev],
        )))

        # If high-signal events are present, surface a TCC/AMFI/Gatekeeper
        # cluster finding so the analyst sees the anomaly without trawling
        # the full JSONL.
        if run.high_signal_count > 0:
            samples = list(run.iter_high_signal(max_count=5))
            sample_str = ""
            if samples:
                sample_event = samples[0]
                sample_str = (f" — sample: subsystem='{sample_event.subsystem}' "
                              f"process='{sample_event.process}' "
                              f"type='{sample_event.log_type}'")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"macOS Unified Logs flagged "
                       f"{run.high_signal_count} high-signal event(s) "
                       f"(security-subsystem hits or fault/error/alert "
                       f"log-types){sample_str}"),
                evidence=[ev],
                hypotheses_supported=["H_MAC_TCC_BYPASS",
                                       "H_MAC_FILELESS_AMFI_BYPASS"],
            )))
        return out
