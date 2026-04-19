"""ExecutionCorroborator — cross-reference execution evidence across
multiple independent Windows artifact sources.

SANS Windows Forensics "Program Execution" section lists 8 sources
that each record program execution with different biases / retention
characteristics. Shimcache alone means "OS checked this for compat"
not "definitely ran"; Prefetch caps at 128/1024 entries; Amcache
only captures PE binaries it's seen. The strongest signal is a BINARY
appearing in ≥2 independent sources.

This agent walks the EZ Tools CSV outputs that windows_artifact has
already produced, groups by lowercase basename, and emits:

  - per-executable Finding for ≥2-source corroboration, confidence
    tiered by (#sources, whether the path is user-writable)
  - summary Finding with counts per source so the report describes
    how many events each source contributed

Never parses EVTX / PE / registry directly — all the schema work lives
in el.skills.execution_corroboration, same design as PR-G for
LateralMovementAnalyst.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import execution_corroboration as xc


# Executables that legitimately execute countless times on any Windows
# host and whose corroboration is uninformative — emit them as "observed"
# in the summary but don't generate per-binary findings.
_NOISY_BASENAMES = frozenset({
    "cmd.exe", "powershell.exe", "conhost.exe", "svchost.exe", "explorer.exe",
    "taskhostw.exe", "dllhost.exe", "rundll32.exe", "winlogon.exe", "services.exe",
    "smss.exe", "csrss.exe", "wininit.exe", "lsass.exe", "spoolsv.exe",
    "searchindexer.exe", "wmiprvse.exe", "audiodg.exe", "msmpeng.exe",
    "securityhealthservice.exe", "runtimebroker.exe", "sihost.exe",
    "searchui.exe", "shellexperiencehost.exe", "fontdrvhost.exe",
    "dwm.exe", "ctfmon.exe", "notepad.exe",
})


class ExecutionCorroboratorAgent(Agent):
    name = "execution_corroborator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        artifacts_dir = ctx.case_dir / "analysis" / "windows_artifact"
        if not artifacts_dir.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"ExecutionCorroborator: windows_artifact has not "
                       f"run yet ({artifacts_dir} missing). Upstream "
                       f"artifact extraction must complete first."),
            ))]

        entries, counts = xc.correlate(artifacts_dir, min_sources=2)
        if not any(counts.values()):
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"ExecutionCorroborator: found no EZ Tools CSVs "
                       f"under {artifacts_dir.name} for shimcache/"
                       f"prefetch/amcache/userassist. Extraction likely "
                       f"produced zero artifacts."),
            ))]

        # Summary + per-source row counts
        summary_path = (ctx.case_dir / "analysis" / self.name
                        / "correlation_summary.json")
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_payload = {
            "per_source_row_count": counts,
            "total_distinct_executables": len(entries),
            "corroborated_count": sum(1 for e in entries.values()
                                       if e.corroboration >= 2),
        }
        summary_path.write_text(json.dumps(summary_payload, indent=2))
        summary_sha = hashlib.sha256(summary_path.read_bytes()).hexdigest()
        summary_ev = EvidenceItem(
            tool="el.execution_corroborator", version="0.1.0",
            command=f"xc.correlate({artifacts_dir.name})",
            output_sha256=summary_sha, output_path=str(summary_path),
            extracted_facts=summary_payload,
        )
        sources_present = [s for s, n in counts.items() if n]
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Execution-artifact correlation: {len(entries)} distinct "
                   f"executable(s) seen across {len(sources_present)} "
                   f"source(s) ({', '.join(sources_present)}). "
                   f"{summary_payload['corroborated_count']} binary(ies) "
                   f"corroborated by ≥2 sources."),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # Per-binary high-signal findings. Skip noisy baseline binaries
        # unless they're in a suspicious path.
        for name, e in sorted(entries.items()):
            if e.corroboration < 2:
                continue
            is_user_path = any(xc.is_user_writable_path(p) for p in e.paths)
            is_noisy = name in _NOISY_BASENAMES
            # Noisy basenames suppress unless the path itself is suspicious
            # (lsass.exe in Temp/ etc.)
            if is_noisy and not is_user_path:
                continue

            # Confidence tiering:
            #   user-writable path + corroboration ≥ 2 → high (dropper shape)
            #   corroboration = 4 (all sources) → high
            #   corroboration ≥ 3              → high
            #   corroboration = 2              → medium
            if is_user_path or e.corroboration >= 3:
                confidence = "high"
            else:
                confidence = "medium"

            hyps: list[str] = ["H_DISK_ARTIFACTS"]
            if is_user_path:
                hyps.append("H_OPPORTUNISTIC_COMMODITY")
            if name in ("mimikatz.exe", "sekurlsa.exe", "kiwi.exe",
                         "procdump.exe", "psexec.exe", "psexesvc.exe"):
                hyps.extend(["H_CREDENTIAL_ACCESS", "H_LATERAL_MOVEMENT"])

            ev = EvidenceItem(
                tool="el.execution_corroborator", version="0.1.0",
                command=f"xc.correlate — {name}",
                output_sha256=summary_sha, output_path=str(summary_path),
                extracted_facts={
                    "executable": name,
                    "sources": sorted(e.sources),
                    "paths": sorted(e.paths),
                    "hit_count": e.hit_count,
                    "last_seen_by_source": e.last_seen_by_source,
                    "user_writable_path": is_user_path,
                },
            )
            sample_path = (sorted(e.paths)[0] if e.paths else "(no path)")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Execution corroborated [{name}]: present in "
                       f"{e.corroboration} independent source(s) "
                       f"({', '.join(sorted(e.sources))}); "
                       f"{e.hit_count} total row(s). Path: {sample_path}. "
                       + ("User-writable path — dropper-shape; " if is_user_path else "")
                       + "Multi-source corroboration strongly supports "
                       f"actual execution."),
                evidence=[ev],
                hypotheses_supported=hyps,
            )))
        return out
