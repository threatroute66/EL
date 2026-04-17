"""Threat Hunter — IOC sweep across case evidence.

Reads the per-case IOC catalog (./iocs.json) produced by the coordinator
post-pass, generates a YARA rule file from it, then sweeps:
  - The original input file
  - All evidence outputs under ./analysis/ (these are tool outputs that
    may contain references to indicators we extracted)

Hits become Findings tagged with the rule name (= the IOC). This closes
the loop: indicators we extracted from one tool's output become hunting
criteria across the whole case.
"""
from __future__ import annotations

import json
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import yara_hunt


class ThreatHunterAgent(Agent):
    name = "threat_hunter"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        ioc_path = ctx.case_dir / "iocs.json"
        if not ioc_path.exists():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="No iocs.json present yet — hunt requires extracted indicators",
            ))]

        try:
            iocs = json.loads(ioc_path.read_text())
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Could not parse iocs.json: {e}",
            ))]

        if not any(iocs.get(k) for k in ("md5", "sha1", "sha256", "domain",
                                          "ipv4", "url", "email")):
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="IOC catalog has no hunt-worthy indicators (hashes/domains/IPs/URLs/emails)",
            ))]

        rules_path = analysis / "case_iocs.yar"
        try:
            yara_hunt.generate_ioc_rules(iocs, rules_path, case_id=ctx.case_id)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"YARA rule generation failed: {e}",
            ))]

        targets: list[Path] = [ctx.input_path]
        analysis_root = ctx.case_dir / "analysis"
        if analysis_root.exists():
            targets.append(analysis_root)

        for tgt in targets:
            try:
                r = yara_hunt.scan_paths(rules_path, tgt, analysis,
                                          recursive=tgt.is_dir(), threads=4,
                                          timeout=600)
            except yara_hunt.YaraError as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"yara unavailable for sweep of {tgt}: {e}",
                )))
                continue

            ev = r.as_evidence()
            if r.hit_count == 0:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="low",
                    claim=f"YARA sweep of {tgt.name}: no hits — neither corroborates nor refutes "
                          "(sweep target may not contain the indicator types the catalog holds)",
                    evidence=[ev],
                )))
                continue

            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"YARA sweep of {tgt.name}: {r.hit_count} hit(s) across "
                      f"{len(r.rule_to_files)} unique IOC rule(s)",
                evidence=[ev], hypotheses_supported=["H_IOC_CORROBORATED"],
            )))

        if not out:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="Threat hunt did not execute against any target",
            ))]
        return out
