"""SigmaAnalystAgent — apply a SIGMA rule pack to the EvtxECmd CSV.

SIGMA rules are community-maintained YAML detections mapped to MITRE
ATT&CK (https://github.com/SigmaHQ/sigma). This agent loads a rule
directory, runs every applicable Windows rule against the EvtxECmd CSV
WindowsArtifactAgent has already produced, and emits one Finding per
rule that matches ≥1 row. Each Finding carries the SIGMA rule id + title
in the claim, the MITRE techniques in `extracted_facts`, and lifts
hypotheses derived from the rule's tags (e.g. `attack.credential_access`
→ H_CREDENTIAL_ACCESS).

Rule pack location (first match wins):
  1. ctx.shared["sigma_rules_dir"]
  2. environment variable EL_SIGMA_RULES
  3. /opt/EL/rules/sigma/ (default; typically a clone of SigmaHQ)

If no rules are found, the agent emits a single `insufficient` finding
— explicit, not silent.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import sigma_engine as se


# SIGMA tag family → EL hypothesis. A rule may have several tags; every
# matching family contributes. Tags unrecognised here still produce a
# Finding — we just don't auto-lift a hypothesis.
_TAG_TO_HYPOTHESIS: dict[str, list[str]] = {
    "attack.credential_access":  ["H_CREDENTIAL_ACCESS"],
    "attack.lateral_movement":   ["H_LATERAL_MOVEMENT"],
    "attack.persistence":        ["H_PERSISTENCE_SERVICE"],
    "attack.execution":          ["H_APT_ESPIONAGE"],
    "attack.defense_evasion":    ["H_APT_ESPIONAGE"],
    "attack.privilege_escalation": ["H_APT_ESPIONAGE"],
    "attack.command_and_control": ["H_C2_BEACONING"],
    "attack.discovery":          ["H_APT_ESPIONAGE"],
    "attack.collection":         ["H_INSIDER_DATA_EXFIL"],
    "attack.exfiltration":       ["H_INSIDER_DATA_EXFIL"],
    "attack.impact":             ["H_RANSOMWARE"],
    "attack.initial_access":     ["H_APT_ESPIONAGE"],
    "attack.reconnaissance":     ["H_APT_ESPIONAGE"],
    "attack.resource_development": ["H_APT_ESPIONAGE"],
}

# SIGMA severity → EL confidence tier. Critical + high rules are
# high-confidence when they fire; medium stays medium; low/informational
# become medium (we shouldn't downgrade below what the finding contract
# requires — insufficient is for missing-evidence cases only).
_LEVEL_TO_CONFIDENCE: dict[str, str] = {
    "critical":       "high",
    "high":           "high",
    "medium":         "medium",
    "low":            "medium",
    "informational":  "medium",
}


def _hypotheses_from_tags(tags: list[str]) -> list[str]:
    out: set[str] = set()
    for tag in tags:
        base = tag.lower().strip()
        if base in _TAG_TO_HYPOTHESIS:
            out.update(_TAG_TO_HYPOTHESIS[base])
    return sorted(out)


def _resolve_rules_dir(ctx: AgentContext) -> Path | None:
    override = ctx.shared.get("sigma_rules_dir")
    if override:
        p = Path(override)
        if p.exists():
            return p
    env = os.environ.get("EL_SIGMA_RULES")
    if env:
        p = Path(env)
        if p.exists():
            return p
    default = Path("/opt/EL/rules/sigma")
    if default.exists():
        return default
    return None


def _resolve_car_dir(ctx: AgentContext) -> Path | None:
    """MITRE CAR analytics directory — sibling concept to SIGMA but
    governed by MITRE. Resolution order mirrors `_resolve_rules_dir`:
    ctx.shared override → env var → default at /opt/EL/rules/car/."""
    override = ctx.shared.get("car_rules_dir")
    if override:
        p = Path(override)
        if p.exists():
            return p
    env = os.environ.get("EL_CAR_RULES")
    if env:
        p = Path(env)
        if p.exists():
            return p
    default = Path("/opt/EL/rules/car")
    if default.exists():
        return default
    return None


class SigmaAnalystAgent(Agent):
    name = "sigma_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        csv_path = (ctx.case_dir / "analysis" / "windows_artifact"
                    / "evtx" / "evtx_parsed.csv")
        if not csv_path.is_file():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"SigmaAnalyst: no EvtxECmd CSV at "
                       f"{csv_path.relative_to(ctx.case_dir)} — upstream "
                       f"windows_artifact must have run first."),
            ))]

        rules_dir = _resolve_rules_dir(ctx)
        if rules_dir is None:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"SigmaAnalyst: no rule pack found. Set "
                       f"EL_SIGMA_RULES or populate /opt/EL/rules/sigma/. "
                       f"Clone https://github.com/SigmaHQ/sigma for a "
                       f"community rule pack."),
            ))]

        rules = se.load_rules(rules_dir)
        # Stitch CAR analytics (MITRE Cyber Analytics Repository)
        # into the same evaluator pass. Each CAR YAML may carry a
        # sigma implementation snippet; we extract those, inject
        # the analytic's ATT&CK tags + a car.CAR-YYYY-MM-NNN
        # provenance tag, and the result is just more SigmaRule
        # objects the rest of this loop already knows how to run.
        car_dir = _resolve_car_dir(ctx)
        car_loaded_count = 0
        car_total_analytics = 0
        if car_dir is not None:
            from el.skills.car_import import load_car_rules, parse_analytic
            car_rules = load_car_rules(car_dir)
            rules.extend(car_rules)
            car_loaded_count = sum(1 for r in car_rules if not r.skipped_reason)
            # Also count the analytics that DIDN'T have an embedded
            # sigma snippet. MITRE's upstream CAR repo carries
            # `type: Sigma` implementations as URL references rather
            # than inline `code:` blocks, so the loader returns 0 on
            # a fresh clone even when 100+ analytics are present.
            # Surfacing both counts in the summary keeps the analyst
            # from chasing a phantom misconfiguration.
            from pathlib import Path as _P
            d = _P(car_dir)
            yamls = (list(d.glob("*.yaml")) + list(d.glob("*.yml"))
                     if d.is_dir() else [d])
            car_total_analytics = sum(
                1 for p in yamls if parse_analytic(p) is not None)
        loaded = [r for r in rules if not r.skipped_reason]
        skipped = [r for r in rules if r.skipped_reason]
        if not loaded:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"SigmaAnalyst: rules dir {rules_dir} held "
                       f"{len(skipped)} rule(s), all unparseable/"
                       f"unsupported."),
            ))]

        hits = se.run_rules_against_csv(loaded, csv_path)
        csv_sha = hashlib.sha256(csv_path.read_bytes()).hexdigest()

        out: list[Finding] = []
        summary_ev = EvidenceItem(
            tool="el.sigma_engine", version="0.1.0",
            command=f"sigma_engine.run_rules_against_csv({csv_path.name})",
            output_sha256=csv_sha, output_path=str(csv_path),
            extracted_facts={
                "rules_loaded": len(loaded),
                "rules_skipped": len(skipped),
                "rules_matched": len(hits),
                "rules_dir": str(rules_dir),
                "car_rules_loaded": car_loaded_count,
                "car_rules_dir": str(car_dir) if car_dir else "",
            },
        )
        # CAR note reflects 3 distinct shapes:
        #   1. CAR dir + analytics + sigma snippets all present
        #   2. CAR dir + analytics but 0 sigma snippets (typical for
        #      a fresh clone of MITRE's upstream CAR — their Sigma
        #      impls reference SigmaHQ URLs rather than inlining
        #      `code:` blocks). Doesn't degrade the run; the rules
        #      are still discoverable by the analyst.
        #   3. CAR dir absent (operator never set EL_CAR_RULES /
        #      didn't run install.sh's CAR clone)
        if car_loaded_count:
            car_note = f" + {car_loaded_count} CAR analytic(s) from {car_dir}"
        elif car_total_analytics:
            car_note = (
                f" ({car_total_analytics} CAR analytic(s) found at "
                f"{car_dir} but 0 carried embedded sigma snippets — "
                "MITRE's upstream CAR references SigmaHQ URLs rather "
                "than inlining sigma code; loader works against forks "
                "that embed it)")
        else:
            car_note = ""
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"SigmaAnalyst summary: {len(loaded)} rule(s) loaded "
                   f"from {rules_dir}{car_note}; {len(hits)} rule(s) "
                   f"matched the case's EvtxECmd CSV "
                   f"({'; '.join(f'{h.rule.id}:{h.event_count}' for h in hits[:5]) if hits else 'no matches'})."),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        for h in hits:
            confidence = _LEVEL_TO_CONFIDENCE.get(h.rule.level.lower(),
                                                    "medium")
            hyps = _hypotheses_from_tags(h.rule.tags)
            techniques = h.attack_techniques()
            facts = {
                "sigma_rule_id": h.rule.id,
                "sigma_level": h.rule.level,
                "event_count": h.event_count,
                "first_seen_utc": h.first_seen,
                "last_seen_utc": h.last_seen,
                "attack_techniques": techniques,
                "tags": h.rule.tags[:20],
                "sample_eids": sorted({
                    int(r.get("EventId", "0") or "0")
                    for r in h.sample_rows
                    if str(r.get("EventId", "0") or "0").isdigit()
                }),
                "rule_path": str(h.rule.file_path),
            }
            ev = EvidenceItem(
                tool="el.sigma_engine", version="0.1.0",
                command=f"evaluate_rule({h.rule.id})",
                output_sha256=csv_sha, output_path=str(csv_path),
                extracted_facts=facts,
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"SIGMA rule [{h.rule.level}] "
                       f"'{h.rule.title}' ({h.rule.id}): "
                       f"{h.event_count} event(s) matched; "
                       f"first={h.first_seen or '?'}, "
                       f"last={h.last_seen or '?'}. "
                       f"ATT&CK: {', '.join(techniques) or '-'}."),
                evidence=[ev],
                hypotheses_supported=hyps or ["H_DISK_ARTIFACTS"],
            )))
        return out
