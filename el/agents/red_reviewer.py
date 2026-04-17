"""Red Reviewer — adversarial challenger.

Composition:
  1. Rule-Based Challenger ALWAYS runs (deterministic baseline).
  2. LLM Challenger runs additionally if ANTHROPIC_API_KEY is set.

Final red_review.status per finding = severity-merge of both:
  challenged > unresolved > passed
This means a single 'challenged' from either source dominates — the bias
is toward demanding more evidence, never toward fake-passing.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from el.agents.base import Agent, AgentContext
from el.challengers.rules import challenge as rule_challenge
from el.evidence.ledger import insert as ledger_insert, list_findings
from el.schemas.finding import Finding, RedReview


CHALLENGER_MODEL = os.environ.get("EL_RED_MODEL", "claude-opus-4-7")
SYSTEM = """You are an adversarial DFIR Red Reviewer. Your job is to falsify findings, not validate them.

For EACH finding given, produce strict JSON of the form:
{
  "finding_id": "<id>",
  "status": "passed" | "challenged" | "unresolved",
  "challenger_notes": "<2-4 sentences naming the strongest counter-explanation or alternate hypothesis>",
  "disconfirming_checklist": ["<concrete artifact or query that, if absent or contrary, would refute this finding>", ...]
}

Rules:
- 'passed' only if you cannot construct any plausible alternative explanation given the evidence summary.
- 'challenged' if a benign or alternate-hypothesis explanation exists but the evidence still leans toward the claim.
- 'unresolved' if evidence is too thin to evaluate.
- Each disconfirming checklist item MUST be operational: a specific log, registry key, file, plugin, or query.
- Do not be agreeable. Default toward 'challenged' when in doubt.
- Output a JSON array of these objects, nothing else."""


_SEVERITY = {"passed": 0, "unresolved": 1, "challenged": 2}


@dataclass
class _ChallengeResult:
    status: str
    notes: str
    checklist: list[str]


def _merge(rule: _ChallengeResult, llm: _ChallengeResult | None) -> _ChallengeResult:
    if llm is None:
        return rule
    if _SEVERITY[llm.status] > _SEVERITY[rule.status]:
        winner_status = llm.status
    else:
        winner_status = rule.status
    notes = "; ".join(filter(None, [
        f"rule: {rule.notes}" if rule.notes else "",
        f"llm: {llm.notes}" if llm.notes else "",
    ]))
    checklist = list(rule.checklist) + [c for c in llm.checklist if c not in rule.checklist]
    return _ChallengeResult(status=winner_status, notes=notes, checklist=checklist)


def _llm_challenge(reviewable: list[Finding]) -> dict[str, _ChallengeResult] | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    client = anthropic.Anthropic(api_key=api_key)
    payload = [{
        "finding_id": f.finding_id,
        "agent": f.agent,
        "claim": f.claim,
        "confidence": f.confidence,
        "evidence_summary": [
            {"tool": e.tool, "command": e.command, "facts": e.extracted_facts}
            for e in f.evidence
        ],
        "hypotheses_supported": f.hypotheses_supported,
    } for f in reviewable]

    try:
        msg = client.messages.create(
            model=CHALLENGER_MODEL,
            max_tokens=4096,
            system=SYSTEM,
            messages=[{"role": "user", "content": json.dumps(payload)}],
        )
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        start = text.index("[")
        end = text.rindex("]") + 1
        reviews = json.loads(text[start:end])
    except Exception:
        return None

    out: dict[str, _ChallengeResult] = {}
    for r in reviews:
        fid = r.get("finding_id")
        if not fid:
            continue
        out[fid] = _ChallengeResult(
            status=r.get("status", "unresolved"),
            notes=r.get("challenger_notes", ""),
            checklist=list(r.get("disconfirming_checklist", [])),
        )
    return out


class RedReviewerAgent(Agent):
    name = "red_reviewer"

    def run(self, ctx: AgentContext) -> list[Finding]:
        existing = list_findings(ctx.case_dir, case_id=ctx.case_id)
        reviewable = [f for f in existing
                      if f.confidence in ("high", "medium", "low") and f.agent != self.name]

        if not reviewable:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="No reviewable findings present — nothing to challenge",
            ))]

        rule_results: dict[str, _ChallengeResult] = {}
        for f in reviewable:
            status, notes, checklist = rule_challenge(f)
            rule_results[f.finding_id] = _ChallengeResult(status, notes, checklist)

        llm_results = _llm_challenge(reviewable)

        passed = challenged = unresolved = 0
        for f in reviewable:
            merged = _merge(rule_results[f.finding_id],
                            llm_results.get(f.finding_id) if llm_results else None)
            f.red_review = RedReview(
                status=merged.status,
                challenger_notes=merged.notes,
                disconfirming_checklist=merged.checklist,
            )
            ledger_insert(ctx.case_dir, f)
            if merged.status == "passed":
                passed += 1
            elif merged.status == "challenged":
                challenged += 1
            else:
                unresolved += 1

        mode = "rule+llm" if llm_results is not None else "rule-only"
        summary = (f"Adversarial review ({mode}): passed={passed}, "
                   f"challenged={challenged}, unresolved={unresolved}")
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            claim=summary, confidence="high",
            evidence=reviewable[0].evidence[:1] if reviewable[0].evidence else [],
        ))]
