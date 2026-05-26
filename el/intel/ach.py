"""ACH engine — Heuer-style Analysis of Competing Hypotheses.

For each Finding × Hypothesis, compute an integer score delta. Aggregate by
hypothesis to produce a ranked list. Mutates each Finding's
ach_score_delta field with the per-hypothesis impact.

Diagnostic value of a Finding = variance of its scores across hypotheses.
A finding with all-zero scores is non-diagnostic. A finding scored +3 for
APT and -3 for benign is highly diagnostic — Heuer's standard.

The leading hypothesis is reported with its score, but EL never *concludes*
the leading hypothesis is true: it surfaces ranking + diagnostic findings
+ open disconfirmers, and lets the analyst close.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from el.evidence.ledger import insert as ledger_insert
from el.intel.hypotheses import (
    BENIGN_ID, HYPOTHESES, MODIFIER_IDS, by_id,
)
from el.schemas.finding import EvidenceItem, Finding


# How hard the anti-forensic modifier discounts the benign/null
# hypothesis. The discount is capped so a single tampering finding
# can't nuke the null, while a strong cross-host cleanup signal
# meaningfully suppresses "nothing happened here". Per the
# investigative principle that anti-forensic indicators tell you how
# much to trust the ABSENCE of standard artifacts — present tampering
# means absence is uninformative, so the null loses weight.
_BENIGN_DISCOUNT_CAP = 8


def _benign_discount(af_index: int) -> int:
    """Map the accumulated anti-forensic modifier score to a benign-
    hypothesis discount. Half the AF index, capped — gentle enough
    that one timestomp doesn't bury the null, firm enough that an
    estate-wide scrub does."""
    if af_index <= 0:
        return 0
    return min(af_index // 2, _BENIGN_DISCOUNT_CAP)


@dataclass
class HypothesisRow:
    hyp_id: str
    name: str
    score: int = 0
    supporting_findings: list[str] = field(default_factory=list)
    refuting_findings: list[str] = field(default_factory=list)


def score_findings(findings: list[Finding]) -> tuple[list[HypothesisRow], list[Finding]]:
    """Returns (ranked rows, mutated findings with ach_score_delta filled).

    Findings with confidence='insufficient' are EXCLUDED from scoring. Such
    findings represent "we couldn't evaluate this" — they are not evidence
    for or against any hypothesis. Letting them score lets tool-failure
    messages (e.g. "netscan blocked by symbol mismatch") falsely lift the
    C2 hypothesis via keyword matching on the failure text. Same applies
    to "vol3 unavailable" lifting the benign hypothesis.
    """
    rows = {h.hyp_id: HypothesisRow(hyp_id=h.hyp_id, name=h.name) for h in HYPOTHESES}

    for f in findings:
        if f.confidence == "insufficient":
            f.ach_score_delta = {}
            continue
        # Tier-3 cross-case overlap findings are SUGGESTIVE, not load-bearing.
        # The contract (CLAUDE.md "Three knowledge layers") requires they
        # not influence ACH scoring — case B's hypothesis must stand on
        # case B's own evidence; case A is context only. Earlier the
        # `confidence='low'` shielding was insufficient because keyword
        # matches in the cross-case claim text leaked into ACH deltas.
        if f.agent == "knowledge_lookup":
            f.ach_score_delta = {}
            continue
        deltas: dict[str, int] = {}
        for h in HYPOTHESES:
            d = h.score(f)
            deltas[h.hyp_id] = d
            row = rows[h.hyp_id]
            row.score += d
            if d > 0:
                row.supporting_findings.append(f.finding_id)
            elif d < 0:
                row.refuting_findings.append(f.finding_id)
        f.ach_score_delta = {k: v for k, v in deltas.items() if v != 0}

    # Anti-forensic modifier: its accumulated score is a CONTEXTUAL
    # variable, not a competing motive. Discount the benign/null
    # hypothesis by a capped function of the modifier index — present
    # tampering means the absence of standard artifacts is uninformative,
    # so "nothing happened here" loses weight. The modifier rows
    # themselves are then excluded from the ranked leader list below so
    # "the operator scrubbed evidence" (a HOW) can't outrank the actual
    # motive (a WHY). See el.intel.hypotheses MODIFIER_IDS + the
    # is_modifier rationale.
    af_index = sum(rows[mid].score for mid in MODIFIER_IDS if mid in rows)
    if af_index > 0 and BENIGN_ID in rows:
        rows[BENIGN_ID].score -= _benign_discount(af_index)

    # Ranked = competing hypotheses only. Modifiers are surfaced
    # separately via anti_forensic_context(); keeping them out of the
    # ranking is the whole point of the demotion.
    ranked = sorted(
        (r for r in rows.values() if r.hyp_id not in MODIFIER_IDS),
        key=lambda r: (-r.score, r.hyp_id),
    )
    return ranked, findings


def anti_forensic_context(findings: list[Finding]) -> dict | None:
    """Compute the anti-forensic contextual modifier for a finding set.

    Returns None when no anti-forensic / evidence-tampering signal is
    present. Otherwise a dict the reporting layer surfaces as a
    contextual flag:

      {
        "index": int,              # accumulated modifier score
        "benign_discount": int,    # points subtracted from the null
        "indicators": [            # one row per contributing modifier
            {"hyp_id", "name", "score", "support_count"}, ...
        ],
        "contributing_finding_ids": [...],
      }

    This is a pure projection (re-scores the modifier hypotheses); it
    does not mutate findings. Callers: render.py, diamond.py, the
    leading-hypothesis emitter — anywhere the 'how much to trust the
    absence of artifacts' caveat belongs.
    """
    indicators: list[dict] = []
    contributing: set[str] = set()
    index = 0
    for h in HYPOTHESES:
        if h.hyp_id not in MODIFIER_IDS:
            continue
        score = 0
        supporters: list[str] = []
        for f in findings:
            if f.confidence == "insufficient" or f.agent == "knowledge_lookup":
                continue
            d = h.score(f)
            if d > 0:
                score += d
                supporters.append(f.finding_id)
        if score > 0:
            index += score
            contributing.update(supporters)
            indicators.append({
                "hyp_id": h.hyp_id, "name": h.name,
                "score": score, "support_count": len(supporters),
            })
    if index <= 0:
        return None
    indicators.sort(key=lambda r: -r["score"])
    return {
        "index": index,
        "benign_discount": _benign_discount(index),
        "indicators": indicators,
        "contributing_finding_ids": sorted(contributing),
    }


def diagnostic_findings(findings: list[Finding], top_n: int = 5) -> list[Finding]:
    """Findings with the highest variance across hypotheses are the most diagnostic."""
    def variance(f: Finding) -> int:
        if not f.ach_score_delta:
            return 0
        vals = list(f.ach_score_delta.values())
        return max(vals) - min(vals)
    return sorted(findings, key=variance, reverse=True)[:top_n]


def write_matrix(case_dir: Path, ranked: list[HypothesisRow], findings: list[Finding]) -> Path:
    out = case_dir / "ach_matrix.json"
    payload = {
        "ranking": [
            {"hyp_id": r.hyp_id, "name": r.name, "score": r.score,
             "support_count": len(r.supporting_findings),
             "refute_count": len(r.refuting_findings)}
            for r in ranked
        ],
        # Anti-forensic modifier context (None when no tampering
        # signal) — surfaced so reports can show the contextual flag
        # and the benign discount that was applied to the ranking.
        "anti_forensic_context": anti_forensic_context(findings),
        "matrix": [
            {"finding_id": f.finding_id, "claim": f.claim,
             "ach_score_delta": f.ach_score_delta}
            for f in findings
        ],
    }
    out.write_text(json.dumps(payload, indent=2))
    return out


def emit_leading_hypothesis_finding(
    case_id: str, case_dir: Path, ranked: list[HypothesisRow], matrix_path: Path,
) -> Finding:
    """Emit a structured Finding capturing the leading hypothesis + score gap.

    Confidence is bounded by the score gap between #1 and #2 — narrow gaps
    cap confidence at 'low' to prevent over-confident attribution.
    """
    if not ranked:
        f = Finding(case_id=case_id, agent="ach_engine", confidence="insufficient",
                    claim="No hypotheses scored")
        ledger_insert(case_dir, f)
        return f

    leader = ranked[0]
    runner_up = ranked[1] if len(ranked) > 1 else None
    gap = leader.score - (runner_up.score if runner_up else 0)
    hyp = by_id()[leader.hyp_id]

    if leader.score <= 0:
        confidence = "insufficient"
        claim = (f"No hypothesis crossed zero — leading is {leader.name} at {leader.score}; "
                 "evidence is too thin to support any specific case-level explanation")
    elif gap >= 5 and leader.score >= 4:
        confidence = "high"
        claim = (f"Leading hypothesis: {leader.name} (score={leader.score}, gap=+{gap}). "
                 f"{hyp.description}")
    elif gap >= 2:
        confidence = "medium"
        claim = (f"Leading hypothesis: {leader.name} (score={leader.score}, gap=+{gap}). "
                 f"{hyp.description}")
    else:
        confidence = "low"
        claim = (f"Leading hypothesis: {leader.name} (score={leader.score}, gap=+{gap}). "
                 "Score gap is narrow — multiple hypotheses remain plausible.")

    sha = "0" * 64
    af_ctx = None
    try:
        import hashlib
        raw = matrix_path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        af_ctx = json.loads(raw).get("anti_forensic_context")
    except Exception:
        pass

    # Anti-forensic context is appended to the leading-hypothesis claim
    # as a contextual caveat — the modifier no longer competes for the
    # lead, but the analyst must still know the absence of standard
    # artifacts is being weighed against active tampering.
    if af_ctx and confidence != "insufficient":
        names = ", ".join(i["name"] for i in af_ctx["indicators"][:3])
        claim += (
            f" ⚑ Anti-forensic context: {len(af_ctx['indicators'])} "
            f"tampering signal(s) present (index={af_ctx['index']}; "
            f"{names}). The benign/null hypothesis was discounted by "
            f"{af_ctx['benign_discount']} — the absence of standard "
            f"artifacts on this host should be weighed against active "
            f"evidence destruction, not read as innocence."
        )

    ev = EvidenceItem(
        tool="el.ach_engine", version="0.1.0",
        command=f"ACH score over {len(HYPOTHESES)} hypotheses",
        output_sha256=sha, output_path=str(matrix_path),
        extracted_facts={
            "leader": leader.hyp_id, "leader_score": leader.score,
            "runner_up": runner_up.hyp_id if runner_up else None,
            "runner_up_score": runner_up.score if runner_up else None,
            "gap": gap,
            "anti_forensic_index": (af_ctx or {}).get("index", 0),
            "anti_forensic_benign_discount": (af_ctx or {}).get("benign_discount", 0),
        },
    )
    f = Finding(
        case_id=case_id, agent="ach_engine",
        claim=claim, confidence=confidence,
        evidence=[ev] if confidence != "insufficient" else [],
        hypotheses_supported=[leader.hyp_id] if leader.score > 0 else [],
    )
    ledger_insert(case_dir, f)
    return f
