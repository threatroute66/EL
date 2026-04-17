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
from el.intel.hypotheses import HYPOTHESES, by_id
from el.schemas.finding import EvidenceItem, Finding


@dataclass
class HypothesisRow:
    hyp_id: str
    name: str
    score: int = 0
    supporting_findings: list[str] = field(default_factory=list)
    refuting_findings: list[str] = field(default_factory=list)


def score_findings(findings: list[Finding]) -> tuple[list[HypothesisRow], list[Finding]]:
    """Returns (ranked rows, mutated findings with ach_score_delta filled)."""
    rows = {h.hyp_id: HypothesisRow(hyp_id=h.hyp_id, name=h.name) for h in HYPOTHESES}

    for f in findings:
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

    ranked = sorted(rows.values(), key=lambda r: (-r.score, r.hyp_id))
    return ranked, findings


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
    try:
        import hashlib
        sha = hashlib.sha256(matrix_path.read_bytes()).hexdigest()
    except Exception:
        pass

    ev = EvidenceItem(
        tool="el.ach_engine", version="0.1.0",
        command=f"ACH score over {len(HYPOTHESES)} hypotheses",
        output_sha256=sha, output_path=str(matrix_path),
        extracted_facts={
            "leader": leader.hyp_id, "leader_score": leader.score,
            "runner_up": runner_up.hyp_id if runner_up else None,
            "runner_up_score": runner_up.score if runner_up else None,
            "gap": gap,
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
