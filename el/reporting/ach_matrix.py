"""Render a Heuer-style ACH consistency matrix as markdown.

The ACH matrix is the standard analytic-tradecraft deliverable of a
structured-hypothesis analysis: findings down, hypotheses across, a
consistent / inconsistent / neutral cell at each intersection. It
makes the diagnosticity of each finding visually obvious — the
findings whose row has the most cells filled are the ones that
discriminate most between hypotheses (Heuer's "most diagnostic").

EL stores the per-finding, per-hypothesis delta under
`Finding.ach_score_delta`. This module renders that into markdown:

  | finding_id | claim (trimmed) | H_A | H_B | H_C | ... |
  |---|---|:---:|:---:|:---:|...
  | 01ABC… | psscan hidden procs | +3 | -- | +1 | ... |
  | 01DEF… | vssadmin delete … | -- | +2 | +3 | ... |

Each cell is one of:
  `+N` — finding supports the hypothesis with score +N
  `-N` — finding refutes (negative delta)
  `--` — no contribution (delta == 0)

Only rows with at least one non-zero delta are shown; findings with
no ACH bearing are diagnostic noise here.
"""
from __future__ import annotations

from el.schemas.finding import Finding


def _cell(delta: int) -> str:
    if delta == 0:
        return "--"
    return f"{delta:+d}"


def build_ach_matrix_markdown(
    findings: list[Finding],
    ach_ranking: list,
) -> list[str]:
    """Return a list of markdown lines. Empty list when there's no
    signal (no findings with score deltas OR no ranking)."""
    if not ach_ranking or not findings:
        return []

    # Column order follows the ranking (leading hypothesis first).
    hyp_ids = [r.hyp_id for r in ach_ranking]

    # Filter to findings that contribute to at least one hypothesis
    diag = [f for f in findings
            if f.ach_score_delta
            and any(f.ach_score_delta.get(h, 0) != 0 for h in hyp_ids)]
    if not diag:
        return []

    # Stable order: by max absolute contribution descending, then
    # by finding_id for determinism.
    def _max_abs(f: Finding) -> int:
        return max(abs(f.ach_score_delta.get(h, 0)) for h in hyp_ids)
    diag.sort(key=lambda f: (-_max_abs(f), f.finding_id))

    lines: list[str] = []
    lines.append("## ACH Matrix (Heuer Analysis of Competing Hypotheses)")
    lines.append("")
    lines.append("Consistency grid: each row is a Finding; each column is a "
                  "ranked hypothesis. `+N` = finding supports the hypothesis "
                  "with that score delta; `-N` = refutes; `--` = no bearing. "
                  "Findings are sorted by the largest absolute delta in any "
                  "column — the top rows are the most diagnostic per Heuer.")
    lines.append("")

    # Header with short hypothesis IDs (dropping the H_ prefix for width)
    short = [h.removeprefix("H_") for h in hyp_ids]
    lines.append("| Finding | Claim | " + " | ".join(short) + " |")
    lines.append("|---|---|" + "|".join(":---:" for _ in short) + "|")

    for f in diag:
        claim_trim = (f.claim[:70] + "…") if len(f.claim) > 71 else f.claim
        # Markdown-escape pipe chars in claim
        claim_trim = claim_trim.replace("|", "\\|")
        cells = " | ".join(_cell(f.ach_score_delta.get(h, 0)) for h in hyp_ids)
        lines.append(f"| `{f.finding_id}` | {claim_trim} | {cells} |")
    lines.append("")
    return lines


__all__ = ["build_ach_matrix_markdown"]
