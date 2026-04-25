"""Render a Key Assumptions Check (KAC) section for the case report.

Companion to :mod:`el.intel.kac`. Pure markdown rendering — no
side effects, no I/O. The case-report writer (``el report``) calls
``render_kac_md(findings, top_hypothesis)`` and inlines the result
into the deterministic projection.
"""
from __future__ import annotations

from el.intel.kac import KACAssumption, build_kac
from el.schemas.finding import Finding


def render_kac_md(findings: list[Finding] | None = None,
                   *, top_hypothesis: str | None = None,
                   extra: list[KACAssumption] | None = None,
                   header_level: int = 2) -> str:
    """Return a markdown ``## Key Assumptions Check`` section
    populated from the supplied findings + optional hypothesis
    label. Returns the empty string only when no assumptions
    exist — never possible in practice because the baseline
    set is non-empty."""
    assumptions = build_kac(findings, top_hypothesis=top_hypothesis,
                            extra=extra)
    if not assumptions:
        return ""
    h = "#" * max(1, min(header_level, 6))
    lines: list[str] = [
        f"{h} Key Assumptions Check",
        "",
        ("The KAC surfaces the assumptions baked into this case's "
         "conclusion so each can be challenged on its own merits "
         "(Heuer / IC structured-analytic technique). Confidence + "
         "impact + status follow the standard ladder; the "
         "rationale points at the evidence anchor that supports — "
         "or fails to support — the assumption."),
        "",
        "| # | Assumption | Confidence | Impact | Status | Rationale |",
        "|---|---|---|---|---|---|",
    ]
    for i, a in enumerate(assumptions, 1):
        text = _md_escape(a.text)
        rationale = _md_escape(a.rationale)
        lines.append(
            f"| {i} | {text} | {a.confidence} | {a.impact} | "
            f"{a.status} | {rationale} |"
        )
    # Tail tally — useful when KAC is large; reviewers scan this first.
    by_status = {"Valid": 0, "Conditional": 0, "Invalid": 0}
    for a in assumptions:
        by_status[a.status] = by_status.get(a.status, 0) + 1
    lines += [
        "",
        (f"**Tally:** {by_status['Valid']} Valid · "
         f"{by_status['Conditional']} Conditional · "
         f"{by_status['Invalid']} Invalid "
         f"(total {len(assumptions)})"),
    ]
    return "\n".join(lines) + "\n"


def _md_escape(s: str) -> str:
    """Escape pipes and newlines so the markdown table doesn't
    break — assumption text and rationale can carry both."""
    return (s or "").replace("|", "\\|").replace("\n", " ")


__all__ = ["render_kac_md"]
