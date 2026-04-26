"""Render actor-playbook fingerprint matches into a markdown
section for the case report.

Companion to :mod:`el.intel.actor_playbooks`. Pure deterministic
projection — no I/O, no network, no LLM. Suggestive only:
attribution is non-forensic and the section text says so.
"""
from __future__ import annotations

from el.intel.actor_playbooks import (
    PlaybookMatch, score_findings, by_actor)
from el.schemas.finding import Finding


def render_actor_matches_md(findings: list[Finding] | None,
                              *,
                              header_level: int = 2,
                              max_matches: int = 5,
                              min_coverage: float = 0.4,
                              ) -> str:
    """Return the markdown section. Empty string when no playbook
    rises above ``min_coverage`` — the section is omitted from
    reports rather than rendered as a "no match" placeholder."""
    if not findings:
        return ""
    raw = score_findings(findings)
    matches = [m for m in raw if m.coverage >= min_coverage][:max_matches]
    if not matches:
        return ""
    h = "#" * max(1, min(header_level, 6))
    lines: list[str] = [
        f"{h} Actor-Playbook Resemblance",
        "",
        ("This section ranks the case's observed ATT&CK technique "
         "set against curated APT-actor playbooks (MITRE-Group-"
         "profile-derived). **Suggestive only** — attribution is "
         "outside the scope of EL's forensic chain. A high match "
         "means the kill-chain shape resembles the actor's "
         "documented TTPs, not that the actor is responsible."),
        "",
        ("| Rank | Actor | Coverage | Score | Matched | Missing | "
         "References |"),
        ("|---:|---|---:|---:|---|---|---|"),
    ]
    for i, m in enumerate(matches, 1):
        pb = m.playbook
        aliases = (f" (a.k.a. {', '.join(pb.aliases[:2])})"
                    if pb.aliases else "")
        matched = ", ".join(f"`{t}`" for t in m.matched[:6])
        if len(m.matched) > 6:
            matched += f", … (+{len(m.matched) - 6})"
        missing = ", ".join(f"`{t}`" for t in m.missing[:4]) or "—"
        if len(m.missing) > 4:
            missing += f", … (+{len(m.missing) - 4})"
        refs = ", ".join(pb.references[:1])
        lines.append(
            f"| {i} | **{pb.actor}**{aliases} | "
            f"{m.coverage*100:.0f}% | {m.score:.2f} | "
            f"{matched} | {missing} | {refs} |"
        )
    lines += [
        "",
        ("_Coverage is the fraction of the actor's playbook the case "
         "observed; score weights coverage by the square root of the "
         "matched-technique count so a deeper partial match outranks "
         "a wider shallow one._"),
    ]
    return "\n".join(lines) + "\n"


__all__ = ["render_actor_matches_md"]
