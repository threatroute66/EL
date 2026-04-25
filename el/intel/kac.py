"""Key Assumptions Check (KAC) — structured-analytic technique.

Closes the gap-doc Intel-depth bullet "KAC structured-technique
template". The KAC is one of the four core CIA/IC structured-
analytic techniques (alongside ACH, Devil's Advocacy, and Red Hat
Analysis). It forces the analyst to surface the assumptions baked
into a conclusion so each one can be challenged on its own merits
rather than being silently inherited from "the way we always do
this."

A KAC is a list of statements, each annotated with:

- ``text``       — the assumption itself
- ``confidence`` — Solid | Caveats | Unsupported
- ``impact``     — High | Medium | Low (severity if assumption is wrong)
- ``status``     — Valid | Conditional | Invalid
- ``rationale``  — supporting / refuting evidence pointer

EL builds the KAC from two pools:

1. **Baseline assumptions** — the standing methodological claims
   every EL investigation makes (intake hash integrity, parser
   correctness, ACH considered alternatives, chain of custody,
   UTC, Layer-3 cross-case-is-suggestive contract). These are
   identical across cases; they appear so a reviewer can verify
   they were CHECKED, not skipped.
2. **Per-finding derived assumptions** — generated from the
   actual Finding ledger. Examples: every ``confidence='low'``
   Finding adds an assumption "the heuristic match in <claim> is
   accurate" with confidence='Caveats'. Every Finding citing a
   feed source (``threat_feeds``) adds "the external feed is
   authoritative for these IOCs" at confidence='Caveats'.

The companion ``el.reporting.kac.render_kac_md`` turns the list
into a markdown table for the case report.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from el.schemas.finding import Finding


_CONFIDENCE = ("Solid", "Caveats", "Unsupported")
_IMPACT = ("High", "Medium", "Low")
_STATUS = ("Valid", "Conditional", "Invalid")


@dataclass
class KACAssumption:
    text: str
    confidence: str = "Solid"             # Solid | Caveats | Unsupported
    impact: str = "Medium"                # High | Medium | Low
    status: str = "Valid"                 # Valid | Conditional | Invalid
    rationale: str = ""                   # short supporting note

    def __post_init__(self):
        if self.confidence not in _CONFIDENCE:
            raise ValueError(
                f"confidence must be one of {_CONFIDENCE}; "
                f"got {self.confidence!r}")
        if self.impact not in _IMPACT:
            raise ValueError(
                f"impact must be one of {_IMPACT}; got {self.impact!r}")
        if self.status not in _STATUS:
            raise ValueError(
                f"status must be one of {_STATUS}; got {self.status!r}")


# --- baseline assumptions ----------------------------------------------

# Pinned at module scope so they can be inspected / asserted by tests
# without rebuilding through `build_kac()`.
BASELINE_ASSUMPTIONS: tuple[KACAssumption, ...] = (
    KACAssumption(
        text=("Intake correctly identified the evidence type and "
              "the SHA-256 manifest matches the source media."),
        confidence="Solid", impact="High", status="Valid",
        rationale="cases/<id>/manifest.json + provisioning snapshot",
    ),
    KACAssumption(
        text=("Court-vetted parsers (Volatility 3, EvtxECmd, "
              "MFTECmd, Plaso, fls/mactime) correctly interpret "
              "the underlying binary structures."),
        confidence="Solid", impact="High", status="Valid",
        rationale="EvidenceItem.tool + version + sha256 chain",
    ),
    KACAssumption(
        text=("Alternative hypotheses (≥3 including a null) have "
              "been considered and scored against the evidence."),
        confidence="Solid", impact="High", status="Valid",
        rationale="el/intel/ach.py — see ACH ranking section",
    ),
    KACAssumption(
        text=("Chain of custody is intact: evidence directories "
              "remain read-only and analysis output is sha256-"
              "manifested at coordinator-DONE."),
        confidence="Solid", impact="High", status="Valid",
        rationale="el/seal.py + cases/_archives/<id>-<TS>.tar.gz",
    ),
    KACAssumption(
        text=("All timestamps are UTC; no timezone drift between "
              "host clock and recorded events."),
        confidence="Solid", impact="Medium", status="Valid",
        rationale="datetime.now(timezone.utc) throughout EL",
    ),
    KACAssumption(
        text=("Cross-case IOC overlap is treated as suggestive "
              "context only; Layer-3 knowledge.sqlite hits never "
              "directly score a hypothesis in this case."),
        confidence="Solid", impact="Medium", status="Valid",
        rationale="confidence='low' enforced on knowledge_lookup findings",
    ),
    KACAssumption(
        text=("The Red Reviewer ran against every Finding and no "
              "RedReview.status == 'unresolved' remains."),
        confidence="Solid", impact="High", status="Valid",
        rationale=("coordinator refuses SYNTHESIZE while any "
                   "finding is unresolved"),
    ),
)


# --- per-finding derivation --------------------------------------------


def _from_low_confidence(findings: Iterable[Finding]
                          ) -> list[KACAssumption]:
    """Every ``confidence='low'`` claim is, by definition, an
    assumption that the analyst is willing to act on but should
    flag as the analyst's risk."""
    out: list[KACAssumption] = []
    for f in findings:
        if f.confidence != "low":
            continue
        out.append(KACAssumption(
            text=(f"The low-confidence claim — '{f.claim[:140]}' — "
                  f"is correctly attributed to {f.agent}."),
            confidence="Caveats",
            impact="Medium",
            status="Conditional",
            rationale=f"finding {f.finding_id} (agent={f.agent})",
        ))
    return out


def _from_insufficient(findings: Iterable[Finding]
                        ) -> list[KACAssumption]:
    """Every insufficient finding is a known gap. Surface as an
    explicit "we did NOT confirm X" assumption so the reviewer
    sees what's missing rather than assuming it was checked."""
    out: list[KACAssumption] = []
    for f in findings:
        if f.confidence != "insufficient":
            continue
        out.append(KACAssumption(
            text=(f"Investigators accept the gap noted in "
                  f"'{f.claim[:140]}' will not be filled in this case."),
            confidence="Caveats",
            impact="Medium",
            status="Conditional",
            rationale=(f"finding {f.finding_id} — agent {f.agent} "
                       "could not produce evidence"),
        ))
    return out


def _from_external_feed(findings: Iterable[Finding]
                         ) -> list[KACAssumption]:
    """Findings ultimately rooted in an external feed (MISP/TAXII)
    inherit that feed's reputational risk."""
    seen_agents: set[str] = set()
    out: list[KACAssumption] = []
    for f in findings:
        if f.agent != "threat_feeds":
            continue
        if f.agent in seen_agents:
            continue
        seen_agents.add(f.agent)
        out.append(KACAssumption(
            text=("External threat-intel feeds (MISP / TAXII) used "
                  "for cross-case context are accurate and "
                  "current."),
            confidence="Caveats",
            impact="Low",
            status="Conditional",
            rationale=("feed observations carry confidence='low' "
                       "and never score hypotheses directly"),
        ))
    return out


def _from_heuristic_evidence(findings: Iterable[Finding]
                              ) -> list[KACAssumption]:
    """Findings whose evidence has Admiralty A2 (heuristic match —
    yara, capa, sigma, diec, tlsh) are by-construction less
    deterministic than A1 binary parses."""
    if any(
        any((ev.source_reliability == "A" and ev.info_credibility == "2")
            for ev in f.evidence)
        for f in findings
    ):
        return [KACAssumption(
            text=("Heuristic matchers (YARA / capa / sigma / diec / "
                  "TLSH) used in this case correctly classify the "
                  "samples they fired on."),
            confidence="Caveats",
            impact="Medium",
            status="Conditional",
            rationale="EvidenceItem.admiralty == 'A2' for one+ items",
        )]
    return []


def build_kac(findings: list[Finding] | None = None,
               *, top_hypothesis: str | None = None,
               extra: list[KACAssumption] | None = None
               ) -> list[KACAssumption]:
    """Assemble the KAC list for a case.

    Parameters
    ----------
    findings : the case ledger (or any subset to KAC).
    top_hypothesis : human-readable label of the leading
        hypothesis. Surfaces as an assumption in its own right
        (the analyst's commitment that this hypothesis best
        explains the evidence, falsifiable on its terms).
    extra : caller-supplied KACAssumption entries to append after
        the derived set — useful for case-specific gotchas the
        analyst wants on the record.
    """
    out: list[KACAssumption] = list(BASELINE_ASSUMPTIONS)
    if top_hypothesis:
        out.append(KACAssumption(
            text=(f"The leading hypothesis '{top_hypothesis}' best "
                  "explains the evidence pattern after ACH ranking."),
            confidence="Solid",
            impact="High",
            status="Valid",
            rationale="ACH ranking; refer to ACH matrix for scoring",
        ))
    if findings:
        out.extend(_from_low_confidence(findings))
        out.extend(_from_insufficient(findings))
        out.extend(_from_external_feed(findings))
        out.extend(_from_heuristic_evidence(findings))
    if extra:
        out.extend(extra)
    return out


def baseline_count() -> int:
    """Number of always-on baseline assumptions — useful for tests
    that assert the per-finding derivation added the right delta."""
    return len(BASELINE_ASSUMPTIONS)


__all__ = [
    "KACAssumption",
    "BASELINE_ASSUMPTIONS",
    "build_kac",
    "baseline_count",
]
