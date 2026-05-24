"""Render an Activity Thread for the case.

Faithful to Caltagirone, Pendergast & Betz (2013) §8. The paper
defines the Activity Thread as:

    AT = (V, A), a directed phase-ordered graph where each vertex
    is a Diamond event and each arc (i, j) is labelled with the
    4-tuple (Confidence, AND/OR, Hypothesis/Actual, Provides).

EL renders the thread as a phase-bucketed markdown table because
the report is consumed as flat text — the per-case Kùzu graph at
`graph.kuzu/` holds the actual DAG for analysts who want to pivot.

PHASE MODEL

The paper allows any phased model of adversary operations
(§4.5.2, footnote 7: "our model can utilize any phased model …").
EL uses the MITRE ATT&CK tactic order from
``el.intel.attack_tactics.TACTICS`` because every EL finding that
carries an ``attack_techniques`` fact already maps to a tactic via
``TECHNIQUE_TACTIC``. This is a strict superset of the original
Lockheed kill chain (Recon → Weaponization → … → Action on
Objectives) and gives the analyst finer phase-level resolution.

EVENT vs HYPOTHESIS

Each Finding becomes an event. ``Finding.confidence`` maps directly
to the paper's per-arc Confidence label. ``Hypothesis/Actual``
follows from confidence:

  * confidence in {high, medium, low}  → "Actual"
  * confidence == "insufficient"        → "Hypothesis"

This matches the paper's convention (§8 example tables): observed
evidence is Actual; gap-filling reasoning is Hypothesis.

AND/OR and Provides

These arc labels need causal relationships between events. EL's
ledger doesn't currently encode those — findings are emitted
independently by per-domain agents. So this projection shows each
event in its phase bucket with its Provides set (= the technique
IDs the event tags); AND/OR causality would require a downstream
correlator pass that's left to future work.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from el.intel.attack_tactics import TACTICS, TECHNIQUE_TACTIC
from el.schemas.finding import Finding


def _format_id(fid: str) -> str:
    """Shorten ULID for readability — the suffix is enough to
    identify a finding within a single case report."""
    return fid[-6:] if fid and len(fid) > 6 else (fid or "")


def _event_phase(techniques: list[str]) -> str | None:
    """Pick the earliest-phase tactic for a multi-tactic event so
    each event appears exactly once in the thread (paper §8: the
    activity thread is phase-ordered, each vertex placed in 'the
    tuple which matches its phase'). Returns None when no
    technique maps cleanly to a known tactic."""
    if not techniques:
        return None
    candidate_phases = [
        TECHNIQUE_TACTIC[t] for t in techniques
        if t in TECHNIQUE_TACTIC
    ]
    if not candidate_phases:
        return None
    # Earliest phase wins per the order in TACTICS
    return min(candidate_phases, key=lambda p: TACTICS.index(p))


def _collect_techniques(f: Finding) -> list[str]:
    """Union of attack_techniques across the finding's evidence
    items. Deduped, deterministically ordered."""
    seen: list[str] = []
    for ev in f.evidence:
        facts = ev.extracted_facts or {}
        for key in ("attack_techniques", "attack_techniques_list"):
            for tid in facts.get(key) or []:
                tid = str(tid)
                if tid not in seen:
                    seen.append(tid)
    return seen


def _classify_status(confidence: str) -> str:
    """Map EL confidence to the paper's Hypothesis/Actual label."""
    if confidence == "insufficient":
        return "Hypothesis"
    return "Actual"


def _escape_md_cell(s: str) -> str:
    """Strip newlines + escape pipes so a multi-line claim never
    breaks the table grid. Trim long claims so the column stays
    scannable; full text remains in the Findings section below."""
    if not s:
        return ""
    one_line = " ".join(s.split())
    if len(one_line) > 160:
        one_line = one_line[:157] + "…"
    return one_line.replace("|", "\\|")


def build_activity_thread_markdown(
    findings: list[Finding],
    ach_ranking: list,
) -> list[str]:
    """Render the Activity Thread section.

    Empty list when no finding carries a mapped technique — without
    phase data there's nothing to bucket.

    The thread is scoped to the leading hypothesis (paper §8: "each
    thread is specific to one adversary-victim pair"). When no
    leading hypothesis exists or none of its supporting findings
    carry techniques, the renderer widens to all findings with
    techniques and notes the widening in the section header.
    """
    if not findings:
        return []

    leading_hyp = ach_ranking[0].hyp_id if ach_ranking else None
    leading_name = ach_ranking[0].name if ach_ranking else None

    # Pass 1: try the leading-hypothesis-only scope first
    scoped_events: list[tuple[Finding, list[str], str]] = []
    scope_widened = False
    if leading_hyp:
        for f in findings:
            if leading_hyp not in f.hypotheses_supported:
                continue
            techs = _collect_techniques(f)
            phase = _event_phase(techs)
            if phase:
                scoped_events.append((f, techs, phase))

    # Pass 2: widen to every finding when the leading scope is empty
    if not scoped_events:
        scope_widened = True
        for f in findings:
            techs = _collect_techniques(f)
            phase = _event_phase(techs)
            if phase:
                scoped_events.append((f, techs, phase))

    if not scoped_events:
        return []

    # Bucket by phase, preserve created_utc order within each bucket
    bucket: dict[str, list[tuple[Finding, list[str], str]]] = defaultdict(list)
    for ev in scoped_events:
        bucket[ev[2]].append(ev)
    for phase in bucket:
        bucket[phase].sort(key=lambda e: e[0].created_utc or "")

    lines: list[str] = []
    lines.append("## Activity Thread — Phase-Ordered Events")
    lines.append("")
    scope_note = (
        f"Scoped to leading hypothesis **{leading_name}** "
        f"(`{leading_hyp}`)."
        if leading_hyp and not scope_widened else
        "Widened to all findings with technique tags — the leading "
        "hypothesis has no phase-tagged supporting findings, so the "
        "thread shows the full case activity instead."
        if leading_hyp else
        "No leading hypothesis — thread shows every finding with "
        "phase-tagged techniques."
    )
    lines.append(
        f"Per Caltagirone/Pendergast/Betz (2013) §8: each event is a "
        f"Diamond vertex, placed in the MITRE ATT&CK tactic that "
        f"matches its earliest-mapped technique. {scope_note} The "
        f"full causal DAG (AND/OR arcs, Provides chain) lives in the "
        f"per-case Kùzu graph at `graph.kuzu/`."
    )
    lines.append("")
    lines.append(
        f"_{len(scoped_events)} event(s) across "
        f"{len(bucket)} phase(s)._"
    )
    lines.append("")

    # Walk phases in canonical order — empty buckets are skipped
    for phase in TACTICS:
        events = bucket.get(phase)
        if not events:
            continue
        lines.append(f"### {phase}")
        lines.append("")
        lines.append("| Event | Status | Confidence | "
                      "Provides (techniques) | Claim |")
        lines.append("|---|---|---|---|---|")
        for f, techs, _ in events:
            status = _classify_status(f.confidence)
            provides = ", ".join(f"`{t}`" for t in techs[:6])
            if len(techs) > 6:
                provides += f" _+{len(techs) - 6} more_"
            event_label = (f"`{_format_id(f.finding_id)}` "
                            f"({f.agent})")
            claim_cell = _escape_md_cell(f.claim or "")
            lines.append(
                f"| {event_label} | {status} | "
                f"{f.confidence} | {provides} | {claim_cell} |"
            )
        lines.append("")

    return lines
