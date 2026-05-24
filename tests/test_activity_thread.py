"""Contract tests for the Activity Thread renderer.

Locks in the paper-faithful behaviour of
``el/reporting/activity_thread.py`` per Caltagirone/Pendergast/Betz
(2013) §8:

  * Phase-bucketed table — one section per MITRE ATT&CK tactic
    that has at least one event
  * Each event placed in the EARLIEST mapped phase per the TACTICS
    canonical order (multi-tactic techniques don't appear twice)
  * Status = "Actual" for confidence ∈ {high, medium, low},
    "Hypothesis" for confidence == "insufficient"
  * Scope = supporting findings of the leading hypothesis when
    available; widens to all findings (with header note) when the
    leading hypothesis has no phase-tagged supports — this matches
    the LoneWolf shape where the leader (H_ANTI_FORENSICS) has
    plenty of findings but none carry attack_techniques
  * Empty thread (no findings carry mapped techniques) → empty list,
    not a half-rendered section
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from el.reporting.activity_thread import build_activity_thread_markdown
from el.schemas.finding import EvidenceItem, Finding


def _ev(facts: dict | None = None) -> EvidenceItem:
    return EvidenceItem(
        tool="x", version="1", command="y", output_sha256="0" * 64,
        output_path="/tmp/z", extracted_facts=facts or {},
    )


def _finding(fid: str, *,
              claim: str = "x",
              confidence: str = "high",
              supports: list[str] | None = None,
              evidence_facts: dict | None = None,
              created_utc: datetime | None = None,
              agent: str = "test_agent") -> Finding:
    f = Finding(
        case_id="at-test",
        agent=agent,
        claim=claim,
        confidence=confidence,
        evidence=[_ev(evidence_facts or {})],
        hypotheses_supported=supports or [],
    )
    # finding_id is auto-generated as ULID — override for predictable test ids
    object.__setattr__(f, "finding_id", fid)
    if created_utc:
        object.__setattr__(f, "created_utc", created_utc)
    return f


def _rank(hyp_id: str, name: str, score: int) -> SimpleNamespace:
    return SimpleNamespace(hyp_id=hyp_id, name=name, score=score)


# ---------------------------------------------------------------------------
# Empty inputs
# ---------------------------------------------------------------------------

def test_empty_findings_returns_empty():
    assert build_activity_thread_markdown([], []) == []


def test_no_findings_with_techniques_returns_empty():
    """When no finding carries attack_techniques, the section
    should be empty — better than rendering a phase grid with
    nothing in it."""
    f = _finding("01A", supports=["H_X"])
    assert build_activity_thread_markdown([f], []) == []


# ---------------------------------------------------------------------------
# Scope: leading-hypothesis-first, widen on empty
# ---------------------------------------------------------------------------

def test_scope_to_leading_hypothesis_supporting_findings():
    """Per paper §8: each thread is specific to one adversary-victim
    pair. When the leading hypothesis has phase-tagged supporting
    findings, only those appear in the thread."""
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    leader_event = _finding(
        "01A", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001"]},
        claim="Beacon detected in netscan output")
    other_event = _finding(
        "02B", supports=["H_OPPORTUNISTIC_COMMODITY"],
        evidence_facts={"attack_techniques": ["T1547.001"]},
        claim="Run-key persistence on commodity malware")
    lines = build_activity_thread_markdown(
        [leader_event, other_event], ranking)
    text = "\n".join(lines)
    assert "01A" in text  # leader-supporting event present
    assert "02B" not in text  # off-thread event excluded
    assert "Scoped to leading hypothesis" in text


def test_scope_widens_when_leader_has_no_phase_tagged_supports():
    """LoneWolf shape: H_ANTI_FORENSICS leads with 13 supporting
    findings but none carry attack_techniques (anti-forensic disk
    findings aren't ATT&CK-tagged). The renderer should widen to
    the full case rather than emit an empty thread."""
    ranking = [_rank("H_ANTI_FORENSICS", "Anti-forensics", 55)]
    anti_forensic_no_techs = _finding(
        "01A", supports=["H_ANTI_FORENSICS"],
        evidence_facts={},
        claim="VSS diff: live Security.evtx scrubbed")
    other_techs_event = _finding(
        "02B", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001"]},
        claim="Netscan beacon")
    lines = build_activity_thread_markdown(
        [anti_forensic_no_techs, other_techs_event], ranking)
    text = "\n".join(lines)
    assert "Widened to all findings" in text
    assert "02B" in text  # the off-leader-but-phase-tagged event


# ---------------------------------------------------------------------------
# Phase bucketing — earliest-phase wins
# ---------------------------------------------------------------------------

def test_event_with_multitactic_technique_lands_in_earliest_phase():
    """T1053.005 (Scheduled Task) is polytactic but maps to
    Execution in TECHNIQUE_TACTIC (the canonical primary). When an
    event carries BOTH T1053.005 (Execution) and T1071 (C2), it
    lands in Execution because Execution precedes Command and
    Control in the TACTICS order."""
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    f = _finding(
        "01A", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001", "T1053.005"]},
        claim="Scheduled-task launcher that also beacons")
    lines = build_activity_thread_markdown([f], ranking)
    text = "\n".join(lines)
    # Section header for Execution must appear BEFORE the event,
    # and there is no Command-and-Control section for this event
    # (it was placed in Execution exclusively)
    exec_idx = text.find("### Execution")
    c2_idx = text.find("### Command and Control")
    assert exec_idx > 0
    assert c2_idx < 0


def test_events_bucketed_by_phase_in_canonical_order():
    """Phases must appear in TACTICS order — Initial Access first,
    Impact last."""
    ranking = [_rank("H_APT_ESPIONAGE", "APT", 20)]
    f_ia = _finding(
        "01A", supports=["H_APT_ESPIONAGE"],
        evidence_facts={"attack_techniques": ["T1566.001"]},
        claim="Phish email", agent="email_forensicator")
    f_exec = _finding(
        "02B", supports=["H_APT_ESPIONAGE"],
        evidence_facts={"attack_techniques": ["T1059.001"]},
        claim="PowerShell spawn", agent="powershell_analyst")
    f_c2 = _finding(
        "03C", supports=["H_APT_ESPIONAGE"],
        evidence_facts={"attack_techniques": ["T1071.001"]},
        claim="HTTPS beacon", agent="network_analyst")
    lines = build_activity_thread_markdown(
        [f_c2, f_ia, f_exec], ranking)
    text = "\n".join(lines)
    ia_idx = text.find("### Initial Access")
    exec_idx = text.find("### Execution")
    c2_idx = text.find("### Command and Control")
    assert ia_idx < exec_idx < c2_idx


# ---------------------------------------------------------------------------
# Status — Actual vs Hypothesis per paper §8
# ---------------------------------------------------------------------------

def test_actual_status_for_high_confidence():
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    f = _finding(
        "01A", supports=["H_C2_BEACONING"], confidence="high",
        evidence_facts={"attack_techniques": ["T1071.001"]})
    text = "\n".join(build_activity_thread_markdown([f], ranking))
    assert "Actual" in text
    assert "Hypothesis" not in text


def test_hypothesis_status_for_insufficient_confidence():
    """Per paper §8: events lacking evidence are recorded as
    Hypothesis — the analyst can still document the suspected
    causal step. EL's `insufficient` confidence maps here."""
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    # NOTE: insufficient findings can have empty evidence per the
    # Pydantic contract, but build_activity_thread only looks at
    # extracted_facts, so we pass a fact-bearing evidence stub.
    f = _finding(
        "01A", supports=["H_C2_BEACONING"], confidence="insufficient",
        evidence_facts={"attack_techniques": ["T1071.001"]})
    text = "\n".join(build_activity_thread_markdown([f], ranking))
    assert "Hypothesis" in text


# ---------------------------------------------------------------------------
# Provides column — the techniques the event tags
# ---------------------------------------------------------------------------

def test_provides_column_lists_techniques():
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    f = _finding(
        "01A", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001", "T1105"]})
    text = "\n".join(build_activity_thread_markdown([f], ranking))
    assert "T1071.001" in text
    assert "T1105" in text


# ---------------------------------------------------------------------------
# Claim-cell sanitisation — pipes must not break the table grid
# ---------------------------------------------------------------------------

def test_pipe_in_claim_escaped():
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    f = _finding(
        "01A", supports=["H_C2_BEACONING"],
        claim="cmd: foo | bar | baz",
        evidence_facts={"attack_techniques": ["T1071.001"]})
    text = "\n".join(build_activity_thread_markdown([f], ranking))
    # Pipes in claim text must be backslash-escaped, never raw
    # (raw pipes would terminate the table cell early)
    assert "foo \\| bar \\| baz" in text


def test_long_claim_truncated():
    """160-char cap keeps the table scannable; full claim text
    lives in the Findings section below."""
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    f = _finding(
        "01A", supports=["H_C2_BEACONING"],
        claim="x" * 500,
        evidence_facts={"attack_techniques": ["T1071.001"]})
    text = "\n".join(build_activity_thread_markdown([f], ranking))
    assert "…" in text  # ellipsis present
    # No row should contain the full 500-char string
    assert "x" * 200 not in text


# ---------------------------------------------------------------------------
# Chronological ordering within each phase
# ---------------------------------------------------------------------------

def test_events_within_phase_chronological():
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    early = _finding(
        "01A", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001"]},
        claim="early-event",
        created_utc=datetime(2025, 1, 1, tzinfo=timezone.utc))
    late = _finding(
        "02B", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001"]},
        claim="late-event",
        created_utc=datetime(2025, 6, 1, tzinfo=timezone.utc))
    # Pass them out of order — renderer must sort by created_utc
    text = "\n".join(
        build_activity_thread_markdown([late, early], ranking))
    early_pos = text.find("early-event")
    late_pos = text.find("late-event")
    assert early_pos > 0 and late_pos > early_pos
