"""Tests for the Executive Narrative synthesizer.

Covers:
  - Beat classification (hypothesis-tag > ATT&CK-technique > agent-name)
  - Evidence-time extraction (artifact time, not EL wall clock)
  - Single-hypothesis narrative + open-questions section
  - Multi-hypothesis parallel narrative when ACH gap < 3
  - Honest "initial compromise not reconstructible" gap statement
"""
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import BaseModel

from el.reporting.narrative import (
    BEATS, NarrativeReport, _beat_from_finding,
    evidence_time, synthesize,
)
from el.schemas.finding import EvidenceItem, Finding, RedReview


def _mk(
    claim: str, *, agent: str = "t", confidence: str = "high",
    hypotheses: list | None = None,
    techniques: list | None = None,
    ach_delta: dict | None = None,
    evidence_time_str: str | None = None,
    red_status: str = "passed",
) -> Finding:
    ef = {}
    if techniques:
        ef["attack_techniques"] = techniques
    if evidence_time_str:
        ef["ts_utc"] = evidence_time_str
    return Finding(
        case_id="t-nar", agent=agent, claim=claim,
        confidence=confidence,
        evidence=[EvidenceItem(
            tool="t", version="0", command="x",
            output_sha256="0" * 64, output_path="/tmp/x",
            extracted_facts=ef)],
        hypotheses_supported=hypotheses or [],
        ach_score_delta=ach_delta or {},
        red_review=RedReview(status=red_status),
    )


class _Rank(BaseModel):
    hyp_id: str
    name: str
    score: int
    supporting_findings: list = []
    refuting_findings: list = []


# ---------------------------------------------------------------------------
# Beat classification
# ---------------------------------------------------------------------------

def test_beat_from_hypothesis_tag_wins():
    f = _mk("persistence via scheduled task",
             hypotheses=["H_PERSISTENCE_SCHEDULED_TASK"])
    assert _beat_from_finding(f) == "persistence"


def test_beat_from_attack_technique_fallback():
    # No hypothesis tag; ATT&CK T1059.001 (PowerShell) maps to
    # Execution tactic → execution beat
    f = _mk("powershell invocation", techniques=["T1059.001"])
    assert _beat_from_finding(f) == "execution"


def test_beat_from_agent_name_fallback():
    # No hypothesis, no techniques — falls through to agent-name hints
    f = _mk("eh", agent="lateral_movement_analyst")
    assert _beat_from_finding(f) == "lateral"
    assert _beat_from_finding(_mk("eh", agent="triage")) == "prologue"
    assert _beat_from_finding(_mk("eh", agent="network_analyst")) \
           == "command_control"


def test_beat_impact_covers_exfil_and_ransom():
    assert _beat_from_finding(_mk(
        "exfil over https",
        hypotheses=["H_INSIDER_EMAIL_EXFIL"])) == "impact"
    assert _beat_from_finding(_mk(
        "ransomware",
        hypotheses=["H_RANSOMWARE"])) == "impact"


# ---------------------------------------------------------------------------
# Evidence-time extraction
# ---------------------------------------------------------------------------

def test_evidence_time_prefers_artifact_time_over_created_utc():
    f = _mk("found an event",
             evidence_time_str="2008-07-19T14:32:00Z")
    dt = evidence_time(f)
    assert dt is not None
    assert dt.year == 2008 and dt.month == 7 and dt.day == 19


def test_evidence_time_none_when_no_timestamp_anywhere():
    f = _mk("nothing timestamped here")
    # No ts_utc in extracted_facts, no ISO date in claim
    assert evidence_time(f) is None


def test_evidence_time_mines_claim_text_as_last_resort():
    f = _mk("mass-wipe of system binaries at 2008-07-18T05:28:48")
    dt = evidence_time(f)
    assert dt is not None and dt.year == 2008


# ---------------------------------------------------------------------------
# Single-hypothesis narrative
# ---------------------------------------------------------------------------

def test_synthesize_produces_per_beat_sections(tmp_path):
    findings = [
        _mk("host is Windows XP, Jean's workstation",
             agent="triage"),
        _mk("PowerShell Mimikatz invocation detected",
             techniques=["T1059.001", "T1003.001"],
             hypotheses=["H_CREDENTIAL_ACCESS"],
             ach_delta={"H_APT_ESPIONAGE": 4}),
        _mk("m57biz.xls emailed to external Hotmail",
             hypotheses=["H_INSIDER_EMAIL_EXFIL"],
             ach_delta={"H_INSIDER_EMAIL_EXFIL": 5}),
    ]
    ach = [_Rank(hyp_id="H_INSIDER_EMAIL_EXFIL",
                  name="Insider exfil", score=9),
           _Rank(hyp_id="H_APT_ESPIONAGE",
                  name="APT espionage", score=4)]
    nr = synthesize(case_id="t-nar", findings=findings,
                     ach_ranking=ach)
    md = nr.as_markdown()
    assert "Executive Narrative" in md
    assert "H_INSIDER_EMAIL_EXFIL" in md
    # Both the credential-access beat and the impact beat render
    assert "Recon + credential-access" in md
    assert "Impact + exfiltration" in md
    # Finding IDs cited inline
    assert f"[{findings[1].finding_id}]" in md
    assert f"[{findings[2].finding_id}]" in md
    # Small-gap alternative section: gap = 9 - 4 = 5 → NOT small, so
    # alt_beats should be empty
    assert nr.alt_beats == []
    assert "Alternative narrative" not in md


def test_synthesize_small_gap_emits_parallel_alt_narrative():
    """When ACH gap between leader and runner-up is < 3, narrative
    presents BOTH hypotheses. This is the M57-Jean requirement: the
    evidence supports both insider-exfil and external-compromise."""
    findings = [
        _mk("m57biz.xls emailed to external address",
             hypotheses=["H_INSIDER_EMAIL_EXFIL",
                          "H_APT_ESPIONAGE"],
             ach_delta={"H_INSIDER_EMAIL_EXFIL": 3,
                         "H_APT_ESPIONAGE": 2}),
        _mk("AIM6 bundleware installer traces on disk",
             hypotheses=["H_APT_ESPIONAGE"],
             ach_delta={"H_APT_ESPIONAGE": 2}),
    ]
    ach = [_Rank(hyp_id="H_INSIDER_EMAIL_EXFIL",
                  name="Insider exfil", score=5),
           _Rank(hyp_id="H_APT_ESPIONAGE",
                  name="Compromise + framed", score=4)]   # gap = 1
    nr = synthesize(case_id="t-nar", findings=findings,
                     ach_ranking=ach)
    md = nr.as_markdown()
    assert nr.leading_gap == 1
    assert nr.alt_beats            # alt narrative populated
    assert "Alternative narrative" in md
    assert "H_APT_ESPIONAGE" in md
    assert "supports more than one theory" in md


def test_synthesize_empty_trigger_emits_honest_gap():
    """When no initial-access evidence exists, narrative says so."""
    findings = [
        _mk("exfil via https",
             hypotheses=["H_INSIDER_EMAIL_EXFIL"]),
    ]
    ach = [_Rank(hyp_id="H_INSIDER_EMAIL_EXFIL",
                  name="Insider", score=5)]
    nr = synthesize(case_id="t-nar", findings=findings,
                     ach_ranking=ach)
    md = nr.as_markdown()
    # The trigger beat renders even with zero findings, with an
    # explicit "not reconstructible" statement.
    assert "Initial compromise" in md
    assert "not reconstructible" in md


def test_synthesize_surfaces_unresolved_and_insufficient_counts():
    findings = [
        _mk("suspicious",
             hypotheses=["H_APT_ESPIONAGE"], red_status="unresolved"),
        _mk("partial evidence", confidence="insufficient"),
    ]
    ach = [_Rank(hyp_id="H_APT_ESPIONAGE",
                  name="APT", score=3)]
    nr = synthesize(case_id="t-nar", findings=findings,
                     ach_ranking=ach)
    assert nr.unresolved_count == 1
    assert nr.insufficient_count == 1
    md = nr.as_markdown()
    assert "Open questions" in md
    assert "unresolved" in md
    assert "insufficient" in md


def test_synthesize_no_findings_no_ranking():
    nr = synthesize(case_id="empty", findings=[], ach_ranking=[])
    assert nr.leading_hypothesis is None
    assert nr.leading_score == 0
    md = nr.as_markdown()
    assert "Executive Narrative" in md
    # Honest trigger gap still visible even with nothing to narrate
    assert "not reconstructible" in md


def test_narrative_paragraph_orders_chronologically_within_beat():
    """Within a beat, findings sort by diagnostic score then by
    evidence time — so earlier artifact times surface earlier for
    equally-diagnostic findings."""
    earlier = _mk("early compromise",
                    hypotheses=["H_INITIAL_ACCESS_WEB"],
                    evidence_time_str="2008-07-18T05:00:00Z",
                    ach_delta={"H_APT_ESPIONAGE": 3})
    later = _mk("later compromise",
                  hypotheses=["H_INITIAL_ACCESS_WEB"],
                  evidence_time_str="2008-07-19T12:00:00Z",
                  ach_delta={"H_APT_ESPIONAGE": 3})    # same spread
    nr = synthesize(case_id="t-nar",
                     findings=[later, earlier],        # reversed input
                     ach_ranking=[_Rank(
                         hyp_id="H_APT_ESPIONAGE", name="a", score=6)])
    # Trigger beat's top_findings should have `earlier` first
    trigger = next(b for b in nr.beats if b.beat == "trigger")
    assert trigger.finding_count == 2
    assert trigger.top_findings[0].finding_id == earlier.finding_id
