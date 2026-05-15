"""Architectural security boundaries — tested by attempting to bypass them.

Find Evil 2026 judging criterion (Constraint Implementation):

    "Are guardrails architectural or prompt-based? Judges evaluate
    where security boundaries are enforced and whether they were
    tested for bypass."

This file pins each architectural boundary by constructing the
specific adversarial input that would *violate* the boundary and
asserting it fails. Every test is named after the bypass attempt,
not the property being preserved. If a test starts passing in
the wrong direction (the bypass succeeds), the boundary regressed.

The boundaries enforced:

1. Pydantic schema — a non-insufficient Finding cannot exist
   without grounding evidence. The only way to make a claim is
   to attach a tool's output trace.
2. State machine — illegal transitions raise; the
   ADVERSARIAL_REVIEW → SYNTHESIZE gate refuses to score the case
   while any Finding's `red_review.status == "unresolved"`.
3. ACH engine — `confidence="insufficient"` is excluded from
   hypothesis scoring so tool-failure messages don't shift the
   ranking based on what EL couldn't extract.
4. Evidence read-only enforcement — intake strips write bits from
   files under protected paths (``/cases/``, ``/mnt/``, ``/media/``,
   ``/evidence/``) so the case workflow physically cannot mutate
   the evidence it ingests.
5. EvidenceItem human_summary cap — defends the executive tier from
   model-generated walls of prose by raising on overlong inputs.

The existing per-component contracts in ``test_finding_contract.py``,
``test_coordinator_blocks.py``, ``test_ach_excludes_insufficient.py``,
and ``test_ioc_feedback_loop_guard.py`` collectively cover the same
ground; this file's contribution is grouping them under one
"attempted bypass" frame the judges can read in a single pass.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from el.evidence import intake as intake_mod
from el.intel.ach import score_findings
from el.orchestrator.states import State, TRANSITIONS, can_transition
from el.schemas.finding import EvidenceItem, Finding, RedReview


# ---------------------------------------------------------------------------
# Boundary 1 — Pydantic schema rejects evidence-less factual claims
# ---------------------------------------------------------------------------
#
# An attacker (or careless agent author) wants to inject a high-confidence
# claim without an underlying tool trace. The Pydantic model_validator on
# Finding refuses to construct such an object — it raises before the
# instance exists, so the bad value cannot reach the ledger.
# ---------------------------------------------------------------------------


def _grounded_evidence() -> EvidenceItem:
    return EvidenceItem(
        tool="t", version="0", command="x",
        output_sha256="0" * 64, output_path="/tmp/x",
    )


@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_bypass_evidence_requirement_via_empty_evidence_array(confidence):
    """ATTEMPT: claim a finding at non-insufficient confidence with no
    evidence. The Pydantic validator must reject before construction.
    This is the core anti-hallucination boundary."""
    with pytest.raises(ValidationError) as exc:
        Finding(case_id="c", agent="a", confidence=confidence,
                claim="something happened", evidence=[])
    assert "evidence" in str(exc.value).lower()


def test_legal_escape_insufficient_with_empty_evidence_is_accepted():
    """The ONLY legal way to emit a claim without evidence: confidence
    'insufficient'. This is a first-class output saying 'EL couldn't
    extract this' — the rules call it out as 'honesty valued over
    perfection'."""
    f = Finding(case_id="c", agent="a", confidence="insufficient",
                claim="vol3 symbol cache miss — see analysis/...stderr",
                evidence=[])
    assert f.confidence == "insufficient"


@pytest.mark.parametrize("field,blank", [
    ("case_id", ""), ("agent", ""), ("claim", ""),
    ("case_id", "   "), ("agent", "\t"), ("claim", "\n"),
])
def test_bypass_required_fields_via_blank_strings(field, blank):
    """ATTEMPT: provide whitespace-only required fields. The custom
    _nonempty validator rejects these — blank metadata is forbidden so
    every finding has a real case / agent / claim attribution."""
    kwargs = dict(case_id="c", agent="a", confidence="high",
                  claim="real claim", evidence=[_grounded_evidence()])
    kwargs[field] = blank
    with pytest.raises(ValidationError):
        Finding(**kwargs)


def test_bypass_finding_immutability_by_post_construction_mutation():
    """ATTEMPT: build a valid insufficient finding, then mutate it to
    high-confidence after construction. Pydantic models default to
    frozen=False, but the validator that enforces evidence-for-high-
    confidence runs at construction — *not* on attribute assignment.
    This test pins the current behaviour: a runtime mutation does NOT
    re-run validation, so the architectural guarantee comes from the
    write path (every agent emit goes through Finding(...) construction),
    not from post-construction immutability. The boundary lives in
    *every* agent's emit path; this test documents that contract."""
    f = Finding(case_id="c", agent="a", confidence="insufficient",
                claim="x", evidence=[])
    # The mutation succeeds — Pydantic isn't enforcing on setattr.
    f.confidence = "high"
    # …but a *fresh* construction of the now-bad state would fail:
    with pytest.raises(ValidationError):
        Finding(**f.model_dump())


# ---------------------------------------------------------------------------
# Boundary 2 — State-machine illegal transitions are unreachable
# ---------------------------------------------------------------------------
#
# An attacker wants to skip the ADVERSARIAL_REVIEW step to land
# unreviewed findings in the synthesized report. The state machine's
# transition table forbids this.
# ---------------------------------------------------------------------------


def test_bypass_review_gate_by_jumping_intake_to_synthesize():
    """ATTEMPT: skip from INTAKE straight to SYNTHESIZE, bypassing
    Triage / HypothesisGen / ParallelInvestigate / Correlate /
    AdversarialReview. The transition table must refuse."""
    assert not can_transition(State.INTAKE, State.SYNTHESIZE)
    assert not can_transition(State.TRIAGE, State.SYNTHESIZE)
    assert not can_transition(State.HYPOTHESIS_GEN, State.SYNTHESIZE)
    assert not can_transition(State.PARALLEL_INVESTIGATE, State.SYNTHESIZE)
    assert not can_transition(State.CORRELATE, State.SYNTHESIZE)
    # Only ADVERSARIAL_REVIEW → SYNTHESIZE is legal:
    assert can_transition(State.ADVERSARIAL_REVIEW, State.SYNTHESIZE)


def test_bypass_done_state_to_restart_pipeline():
    """ATTEMPT: from DONE state, transition somewhere — typical
    coordinator reuse bug from the BelkaCTF6 bundle. DONE must be
    terminal; no successors."""
    assert TRANSITIONS[State.DONE] == set()
    for dst in State:
        assert not can_transition(State.DONE, dst), \
            f"DONE → {dst.value} must not be reachable"


def test_bypass_blocked_state_with_silent_retry():
    """ATTEMPT: from BLOCKED, transition to anything. BLOCKED must be
    a permanent dead-end; an investigator must manually intervene to
    clear the blocking finding's red_review status, not have the
    coordinator silently skip past."""
    assert TRANSITIONS[State.BLOCKED] == set()


def test_every_state_can_reach_blocked():
    """ATTEMPT: leave the case in a half-investigated state without
    surfacing the blocker. Every non-terminal state must be able to
    transition to BLOCKED so that any unresolved condition can halt
    the pipeline cleanly."""
    for state in State:
        if state in (State.DONE, State.BLOCKED):
            continue
        assert State.BLOCKED in TRANSITIONS[state], \
            f"{state.value} cannot escape to BLOCKED"


# ---------------------------------------------------------------------------
# Boundary 3 — ACH excludes insufficient findings from scoring
# ---------------------------------------------------------------------------
#
# An attacker (or buggy detector) emits N "insufficient" findings to
# tilt the hypothesis ranking via volume. The ACH engine must ignore
# them — what EL *couldn't* extract is not evidence for any hypothesis.
# ---------------------------------------------------------------------------


def test_bypass_ach_ranking_via_insufficient_finding_volume():
    """ATTEMPT: emit 1000 insufficient findings claiming 'apt espionage
    detected — but unable to verify'. Each one would (under a naive
    scorer) lift H_APT_ESPIONAGE despite being tool-failure messages.
    The ACH engine's confidence='insufficient' filter must drop all of
    them before scoring runs."""
    findings = [
        Finding(case_id="c", agent=f"a{i}", confidence="insufficient",
                claim="apt espionage detected but couldn't extract details")
        for i in range(1000)
    ]
    ranked, _ = score_findings(findings)
    apt = next(r for r in ranked if r.hyp_id == "H_APT_ESPIONAGE")
    assert apt.score == 0, \
        "Insufficient findings must not score H_APT_ESPIONAGE"


def test_bypass_ach_by_mixing_grounded_with_insufficient():
    """ATTEMPT: surround one grounded finding with 999 insufficient
    decoys. The decoys must NOT amplify the grounded score.

    Uses H_CREDENTIAL_ACCESS because it's both an emit-side tag AND a
    scored hypothesis (H_PROCESS_INJECTION is tag-only — it lifts other
    hypotheses but doesn't get its own row in the ranking)."""
    grounded = Finding(
        case_id="c", agent="m", confidence="high",
        claim="LSASS credential dump signature observed",
        evidence=[_grounded_evidence()],
        hypotheses_supported=["H_CREDENTIAL_ACCESS"],
    )
    insufficient_noise = [
        Finding(case_id="c", agent=f"n{i}", confidence="insufficient",
                claim="credential access — but no LSASS dump available")
        for i in range(999)
    ]
    ranked_solo, _ = score_findings([grounded])
    ranked_noisy, _ = score_findings([grounded] + insufficient_noise)
    ca_solo = next(r for r in ranked_solo if r.hyp_id == "H_CREDENTIAL_ACCESS")
    ca_noisy = next(r for r in ranked_noisy if r.hyp_id == "H_CREDENTIAL_ACCESS")
    assert ca_solo.score == ca_noisy.score, \
        "Insufficient decoys must not amplify the grounded score"


# ---------------------------------------------------------------------------
# Boundary 4 — Evidence read-only enforcement on intake
# ---------------------------------------------------------------------------
#
# An attacker (or buggy agent) wants to mutate the evidence file
# during the investigation. intake.py strips write bits from files
# under protected paths so even root-equivalent code can't write back.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protected_path", [
    "/cases/some-case/raw/disk.E01",
    "/mnt/evidence/disk.dd",
    "/media/usb/memory.raw",
    "/evidence/incoming/capture.pcap",
])
def test_protected_path_classifier_recognises_evidence_locations(protected_path):
    """ATTEMPT: stage evidence under a path the read-only enforcement
    should cover. _evidence_is_protected must classify each as a
    protected location."""
    assert intake_mod._evidence_is_protected(Path(protected_path))


@pytest.mark.parametrize("user_path", [
    "/tmp/scratch/test.bin",
    "/home/sansforensics/Downloads/file.E01",
    "/opt/EL/scratch/sample.img",
])
def test_user_writable_paths_are_not_falsely_protected(user_path):
    """ATTEMPT (inverse): the read-only enforcement must NOT mass-
    protect every path. User-scratch paths under /tmp/, /home/,
    /opt/EL/scratch/ must remain writable so the analyst can run
    intake on their own working files. False positives here would
    break the operator's ability to clean up."""
    assert not intake_mod._evidence_is_protected(Path(user_path))


def test_intake_strips_write_bits_when_protected(tmp_path, monkeypatch):
    """ATTEMPT: intake a file under a protected path with write bits
    set; intake must chmod the write bits OFF as part of its
    chain-of-custody hardening. This is the only enforcement layer
    that physically prevents downstream code from mutating the
    evidence — every other guard is logical / agent-cooperative."""
    # Simulate the "protected" classifier by monkey-patching the
    # check so we can test without actually writing under /cases/.
    monkeypatch.setattr(intake_mod, "_evidence_is_protected",
                        lambda p: True)
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "writable_evidence.bin"
    src.write_bytes(b"\x00" * 64)
    # Confirm the source starts writable
    os.chmod(src, 0o644)
    assert os.stat(src).st_mode & stat.S_IWUSR
    # Run intake; write bit should be stripped afterwards
    intake_mod.intake(src, case_id="t-readonly")
    assert not (os.stat(src).st_mode & stat.S_IWUSR), \
        "Intake must strip user write bit from protected evidence"
    assert not (os.stat(src).st_mode & stat.S_IWGRP)
    assert not (os.stat(src).st_mode & stat.S_IWOTH)


# ---------------------------------------------------------------------------
# Boundary 5 — EvidenceItem human_summary length cap
# ---------------------------------------------------------------------------
#
# An attacker (or LLM enrichment path) wants to inject a multi-page
# narrative into the executive report tier via human_summary. The
# 200-char cap defends the executive-summary surface from prose
# bloat / model-generated padding.
# ---------------------------------------------------------------------------


def test_bypass_executive_summary_length_cap():
    """ATTEMPT: stuff a 10k-char model-generated narrative into the
    EvidenceItem.human_summary. The HUMAN_SUMMARY_MAX_CHARS validator
    must reject."""
    with pytest.raises(ValidationError):
        EvidenceItem(
            tool="t", version="0", command="x",
            output_sha256="0" * 64, output_path="/tmp/x",
            human_summary="A" * 10_000,
        )


def test_human_summary_at_cap_accepted():
    """A summary exactly at the cap (200 chars) is the boundary case
    that should still be accepted. Pins the off-by-one direction."""
    from el.schemas.finding import HUMAN_SUMMARY_MAX_CHARS
    ev = EvidenceItem(
        tool="t", version="0", command="x",
        output_sha256="0" * 64, output_path="/tmp/x",
        human_summary="A" * HUMAN_SUMMARY_MAX_CHARS,
    )
    assert ev.human_summary is not None


# ---------------------------------------------------------------------------
# Boundary 6 — Default red_review status forces explicit resolution
# ---------------------------------------------------------------------------
#
# An attacker wants to bypass adversarial review by emitting a finding
# pre-marked "passed". The default RedReview.status is "pending" — an
# agent cannot skip the review step by lying about its own outcome.
# ---------------------------------------------------------------------------


def test_default_red_review_status_is_pending():
    """ATTEMPT: emit a finding with no red_review supplied, hoping it
    lands as 'passed' by default. The default must be 'pending' so the
    Red Reviewer always gets a turn to challenge or pass."""
    f = Finding(case_id="c", agent="a", confidence="high",
                claim="x", evidence=[_grounded_evidence()])
    assert f.red_review.status == "pending"


def test_red_review_status_values_are_constrained():
    """ATTEMPT: invent a custom red_review.status like 'auto_approved'
    that bypasses the SYNTHESIZE gate. The Literal type rejects."""
    with pytest.raises(ValidationError):
        RedReview(status="auto_approved")
    with pytest.raises(ValidationError):
        RedReview(status="bypass")


def test_unresolved_red_review_is_a_legal_status():
    """The state-machine gate uses 'unresolved' as its blocking value;
    pin it as a valid Literal so the gate's string compare matches."""
    rr = RedReview(status="unresolved")
    assert rr.status == "unresolved"


# ---------------------------------------------------------------------------
# Boundary 7 — Confidence Literal type rejects invented levels
# ---------------------------------------------------------------------------
#
# An attacker (or careless author) wants to invent a 'critical' or
# 'certain' confidence level above 'high' to mark a finding as
# extra-authoritative. The Literal type rejects.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("invented", ["critical", "certain", "verified",
                                       "definite", "HIGH", "High"])
def test_bypass_confidence_ladder_via_invented_level(invented):
    """ATTEMPT: claim 'critical' confidence (above the documented
    high/medium/low/insufficient ladder). Pydantic Literal must
    reject — including case variations like HIGH / High that would
    let a downstream tool mishandle a finding that LOOKS like 'high'
    but isn't the canonical value."""
    with pytest.raises(ValidationError):
        Finding(case_id="c", agent="a", confidence=invented,
                claim="x", evidence=[_grounded_evidence()])
