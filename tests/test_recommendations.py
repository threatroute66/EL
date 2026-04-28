"""Phase 1.2 contract tests for el.reporting.recommendations.

Recommendations are the executive report's "next steps" section. The
contract:

  * Each recommendation cites the finding_ids that triggered it.
  * Rules only fire when their pattern is genuinely present.
  * Order is deterministic across renders (pinned in _RULES tuple).
  * No recommendation is invented from thin air — passing an empty
    findings list yields zero or only the universal-default rules.
"""
from __future__ import annotations

import pytest

from el.schemas.finding import EvidenceItem, Finding
from el.reporting.recommendations import (
    ADVISORY_DISCLAIMER,
    Recommendation,
    build_recommendations,
)
from el.reporting.narrative import BeatBlock, BEATS, NarrativeReport


def _ev() -> EvidenceItem:
    return EvidenceItem(
        tool="x", version="1", command="y", output_sha256="0" * 64,
        output_path="/tmp/z",
    )


def _f(**kw) -> Finding:
    base = dict(case_id="c", agent="a", claim="x", confidence="high",
                evidence=[_ev()], hypotheses_supported=[])
    base.update(kw)
    return Finding(**base)


def _empty_beats() -> list[BeatBlock]:
    return [BeatBlock(beat=b, heading=b, earliest=None, latest=None,
                      finding_count=0) for b in BEATS]


def _nr(**kw) -> NarrativeReport:
    base = dict(
        case_id="c", leading_hypothesis="H_APT_ESPIONAGE", leading_score=25,
        leading_gap=8, runner_up_hypothesis="H_ANTI_FORENSICS",
        runner_up_score=17, beats=_empty_beats(), alt_beats=[],
        unresolved_count=0, insufficient_count=0,
        insufficient_findings=[],
    )
    base.update(kw)
    return NarrativeReport(**base)


# --- empty case yields no recommendations ----------------------------------

def test_empty_findings_yields_empty_recommendations():
    """Defensive: no findings → no recommendations. The engine must not
    invent advice."""
    recs = build_recommendations(
        _nr(leading_hypothesis=None, leading_score=0, leading_gap=99,
            runner_up_hypothesis=None, runner_up_score=0),
        findings=[],
    )
    assert recs == []


# --- per-rule coverage ------------------------------------------------------

def test_lateral_movement_triggers_isolation():
    f = _f(hypotheses_supported=["H_LATERAL_MOVEMENT"])
    recs = build_recommendations(_nr(), [f])
    assert any(r.category == "containment" and "isolat" in r.action
               for r in recs)
    matched = next(r for r in recs if "isolat" in r.action)
    assert f.finding_id in matched.triggered_by


def test_apt_alone_also_triggers_isolation():
    """The lateral-or-apt rule fires on either hypothesis."""
    f = _f(hypotheses_supported=["H_APT_ESPIONAGE"])
    recs = build_recommendations(_nr(), [f])
    assert any(r.category == "containment" for r in recs)


def test_credential_access_triggers_rotate():
    f = _f(hypotheses_supported=["H_CREDENTIAL_ACCESS"])
    recs = build_recommendations(_nr(), [f])
    assert any("rotate credentials" in r.action.lower() for r in recs)


def test_ransomware_triggers_disconnect():
    f = _f(hypotheses_supported=["H_RANSOMWARE"])
    recs = build_recommendations(
        _nr(leading_hypothesis="H_RANSOMWARE", leading_score=20),
        [f],
    )
    rec = next((r for r in recs if "disconnect" in r.action.lower()), None)
    assert rec is not None
    assert rec.category == "containment"
    assert f.finding_id in rec.triggered_by


def test_ransomware_only_fires_when_leading():
    """If H_RANSOMWARE is supported but isn't the leading theory, the
    disconnect recommendation should NOT fire — we don't shut down the
    network on a runner-up hypothesis."""
    f = _f(hypotheses_supported=["H_RANSOMWARE"])
    recs = build_recommendations(
        _nr(leading_hypothesis="H_APT_ESPIONAGE", leading_score=25), [f],
    )
    assert not any("disconnect" in r.action.lower() for r in recs)


def test_insider_exfil_triggers_legal_hold():
    f = _f(hypotheses_supported=["H_INSIDER_EMAIL_EXFIL"])
    recs = build_recommendations(_nr(), [f])
    assert any(r.category == "reporting"
               and "preservation hold" in r.action.lower()
               for r in recs)


def test_anti_forensics_triggers_recovery():
    f = _f(claim="Disk anomaly [MACB_TIMESTOMP_SKEW] in slot002")
    recs = build_recommendations(_nr(), [f])
    assert any("recover" in r.action.lower() for r in recs)


def test_persistence_triggers_remove():
    f = _f(hypotheses_supported=["H_PERSISTENCE_SERVICE"])
    recs = build_recommendations(_nr(), [f])
    rec = next((r for r in recs if "remove" in r.action.lower()), None)
    assert rec is not None
    assert rec.category == "remediation"


def test_benign_no_incident_triggers_archive():
    recs = build_recommendations(
        _nr(leading_hypothesis="H_BENIGN_NO_INCIDENT", leading_score=5),
        findings=[],
    )
    assert any("inconclusive" in r.action.lower()
               or "no evidence of compromise" in r.action.lower()
               for r in recs)


def test_insufficient_dominant_triggers_collect_more():
    """When the case is mostly insufficient findings (and leading
    score is weak), recommend collecting more."""
    insufficient = [
        Finding(case_id="c", agent="x", claim=f"missing {i}",
                confidence="insufficient")
        for i in range(3)
    ]
    recs = build_recommendations(
        _nr(insufficient_findings=insufficient, leading_score=2,
            insufficient_count=3),
        insufficient,
    )
    rec = next((r for r in recs if "collect" in r.action.lower()), None)
    assert rec is not None
    # Trigger trace-back includes the insufficient finding IDs.
    assert insufficient[0].finding_id in rec.triggered_by


def test_insufficient_with_strong_leader_skips_collect_more():
    """If the leading hypothesis has solid score, insufficient
    findings are gaps not the dominant signal — don't call for more
    collection."""
    insufficient = [
        Finding(case_id="c", agent="x", claim=f"missing {i}",
                confidence="insufficient")
        for i in range(3)
    ]
    recs = build_recommendations(
        _nr(leading_score=20, insufficient_findings=insufficient,
            insufficient_count=3),
        insufficient,
    )
    assert not any("collect" in r.action.lower() for r in recs)


# --- determinism ------------------------------------------------------------

def test_recommendation_order_is_deterministic():
    """Two runs over the same input must produce the same order so
    the executive report doesn't churn between renders."""
    f1 = _f(hypotheses_supported=["H_LATERAL_MOVEMENT"])
    f2 = _f(hypotheses_supported=["H_CREDENTIAL_ACCESS"])
    f3 = _f(claim="Disk anomaly [SYSTEM_BINARY_ZERO_TIMESTAMPS] something")
    recs_a = [(r.category, r.action) for r in
              build_recommendations(_nr(), [f1, f2, f3])]
    recs_b = [(r.category, r.action) for r in
              build_recommendations(_nr(), [f1, f2, f3])]
    assert recs_a == recs_b


# --- structural -------------------------------------------------------------

def test_advisory_disclaimer_present():
    """The renderer needs the disclaimer; tests pin its presence."""
    assert ADVISORY_DISCLAIMER
    assert "advisory" in ADVISORY_DISCLAIMER.lower()


def test_recommendation_dataclass_fields():
    """Sanity: every rule's output conforms to the Recommendation
    dataclass and has non-empty action/rationale."""
    f = _f(hypotheses_supported=["H_LATERAL_MOVEMENT"])
    recs = build_recommendations(_nr(), [f])
    for r in recs:
        assert isinstance(r, Recommendation)
        assert r.action.strip()
        assert r.rationale.strip()
        assert r.category in {"containment", "investigation",
                               "remediation", "reporting", "hardening"}
