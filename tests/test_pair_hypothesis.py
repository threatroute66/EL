"""Tests for the two pair-detection-aware hypotheses.

H_PAIRED_CAPTURE_CANDIDATE — advisory; lifts on the tag triage emits
when ctx.shared['paired_with'] is set. Scoring is intentionally low
(+1) so it never beats a real threat hypothesis.

H_NOT_CLEAN_BASELINE — load-bearing; lifts (+3) on a memory_forensicator
"no non-baseline items observed" finding that ALSO carries the
H_NOT_CLEAN_BASELINE tag (emitted by memory_forensicator when paired).
The same finding must NOT lift H_BENIGN_NO_INCIDENT (which would
otherwise +2 on the "no non-baseline" claim) — that's the false-positive
this whole feature exists to fix.
"""
from __future__ import annotations

from el.intel.ach import score_findings
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def test_paired_capture_marker_lifts_paired_hypothesis():
    """Triage emits a finding with H_PAIRED_CAPTURE_CANDIDATE when
    the bundle's pair detector flagged this device. The advisory
    hypothesis should appear in the ranking with a positive score
    (just enough to surface; not enough to compete with real threats)."""
    f = Finding(case_id="c", agent="triage", confidence="high",
                claim="Paired capture detected: wkstn-01-memory ↔ wkstn-01-mem",
                evidence=[_ev()],
                hypotheses_supported=["H_PAIRED_CAPTURE_CANDIDATE"])
    ranked, _ = score_findings([f])
    paired = next(r for r in ranked if r.hyp_id == "H_PAIRED_CAPTURE_CANDIDATE")
    assert paired.score == 1


def test_paired_zero_diff_does_not_lift_benign():
    """The load-bearing case: when the bundle is paired AND the
    baseliner zero-diff fires, H_BENIGN_NO_INCIDENT must stay at 0.
    Before this guard the same finding lifted benign by +2 — and a
    pair where the host was never cleaned would falsely look like
    a clean host in ACH."""
    f = Finding(
        case_id="c", agent="memory_forensicator", confidence="high",
        claim="Baseline comparison (proc): no non-baseline items observed",
        evidence=[_ev()],
        hypotheses_supported=["H_NOT_CLEAN_BASELINE"])
    ranked, _ = score_findings([f])
    benign = next(r for r in ranked if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    assert benign.score == 0


def test_paired_zero_diff_lifts_not_clean_baseline():
    """Same finding that suppresses the null must positively lift
    H_NOT_CLEAN_BASELINE — that's the conclusion the analyst should
    actually read in the report."""
    f = Finding(
        case_id="c", agent="memory_forensicator", confidence="high",
        claim="Baseline comparison (drv): no non-baseline items observed",
        evidence=[_ev()],
        hypotheses_supported=["H_NOT_CLEAN_BASELINE"])
    ranked, _ = score_findings([f])
    not_clean = next(r for r in ranked
                     if r.hyp_id == "H_NOT_CLEAN_BASELINE")
    assert not_clean.score == 3


def test_unpaired_zero_diff_still_lifts_benign():
    """The pre-existing behaviour must NOT regress: on a single-host
    (non-paired) case, a baseliner zero-diff is still positive
    evidence the host is clean and should still lift the null.
    Without this regression-guard test, anyone tightening _h_benign
    later could break the clean-host path silently."""
    f = Finding(
        case_id="c", agent="memory_forensicator", confidence="high",
        claim="Baseline comparison (proc): no non-baseline items observed",
        evidence=[_ev()],
        hypotheses_supported=[])  # NO paired marker
    ranked, _ = score_findings([f])
    benign = next(r for r in ranked if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    assert benign.score == 2


def test_paired_capture_marker_alone_does_not_dominate():
    """Even with the pair marker present, an active threat finding
    must outrank the advisory paired-capture hypothesis. Anything
    else and the paired hypothesis becomes noise that buries real
    detections."""
    advisory = Finding(case_id="c", agent="triage", confidence="high",
                       claim="Paired capture detected",
                       evidence=[_ev()],
                       hypotheses_supported=["H_PAIRED_CAPTURE_CANDIDATE"])
    threat = Finding(case_id="c", agent="mem", confidence="high",
                     claim="Process-injection signature in suspect PID",
                     evidence=[_ev()],
                     hypotheses_supported=["H_PROCESS_INJECTION"])
    ranked, _ = score_findings([advisory, threat])
    leader = ranked[0]
    paired = next(r for r in ranked if r.hyp_id == "H_PAIRED_CAPTURE_CANDIDATE")
    assert leader.score > paired.score
    assert leader.hyp_id != "H_PAIRED_CAPTURE_CANDIDATE"
