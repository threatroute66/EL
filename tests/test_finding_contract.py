import pytest
from pydantic import ValidationError

from el.schemas.finding import Finding, EvidenceItem


def _evidence(**overrides):
    base = dict(
        tool="vol.py", version="2.20.0",
        command="windows.pstree", output_sha256="0" * 64,
        output_path="/tmp/x",
    )
    base.update(overrides)
    return EvidenceItem(**base)


def test_grounded_finding_accepts():
    f = Finding(
        case_id="c1", agent="memory", claim="explorer.exe spawned cmd.exe",
        confidence="high", evidence=[_evidence()],
    )
    assert f.evidence and f.confidence == "high"


def test_high_confidence_without_evidence_rejected():
    with pytest.raises(ValidationError):
        Finding(case_id="c1", agent="memory", claim="x", confidence="high")


def test_low_confidence_without_evidence_rejected():
    with pytest.raises(ValidationError):
        Finding(case_id="c1", agent="memory", claim="x", confidence="low")


def test_insufficient_without_evidence_accepted():
    f = Finding(case_id="c1", agent="memory",
                claim="vol3 unavailable; cannot evaluate", confidence="insufficient")
    assert f.confidence == "insufficient" and not f.evidence


def test_blank_fields_rejected():
    with pytest.raises(ValidationError):
        Finding(case_id="", agent="memory", claim="x", confidence="insufficient")
    with pytest.raises(ValidationError):
        Finding(case_id="c1", agent=" ", claim="x", confidence="insufficient")


# --- Phase 0.3: human_summary on EvidenceItem -------------------------------
# human_summary is the optional plain-English restatement used by the
# executive (non-expert) report tier. Optional + length-capped so prose
# stays scannable; long technical detail belongs in claim/extracted_facts.

def test_evidence_human_summary_defaults_none():
    e = _evidence()
    assert e.human_summary is None


def test_evidence_human_summary_accepts_short_prose():
    e = _evidence(human_summary="Login secrets were extracted from memory.")
    assert e.human_summary.startswith("Login")


def test_evidence_human_summary_rejects_overlong():
    from el.schemas.finding import HUMAN_SUMMARY_MAX_CHARS
    too_long = "x" * (HUMAN_SUMMARY_MAX_CHARS + 1)
    with pytest.raises(ValidationError):
        _evidence(human_summary=too_long)
