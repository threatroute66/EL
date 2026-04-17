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
