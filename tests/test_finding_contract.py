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


# --- Phase 3.1: device tag on Finding --------------------------------------
# The device field is the bundle-case multi-host marker. None for single-host
# cases (existing behaviour); set to the device label when a bundle's
# synthesis pass copies findings into the bundle ledger.

def test_finding_device_defaults_none():
    f = Finding(case_id="c1", agent="a", claim="x",
                confidence="insufficient")
    assert f.device is None


def test_finding_device_accepts_string():
    f = Finding(case_id="c1", agent="a", claim="x",
                confidence="insufficient", device="laptop")
    assert f.device == "laptop"


def test_finding_device_round_trips_through_json():
    """Bundles persist findings via Pydantic JSON; the device tag
    must round-trip cleanly so the synthesis pass + executive
    renderer see the same value."""
    f = Finding(case_id="c1", agent="a", claim="x",
                confidence="insufficient", device="phone")
    blob = f.model_dump_json()
    restored = Finding.model_validate_json(blob)
    assert restored.device == "phone"


def test_finding_old_json_without_device_still_loads():
    """Backwards-compat: a payload from before the device field
    existed must still validate (defaults to None)."""
    legacy = (
        '{"finding_id":"01TEST","case_id":"c1","agent":"a",'
        '"claim":"x","confidence":"insufficient",'
        '"created_utc":"2024-01-01T00:00:00+00:00"}'
    )
    f = Finding.model_validate_json(legacy)
    assert f.device is None
