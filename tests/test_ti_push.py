"""TI push skill — unit tests.

Real OpenCTI / MISP integration is gated; tests cover env-var detection,
opt-out behaviour, indicator-count parsing, and dataclass shape. End-to-end
flows are exercised with mocked clients.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from el.skills import ti_push as ti


# --- configured detection -------------------------------------------

def test_opencti_configured_false_when_unset(monkeypatch):
    monkeypatch.delenv("EL_OPENCTI_URL", raising=False)
    monkeypatch.delenv("EL_OPENCTI_TOKEN", raising=False)
    assert not ti.opencti_configured()


def test_opencti_configured_true_when_both_set(monkeypatch):
    monkeypatch.setenv("EL_OPENCTI_URL", "https://opencti.example")
    monkeypatch.setenv("EL_OPENCTI_TOKEN", "tok")
    assert ti.opencti_configured()


def test_opencti_configured_false_with_only_url(monkeypatch):
    monkeypatch.setenv("EL_OPENCTI_URL", "https://opencti.example")
    monkeypatch.delenv("EL_OPENCTI_TOKEN", raising=False)
    assert not ti.opencti_configured()


def test_misp_configured_false_when_unset(monkeypatch):
    monkeypatch.delenv("EL_MISP_URL", raising=False)
    monkeypatch.delenv("EL_MISP_KEY", raising=False)
    assert not ti.misp_configured()


def test_misp_configured_true_when_both_set(monkeypatch):
    monkeypatch.setenv("EL_MISP_URL", "https://misp.example")
    monkeypatch.setenv("EL_MISP_KEY", "key")
    assert ti.misp_configured()


def test_any_configured_reflects_either(monkeypatch):
    for k in ("EL_OPENCTI_URL", "EL_OPENCTI_TOKEN",
               "EL_MISP_URL", "EL_MISP_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert not ti.any_configured()
    monkeypatch.setenv("EL_MISP_URL", "x")
    monkeypatch.setenv("EL_MISP_KEY", "y")
    assert ti.any_configured()


# --- _count_indicators ----------------------------------------------

def test_count_indicators_in_real_bundle(tmp_path):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps({
        "type": "bundle",
        "objects": [
            {"type": "identity", "id": "identity--1"},
            {"type": "indicator", "id": "indicator--a"},
            {"type": "indicator", "id": "indicator--b"},
            {"type": "indicator", "id": "indicator--c"},
            {"type": "report", "id": "report--1"},
        ]
    }))
    assert ti._count_indicators(p) == 3


def test_count_indicators_handles_malformed(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not-valid-json")
    assert ti._count_indicators(p) == 0


def test_count_indicators_handles_missing_objects_key(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"type": "bundle"}))
    assert ti._count_indicators(p) == 0


# --- push_to_opencti opt-out ----------------------------------------

def test_push_opencti_returns_unconfigured_when_no_env(tmp_path, monkeypatch):
    monkeypatch.delenv("EL_OPENCTI_URL", raising=False)
    monkeypatch.delenv("EL_OPENCTI_TOKEN", raising=False)
    bundle = tmp_path / "stix.json"
    bundle.write_text(json.dumps({"type": "bundle", "objects": []}))
    result = ti.push_to_opencti(bundle)
    assert result.target == "opencti"
    assert result.configured is False
    assert "opt-in" in result.note.lower() or "not set" in result.note


def test_push_opencti_raises_for_missing_bundle(tmp_path):
    with pytest.raises(ti.TIPushError):
        ti.push_to_opencti(tmp_path / "no-such.json")


# --- push_to_misp opt-out -------------------------------------------

def test_push_misp_returns_unconfigured_when_no_env(tmp_path, monkeypatch):
    monkeypatch.delenv("EL_MISP_URL", raising=False)
    monkeypatch.delenv("EL_MISP_KEY", raising=False)
    bundle = tmp_path / "stix.json"
    bundle.write_text(json.dumps({"type": "bundle", "objects": []}))
    result = ti.push_to_misp(bundle)
    assert result.target == "misp"
    assert result.configured is False


# --- push_to_opencti with mocked client -----------------------------

def test_push_opencti_invokes_import_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_OPENCTI_URL", "https://opencti.example")
    monkeypatch.setenv("EL_OPENCTI_TOKEN", "tok")
    bundle = tmp_path / "stix.json"
    bundle.write_text(json.dumps({
        "type": "bundle",
        "objects": [{"type": "indicator", "id": "indicator--x"}],
    }))

    fake_stix = MagicMock()
    fake_client = MagicMock()
    fake_client.stix2 = fake_stix

    fake_pycti = MagicMock()
    fake_pycti.OpenCTIApiClient = MagicMock(return_value=fake_client)

    import sys
    monkeypatch.setitem(sys.modules, "pycti", fake_pycti)

    result = ti.push_to_opencti(bundle)
    assert result.configured is True
    assert result.rc == 0
    assert result.indicator_count == 1
    # The client's import_bundle_from_json was called with our bundle text
    fake_stix.import_bundle_from_json.assert_called_once()
    args, kwargs = fake_stix.import_bundle_from_json.call_args
    assert "indicator--x" in args[0]
    assert kwargs.get("update") is True


def test_push_opencti_records_failure_in_note(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_OPENCTI_URL", "https://opencti.example")
    monkeypatch.setenv("EL_OPENCTI_TOKEN", "tok")
    bundle = tmp_path / "stix.json"
    bundle.write_text(json.dumps({"type": "bundle", "objects": []}))

    fake_stix = MagicMock()
    fake_stix.import_bundle_from_json.side_effect = RuntimeError("boom")
    fake_client = MagicMock(); fake_client.stix2 = fake_stix
    fake_pycti = MagicMock()
    fake_pycti.OpenCTIApiClient = MagicMock(return_value=fake_client)
    import sys
    monkeypatch.setitem(sys.modules, "pycti", fake_pycti)

    result = ti.push_to_opencti(bundle)
    assert result.rc == 1
    assert "boom" in result.note


# --- push_to_misp with mocked client --------------------------------

def test_push_misp_returns_event_id_on_success(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_MISP_URL", "https://misp.example")
    monkeypatch.setenv("EL_MISP_KEY", "key")
    bundle = tmp_path / "stix.json"
    bundle.write_text(json.dumps({
        "type": "bundle",
        "objects": [{"type": "indicator", "id": "i--1"}],
    }))

    fake_misp = MagicMock()
    fake_misp.upload_stix.return_value = {"Event": {"id": "1234"}}

    fake_pymisp = MagicMock()
    fake_pymisp.PyMISP = MagicMock(return_value=fake_misp)

    import sys
    monkeypatch.setitem(sys.modules, "pymisp", fake_pymisp)

    result = ti.push_to_misp(bundle, event_info="test event")
    assert result.configured is True
    assert result.rc == 0
    assert result.misp_event_id == 1234
    assert result.indicator_count == 1
    fake_misp.upload_stix.assert_called_once()


def test_push_misp_handles_no_event_id_in_response(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_MISP_URL", "https://misp.example")
    monkeypatch.setenv("EL_MISP_KEY", "key")
    bundle = tmp_path / "stix.json"
    bundle.write_text(json.dumps({"type": "bundle", "objects": []}))

    fake_misp = MagicMock()
    fake_misp.upload_stix.return_value = {"status": "ok"}
    fake_pymisp = MagicMock()
    fake_pymisp.PyMISP = MagicMock(return_value=fake_misp)
    import sys
    monkeypatch.setitem(sys.modules, "pymisp", fake_pymisp)

    result = ti.push_to_misp(bundle)
    assert result.misp_event_id is None
    assert "no event_id parsed" in result.note


# --- push_all dispatch ----------------------------------------------

def test_push_all_runs_only_configured_targets(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_OPENCTI_URL", "https://opencti.example")
    monkeypatch.setenv("EL_OPENCTI_TOKEN", "tok")
    monkeypatch.delenv("EL_MISP_URL", raising=False)
    monkeypatch.delenv("EL_MISP_KEY", raising=False)

    bundle = tmp_path / "stix.json"
    bundle.write_text(json.dumps({"type": "bundle", "objects": []}))

    fake_stix = MagicMock()
    fake_client = MagicMock(); fake_client.stix2 = fake_stix
    fake_pycti = MagicMock()
    fake_pycti.OpenCTIApiClient = MagicMock(return_value=fake_client)
    import sys
    monkeypatch.setitem(sys.modules, "pycti", fake_pycti)

    results = ti.push_all(bundle)
    assert len(results) == 1
    assert results[0].target == "opencti"


# --- as_evidence shape ----------------------------------------------

def test_result_as_evidence_shape(tmp_path):
    bundle = tmp_path / "stix.json"
    bundle.write_text("{}")
    r = ti.TIPushResult(
        target="opencti", server_url="https://opencti.example",
        bundle_path=bundle, bundle_sha256="a" * 64,
        rc=0, indicator_count=5, duration_seconds=1.5,
    )
    ev = r.as_evidence()
    assert ev.tool == "ti_push.opencti"
    assert ev.output_sha256 == "a" * 64
    assert ev.extracted_facts["indicator_count"] == 5


def test_result_zero_pads_when_no_sha(tmp_path):
    r = ti.TIPushResult(
        target="misp", server_url="x", bundle_path=tmp_path / "b.json",
        bundle_sha256="", configured=False,
    )
    ev = r.as_evidence()
    assert ev.output_sha256 == "0" * 64
