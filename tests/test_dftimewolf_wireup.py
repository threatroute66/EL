"""End-to-end wireup: triage detects a dfTimewolf bundle and the dispatcher
agent emits provenance + sub-artifact findings."""
import json
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.triage import TriageAgent
from el.agents.dftimewolf_dispatcher import DFTimewolfDispatcherAgent
from el.evidence import intake as intake_mod


def _make_case(tmp_path, monkeypatch, name):
    """Bind intake CASE_ROOT to a per-test dir so we don't pollute /opt/EL/cases."""
    cases = tmp_path / "cases"
    monkeypatch.setattr(intake_mod, "CASE_ROOT", cases)
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "knowledge.sqlite"))
    src = tmp_path / "src"
    src.mkdir()
    return src


def test_triage_routes_dftimewolf_bundle(tmp_path, monkeypatch):
    src = _make_case(tmp_path, monkeypatch, "t-dftw")
    # Build a minimal dfTimewolf bundle.
    (src / "recipe.json").write_text(json.dumps({
        "name": "aws_forensics",
        "modules": [
            {"name": "AWSCollector", "args": {}, "wants": []},
            {"name": "PlasoProcessor", "args": {}, "wants": ["AWSCollector"]},
        ],
    }))
    (src / "dftimewolf.log").write_text("INFO recipe started\n")
    (src / "supertimeline.plaso").write_bytes(b"\x00" * 100)
    (src / "cloudtrail.json").write_text(json.dumps([{
        "eventName": "GetObject", "eventSource": "s3.amazonaws.com",
    }]))

    case_dir = tmp_path / "cases" / "t-dftw"
    case_dir.mkdir(parents=True)
    (case_dir / "analysis").mkdir()

    ctx = AgentContext(
        case_id="t-dftw", case_dir=case_dir, input_path=src,
        manifest={}, shared={},
    )
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "dftimewolf-bundle"
    msgs = [f for f in findings if "dfTimewolf" in f.claim]
    assert msgs, "triage should emit a dfTimewolf detection finding"
    # And the bundle object is stashed for the dispatcher.
    assert ctx.shared.get("dftimewolf_bundle") is not None


def test_dispatcher_emits_provenance_and_routing_hints(tmp_path, monkeypatch):
    src = _make_case(tmp_path, monkeypatch, "t-dftw-dispatch")
    (src / "recipe.json").write_text(json.dumps({
        "name": "gce_forensics",
        "modules": [
            {"name": "GoogleCloudCollector", "args": {}, "wants": []},
        ],
    }))
    (src / "evidence.plaso").write_bytes(b"\x00" * 64)
    (src / "k8s.json").write_text(
        '{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"abc"}'
    )

    case_dir = tmp_path / "cases" / "t-dftw-dispatch"
    case_dir.mkdir(parents=True)

    ctx = AgentContext(
        case_id="t-dftw-dispatch", case_dir=case_dir, input_path=src,
        manifest={}, shared={"evidence_kind": "dftimewolf-bundle"},
    )
    findings = DFTimewolfDispatcherAgent().run(ctx)
    # Headline + per-kind hints.
    headlines = [f for f in findings if "bundle parsed" in f.claim]
    assert len(headlines) == 1
    assert "gce_forensics" in headlines[0].claim
    plaso_hints = [f for f in findings if "kind 'plaso'" in f.claim]
    assert plaso_hints, "expected at least one Plaso routing-hint finding"
    k8s_hints = [f for f in findings if "kind 'k8s_audit'" in f.claim]
    assert k8s_hints, "expected at least one K8s-audit routing-hint finding"


def test_dispatcher_handles_recipe_only_bundle(tmp_path, monkeypatch):
    src = _make_case(tmp_path, monkeypatch, "t-dftw-empty")
    (src / "recipe.json").write_text(json.dumps({
        "name": "empty_recipe",
        "modules": [{"name": "Noop", "args": {}, "wants": []}],
    }))
    case_dir = tmp_path / "cases" / "t-dftw-empty"
    case_dir.mkdir(parents=True)
    ctx = AgentContext(
        case_id="t-dftw-empty", case_dir=case_dir, input_path=src,
        manifest={}, shared={},
    )
    findings = DFTimewolfDispatcherAgent().run(ctx)
    # Provenance finding should still fire even with zero artifacts.
    headlines = [f for f in findings if "bundle parsed" in f.claim]
    assert headlines
    no_artifact_msgs = [f for f in findings if "no recognised sub-artifact" in f.claim]
    assert no_artifact_msgs


def test_dispatcher_handles_missing_dir(tmp_path, monkeypatch):
    """Cold-route via input_path that isn't a real dftimewolf dir:
    dispatcher should emit insufficient rather than raise."""
    case_dir = tmp_path / "cases" / "t-dftw-missing"
    case_dir.mkdir(parents=True)
    ctx = AgentContext(
        case_id="t-dftw-missing", case_dir=case_dir,
        input_path=tmp_path / "nope",
        manifest={}, shared={},
    )
    findings = DFTimewolfDispatcherAgent().run(ctx)
    insufficients = [f for f in findings if f.confidence == "insufficient"]
    assert insufficients
