"""End-to-end wireup: a Falco event JSONL routes to ContainerForensicator
and the agent emits the expected container-escape / K8s privesc findings.
"""
import json
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.container_forensicator import ContainerForensicatorAgent
from el.evidence import intake as intake_mod


def _make_case(tmp_path, monkeypatch, name):
    cases = tmp_path / "cases"
    monkeypatch.setattr(intake_mod, "CASE_ROOT", cases)
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "knowledge.sqlite"))
    return cases / name


def _write_falco_jsonl(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")


def test_container_forensicator_emits_escape_finding(tmp_path, monkeypatch):
    case_dir = _make_case(tmp_path, monkeypatch, "t-container")
    case_dir.mkdir(parents=True)
    log = tmp_path / "falco.jsonl"
    _write_falco_jsonl(log, [
        {"rule": "Container Drift detected", "priority": "CRITICAL",
         "output": "drifted",
         "output_fields": {"container.id": "abc",
                            "container.name": "evil-pod"}},
    ])
    ctx = AgentContext(
        case_id="t-container", case_dir=case_dir, input_path=log,
        manifest={}, shared={"evidence_kind": "falco-events"},
    )
    findings = ContainerForensicatorAgent().run(ctx)

    headlines = [f for f in findings
                  if "Falco events parsed" in f.claim]
    assert headlines

    escape_findings = [
        f for f in findings
        if "H_CONTAINER_ESCAPE" in (f.hypotheses_supported or [])
    ]
    assert escape_findings
    assert escape_findings[0].confidence == "high"


def test_container_forensicator_emits_k8s_privesc(tmp_path, monkeypatch):
    case_dir = _make_case(tmp_path, monkeypatch, "t-k8s")
    case_dir.mkdir(parents=True)
    log = tmp_path / "falco.jsonl"
    _write_falco_jsonl(log, [
        {"rule": "Create Privileged Pod", "priority": "ERROR",
         "output": "privileged pod admitted",
         "output_fields": {"k8s.ns.name": "kube-system",
                            "k8s.pod.name": "evil"}},
        {"rule": "Attach to cluster-admin", "priority": "ERROR",
         "output": "rolebinding tampered",
         "output_fields": {"k8s.ns.name": "default",
                            "k8s.pod.name": "x"}},
    ])
    ctx = AgentContext(
        case_id="t-k8s", case_dir=case_dir, input_path=log,
        manifest={}, shared={"evidence_kind": "falco-events"},
    )
    findings = ContainerForensicatorAgent().run(ctx)

    privesc = [
        f for f in findings
        if "H_K8S_PRIVILEGE_ESCALATION" in (f.hypotheses_supported or [])
    ]
    assert privesc, "expected at least one K8s privesc finding"


def test_container_forensicator_handles_empty_log(tmp_path, monkeypatch):
    case_dir = _make_case(tmp_path, monkeypatch, "t-empty")
    case_dir.mkdir(parents=True)
    log = tmp_path / "falco.jsonl"
    log.write_text("")
    ctx = AgentContext(
        case_id="t-empty", case_dir=case_dir, input_path=log,
        manifest={}, shared={},
    )
    findings = ContainerForensicatorAgent().run(ctx)
    assert any("0 events" in f.claim for f in findings)


def test_container_forensicator_handles_missing_input(tmp_path, monkeypatch):
    case_dir = _make_case(tmp_path, monkeypatch, "t-missing")
    case_dir.mkdir(parents=True)
    ctx = AgentContext(
        case_id="t-missing", case_dir=case_dir,
        input_path=tmp_path / "nope.jsonl",
        manifest={}, shared={},
    )
    findings = ContainerForensicatorAgent().run(ctx)
    assert any(f.confidence == "insufficient" for f in findings)


def test_coordinator_routes_falco_jsonl_to_container_forensicator(
        tmp_path, monkeypatch):
    """Coordinator's _looks_like_falco_events helper picks up Falco JSONL
    when the evidence_kind isn't pre-set."""
    from el.orchestrator.coordinator import (
        _looks_like_falco_events, _looks_like_k8s_audit,
        _looks_like_cloudtrail,
    )
    log = tmp_path / "falco.jsonl"
    _write_falco_jsonl(log, [
        {"rule": "Container Drift detected", "priority": "CRITICAL",
         "output": "x", "output_fields": {}},
    ])
    assert _looks_like_falco_events(log)
    # And it's distinct from k8s-audit / cloudtrail.
    assert not _looks_like_k8s_audit(log)
    assert not _looks_like_cloudtrail(log)
