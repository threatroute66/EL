"""Falco event-JSONL skill — unit tests."""
import gzip
import json
from pathlib import Path

import pytest

from el.skills import falco_events as fe


# --- FalcoEvent.from_json -----------------------------------------

def test_event_from_json_full():
    obj = {
        "rule": "Container Escape via Privileged Mount",
        "priority": "Critical",
        "time": "2026-01-01T12:34:56Z",
        "output": "10.0.0.1 mounted /host inside container",
        "tags": ["container", "escape", "T1611"],
        "output_fields": {
            "container.id": "abc123def456",
            "container.name": "evil-pod",
            "k8s.ns.name": "default",
            "k8s.pod.name": "attacker",
            "proc.cmdline": "/bin/sh -c mount /host",
        },
    }
    e = fe.FalcoEvent.from_json(obj)
    assert e is not None
    assert e.rule == "Container Escape via Privileged Mount"
    assert e.priority == "CRITICAL"
    assert e.container_id == "abc123def456"
    assert e.k8s_pod == "attacker"
    assert "T1611" in e.tags


def test_event_from_json_returns_none_on_missing_rule():
    assert fe.FalcoEvent.from_json({"priority": "ERROR"}) is None
    assert fe.FalcoEvent.from_json({}) is None


def test_event_from_json_returns_none_for_non_dict():
    assert fe.FalcoEvent.from_json("not-a-dict") is None  # type: ignore
    assert fe.FalcoEvent.from_json([]) is None  # type: ignore


def test_event_truncates_long_output():
    obj = {"rule": "x", "priority": "INFO", "output": "X" * 1000}
    e = fe.FalcoEvent.from_json(obj)
    assert len(e.output) <= 500


# --- is_container_escape / is_k8s_privesc -----------------------

def test_is_container_escape_matches_keywords():
    e = fe.FalcoEvent(rule="Container Drift detected", priority="ERROR",
                       time="", output="")
    assert e.is_container_escape()


def test_is_container_escape_negative():
    e = fe.FalcoEvent(rule="Read sensitive file", priority="WARNING",
                       time="", output="")
    assert not e.is_container_escape()


def test_is_k8s_privesc_matches_keywords():
    e = fe.FalcoEvent(rule="Create Privileged Pod", priority="ERROR",
                       time="", output="")
    assert e.is_k8s_privesc()


def test_is_k8s_privesc_attach_to_cluster_admin():
    e = fe.FalcoEvent(rule="Attach to cluster-admin role binding",
                       priority="ERROR", time="", output="")
    assert e.is_k8s_privesc()


# --- severity_rank -----------------------------------------------

def test_severity_rank_orders_correctly():
    crit = fe.FalcoEvent(rule="x", priority="CRITICAL", time="", output="")
    info = fe.FalcoEvent(rule="x", priority="INFO", time="", output="")
    unknown = fe.FalcoEvent(rule="x", priority="MADE_UP", time="", output="")
    assert crit.severity_rank() < info.severity_rank() < unknown.severity_rank()


# --- looks_like_falco_jsonl --------------------------------------

def test_looks_like_falco_jsonl_true(tmp_path):
    p = tmp_path / "falco.jsonl"
    p.write_text(json.dumps({
        "rule": "Container Escape", "priority": "CRITICAL",
        "output": "x", "output_fields": {},
    }) + "\n")
    assert fe.looks_like_falco_jsonl(p)


def test_looks_like_falco_jsonl_false(tmp_path):
    p = tmp_path / "other.jsonl"
    p.write_text(json.dumps({"hello": "world"}) + "\n")
    assert not fe.looks_like_falco_jsonl(p)


def test_looks_like_falco_jsonl_skips_blank_lines(tmp_path):
    p = tmp_path / "with_blanks.jsonl"
    p.write_text("\n\n" + json.dumps({
        "rule": "x", "priority": "INFO", "output": "y",
    }) + "\n")
    assert fe.looks_like_falco_jsonl(p)


def test_looks_like_falco_jsonl_handles_invalid_first_line(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text("not-json-at-all\n")
    assert not fe.looks_like_falco_jsonl(p)


# --- parse_jsonl end-to-end -------------------------------------

def _write_falco(path: Path, events: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(e) for e in events) + "\n"
    )


def test_parse_jsonl_aggregates_priorities_and_rules(tmp_path):
    log = tmp_path / "falco.jsonl"
    _write_falco(log, [
        {"rule": "Container Drift detected", "priority": "Critical",
         "output": "x"},
        {"rule": "Container Drift detected", "priority": "Critical",
         "output": "x"},
        {"rule": "Read sensitive file", "priority": "Warning",
         "output": "x"},
        {"rule": "Create Privileged Pod", "priority": "Error",
         "output": "x"},
    ])
    result = fe.parse_jsonl(log)
    assert result.event_count == 4
    assert result.rule_hits["Container Drift detected"] == 2
    assert result.priority_counts["CRITICAL"] == 2
    assert result.priority_counts["WARNING"] == 1
    assert result.container_escape_hits == 2
    assert result.k8s_privesc_hits == 1


def test_parse_jsonl_handles_gzip(tmp_path):
    log = tmp_path / "falco.jsonl.gz"
    with gzip.open(log, "wt") as f:
        f.write(json.dumps({
            "rule": "Container Escape via mount", "priority": "CRITICAL",
            "output": "x",
        }) + "\n")
    result = fe.parse_jsonl(log)
    assert result.event_count == 1
    assert result.container_escape_hits == 1


def test_parse_jsonl_skips_invalid_lines(tmp_path):
    log = tmp_path / "falco.jsonl"
    log.write_text(
        "not-json\n"
        + json.dumps({"rule": "ok", "priority": "INFO", "output": "x"}) + "\n"
    )
    result = fe.parse_jsonl(log)
    assert result.event_count == 1


def test_parse_jsonl_raises_for_missing_file(tmp_path):
    with pytest.raises(fe.FalcoEventsError):
        fe.parse_jsonl(tmp_path / "nope.jsonl")


def test_parse_jsonl_counts_distinct_containers(tmp_path):
    log = tmp_path / "falco.jsonl"
    _write_falco(log, [
        {"rule": "x", "priority": "INFO", "output": "x",
         "output_fields": {"container.id": "abc", "container.name": "pod1"}},
        {"rule": "x", "priority": "INFO", "output": "x",
         "output_fields": {"container.id": "abc", "container.name": "pod1"}},
        {"rule": "x", "priority": "INFO", "output": "x",
         "output_fields": {"container.id": "def", "container.name": "pod2"}},
    ])
    result = fe.parse_jsonl(log)
    assert result.distinct_containers == 2


# --- high_priority_events ---------------------------------------

def test_high_priority_events_includes_critical_and_error(tmp_path):
    log = tmp_path / "falco.jsonl"
    _write_falco(log, [
        {"rule": "a", "priority": "CRITICAL", "output": "x"},
        {"rule": "b", "priority": "ERROR", "output": "x"},
        {"rule": "c", "priority": "INFO", "output": "x"},
        {"rule": "d", "priority": "WARNING", "output": "x"},
    ])
    result = fe.parse_jsonl(log)
    high = result.high_priority_events()
    rules = sorted(e.rule for e in high)
    assert rules == ["a", "b"]


# --- as_evidence ------------------------------------------------

def test_result_as_evidence_shape(tmp_path):
    log = tmp_path / "falco.jsonl"
    log.write_text("[]")
    result = fe.FalcoEventsResult(
        input_path=log, event_count=10, events=[],
        rule_hits={"r1": 5, "r2": 3, "r3": 2},
        priority_counts={"CRITICAL": 2, "INFO": 8},
        container_escape_hits=2, k8s_privesc_hits=1,
        distinct_containers=3, distinct_k8s_pods=2,
        output_sha256="g" * 64,
    )
    ev = result.as_evidence()
    assert ev.tool == "falco_events"
    assert ev.output_sha256 == "g" * 64
    assert ev.extracted_facts["event_count"] == 10
    assert ev.extracted_facts["container_escape_hits"] == 2
    # Top rule first.
    top_rules = list(ev.extracted_facts["top_rules"].keys())
    assert top_rules[0] == "r1"
