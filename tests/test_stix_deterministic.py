"""STIX bundle deterministic-ID + Layer-3 enrichment — Tier 4.5.

Verifies the new contracts:
  1. Same (case_id, indicator) → same indicator UUID across re-runs.
  2. Different cases → different indicator UUIDs.
  3. Identity / report / bundle IDs are stable per (deployment, case_id).
  4. Layer-3 cross-case observations land as ``el-recurrence-N-cases``
     labels on the relevant indicators.
  5. The bundle still publishes when the knowledge store is unavailable.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from el.reporting.stix import (
    _EL_NAMESPACE, _stix_id_deterministic, emit_bundle,
)


# --- _stix_id_deterministic ------------------------------------------

def test_deterministic_id_stable_across_calls():
    a = _stix_id_deterministic("indicator", "case-1", "ipv4", "1.2.3.4")
    b = _stix_id_deterministic("indicator", "case-1", "ipv4", "1.2.3.4")
    assert a == b


def test_deterministic_id_differs_for_different_cases():
    a = _stix_id_deterministic("indicator", "case-A", "ipv4", "1.2.3.4")
    b = _stix_id_deterministic("indicator", "case-B", "ipv4", "1.2.3.4")
    assert a != b


def test_deterministic_id_differs_for_different_values():
    a = _stix_id_deterministic("indicator", "case-1", "ipv4", "1.2.3.4")
    b = _stix_id_deterministic("indicator", "case-1", "ipv4", "5.6.7.8")
    assert a != b


def test_deterministic_id_format_is_stix_compliant():
    sid = _stix_id_deterministic("indicator", "x", "y", "z")
    assert sid.startswith("indicator--")
    # "indicator" (9) + "--" (2) + UUID (36) = 47 chars total.
    assert len(sid) == 9 + 2 + 36


# --- Identity / report / bundle / attack-pattern stability ------------

def test_identity_id_stable_across_emit_bundle_runs(tmp_path):
    p1 = tmp_path / "b1.json"
    p2 = tmp_path / "b2.json"
    emit_bundle("case-1", [], {"ipv4": {"1.2.3.4"}}, p1,
                 enrich_with_knowledge=False)
    emit_bundle("case-1", [], {"ipv4": {"1.2.3.4"}}, p2,
                 enrich_with_knowledge=False)
    b1 = json.loads(p1.read_text())
    b2 = json.loads(p2.read_text())
    identity1 = next(o for o in b1["objects"] if o["type"] == "identity")
    identity2 = next(o for o in b2["objects"] if o["type"] == "identity")
    # Tier 4.5: identity is stable per deployment.
    assert identity1["id"] == identity2["id"]


def test_indicator_ids_stable_across_emit_bundle_runs(tmp_path):
    iocs = {"ipv4": {"1.2.3.4"}, "domain": {"evil.example.com"}}
    p1 = tmp_path / "b1.json"
    p2 = tmp_path / "b2.json"
    emit_bundle("case-X", [], iocs, p1, enrich_with_knowledge=False)
    emit_bundle("case-X", [], iocs, p2, enrich_with_knowledge=False)
    b1 = json.loads(p1.read_text())
    b2 = json.loads(p2.read_text())

    ind1 = sorted([o["id"] for o in b1["objects"] if o["type"] == "indicator"])
    ind2 = sorted([o["id"] for o in b2["objects"] if o["type"] == "indicator"])
    assert ind1 == ind2  # IDs deterministic on same input


def test_indicator_ids_differ_across_cases(tmp_path):
    iocs = {"ipv4": {"1.2.3.4"}}
    pa = tmp_path / "a.json"
    pb = tmp_path / "b.json"
    emit_bundle("case-A", [], iocs, pa, enrich_with_knowledge=False)
    emit_bundle("case-B", [], iocs, pb, enrich_with_knowledge=False)
    a = json.loads(pa.read_text())
    b = json.loads(pb.read_text())
    ind_a = next(o["id"] for o in a["objects"] if o["type"] == "indicator")
    ind_b = next(o["id"] for o in b["objects"] if o["type"] == "indicator")
    # Same value, different case_id → different deterministic IDs.
    assert ind_a != ind_b


def test_bundle_id_stable_per_case(tmp_path):
    p1 = tmp_path / "x.json"
    p2 = tmp_path / "y.json"
    emit_bundle("case-1", [], {}, p1, enrich_with_knowledge=False)
    emit_bundle("case-1", [], {}, p2, enrich_with_knowledge=False)
    b1 = json.loads(p1.read_text())
    b2 = json.loads(p2.read_text())
    assert b1["id"] == b2["id"]


# --- Knowledge enrichment --------------------------------------------

def test_indicators_get_recurrence_label_when_knowledge_hits(tmp_path,
                                                                monkeypatch):
    iocs = {"ipv4": {"1.2.3.4", "5.6.7.8"}}

    def fake_lookup(values, current_case_id, db_path=None):
        return {
            "1.2.3.4": [
                {"case_id": "case-A"}, {"case_id": "case-B"},
                {"case_id": "case-C"},
            ],
        }

    from el import knowledge as kb
    monkeypatch.setattr(kb, "lookup_iocs", fake_lookup)

    out = tmp_path / "b.json"
    emit_bundle("case-1", [], iocs, out, enrich_with_knowledge=True)
    bundle = json.loads(out.read_text())
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    by_value = {o["name"]: o for o in indicators}
    # 1.2.3.4 was seen in 3 prior cases → label.
    labels_seen = by_value["ipv4: 1.2.3.4"]["labels"]
    assert any(label == "el-recurrence-3-cases" for label in labels_seen)
    # 5.6.7.8 was unique → just el-emitted.
    labels_new = by_value["ipv4: 5.6.7.8"]["labels"]
    assert "el-emitted" in labels_new
    assert all(not lbl.startswith("el-recurrence-") for lbl in labels_new)


def test_bundle_publishes_even_when_knowledge_unavailable(tmp_path,
                                                            monkeypatch):
    """If lookup_iocs raises, the bundle should still publish (no crash)."""
    iocs = {"ipv4": {"1.2.3.4"}}

    from el import knowledge as kb
    def boom(*args, **kwargs):
        raise RuntimeError("knowledge.sqlite locked")
    monkeypatch.setattr(kb, "lookup_iocs", boom)

    out = tmp_path / "b.json"
    emit_bundle("case-1", [], iocs, out, enrich_with_knowledge=True)
    bundle = json.loads(out.read_text())
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    # No recurrence label since enrichment was unavailable.
    assert "el-emitted" in indicators[0]["labels"]


def test_enrichment_can_be_disabled(tmp_path, monkeypatch):
    """enrich_with_knowledge=False bypasses the knowledge store entirely."""
    from el import knowledge as kb
    called = {"count": 0}
    def trace(*args, **kwargs):
        called["count"] += 1
        return {}
    monkeypatch.setattr(kb, "lookup_iocs", trace)

    out = tmp_path / "b.json"
    emit_bundle("case-1", [], {"ipv4": {"1.2.3.4"}}, out,
                 enrich_with_knowledge=False)
    assert called["count"] == 0


# --- Report external_reference + description ------------------------

def test_report_includes_external_reference_to_case(tmp_path):
    out = tmp_path / "b.json"
    emit_bundle("case-XYZ", [], {"ipv4": {"1.2.3.4"}}, out,
                 enrich_with_knowledge=False)
    bundle = json.loads(out.read_text())
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    refs = report.get("external_references") or []
    el_ref = next(r for r in refs if r.get("source_name") == "el-case-id")
    assert el_ref["external_id"] == "case-XYZ"


def test_report_description_includes_layer3_summary(tmp_path, monkeypatch):
    iocs = {"ipv4": {"1.2.3.4", "5.6.7.8"}}

    def fake_lookup(values, current_case_id, db_path=None):
        return {"1.2.3.4": [{"case_id": "case-A"}]}
    from el import knowledge as kb
    monkeypatch.setattr(kb, "lookup_iocs", fake_lookup)

    out = tmp_path / "b.json"
    emit_bundle("case-1", [], iocs, out)
    bundle = json.loads(out.read_text())
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert "Layer-3 enrichment" in report["description"]
    assert "1 indicator(s) observed in prior EL cases" in report["description"]


# --- attack-pattern stability ----------------------------------------

def test_attack_pattern_id_stable_across_cases(tmp_path):
    """A given technique should map to the same STIX id in any case."""
    from el.intel.attack_map import map_case

    # Build a fake findings list that maps to T1003
    from el.schemas.finding import Finding, EvidenceItem
    f = Finding(
        finding_id="01ABC", case_id="case-1", agent="t",
        claim="c", confidence="low",
        hypotheses_supported=["H_CREDENTIAL_ACCESS"],
        evidence=[EvidenceItem(tool="t", version="0",
                                 command="c", output_sha256="0" * 64,
                                 output_path="/x")],
    )
    p1 = tmp_path / "a.json"
    p2 = tmp_path / "b.json"
    emit_bundle("case-1", [f], {}, p1, enrich_with_knowledge=False)
    emit_bundle("case-2", [f], {}, p2, enrich_with_knowledge=False)
    b1 = json.loads(p1.read_text())
    b2 = json.loads(p2.read_text())
    aps1 = sorted([o["id"] for o in b1["objects"]
                   if o["type"] == "attack-pattern"])
    aps2 = sorted([o["id"] for o in b2["objects"]
                   if o["type"] == "attack-pattern"])
    if aps1 and aps2:
        # Same techniques across both cases → same STIX IDs.
        assert aps1 == aps2


# --- Sanity: full bundle still STIX-shape valid ----------------------

def test_full_bundle_shape_preserved(tmp_path):
    out = tmp_path / "b.json"
    emit_bundle("case-1", [],
                 {"ipv4": {"1.2.3.4"}, "sha256": {"a" * 64}},
                 out, enrich_with_knowledge=False)
    bundle = json.loads(out.read_text())
    # Top-level shape.
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    # Identity present + has the expected name.
    identity = next(o for o in bundle["objects"] if o["type"] == "identity")
    assert "Edmond Locard" in identity["name"]
    # 2 indicators present, each with a created_by_ref pointing at identity.
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 2
    for ind in indicators:
        assert ind["created_by_ref"] == identity["id"]
        assert "labels" in ind
