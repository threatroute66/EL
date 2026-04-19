"""Perf + scale regression tests for el.reporting.stix.emit_bundle.

Blind run on M57-Jean produced 6201 IOCs (many noise — PR-6 fixes the
extraction side). Before PR-9, STIX emission looped through every IOC
calling stix2.Indicator(), which validates the pattern string per
instance — 5000 indicators took 9+ minutes.

PR-9 builds indicator/attack-pattern dicts directly and reuses stix2
only for the bundle envelope. These tests lock in:
  - Wall-clock budget for large bundles
  - Cap + truncation-note when an IOC class exceeds the guardrail
  - Back-compat: existing stix_emit test still passes
"""
import json
import time

from el.reporting.stix import emit_bundle, _MAX_INDICATORS_PER_CLASS
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def _dummy_findings(n: int = 3) -> list[Finding]:
    return [
        Finding(case_id="c-perf", agent="memory", confidence="high",
                claim="malfind flagged a region", evidence=[_ev()],
                hypotheses_supported=["H_PROCESS_INJECTION"])
        for _ in range(n)
    ]


def test_1000_indicators_under_two_seconds(tmp_path):
    """1000 mixed IOCs should emit in well under the old 9-minute regime.
    Budget of 2s is loose enough to stay stable on slow CI."""
    iocs = {
        "ipv4": {f"203.0.113.{i}" for i in range(1, 256)},  # ~255
        "domain": {f"evil-{i}.example.com" for i in range(300)},
        "sha256": {f"{i:064x}" for i in range(300)},
        "email": {f"user{i}@evil.example" for i in range(200)},
    }
    total = sum(len(v) for v in iocs.values())
    assert total >= 1000

    out = tmp_path / "stix.json"
    t0 = time.monotonic()
    emit_bundle("c-perf", _dummy_findings(), iocs, out)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0, f"emit took {elapsed:.2f}s (budget 2.0s)"

    bundle = json.loads(out.read_text())
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) >= total


def test_indicator_schema_stays_stix_2_1_compliant(tmp_path):
    """Hand-built dicts must match the shape stix2 expects so external
    consumers still see well-formed objects."""
    iocs = {"domain": {"evil.example.com"}}
    out = tmp_path / "stix.json"
    emit_bundle("c1", _dummy_findings(), iocs, out)
    bundle = json.loads(out.read_text())

    inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert inds
    i = inds[0]
    # Required STIX 2.1 fields
    for field in ("type", "spec_version", "id", "created", "modified",
                  "pattern", "pattern_type", "valid_from", "indicator_types"):
        assert field in i, f"indicator missing {field}"
    assert i["spec_version"] == "2.1"
    assert i["id"].startswith("indicator--")
    assert i["pattern_type"] == "stix"
    assert i["pattern"] == "[domain-name:value = 'evil.example.com']"


def test_attack_pattern_has_mitre_reference(tmp_path):
    findings = [Finding(
        case_id="c1", agent="x", confidence="high",
        claim="y", evidence=[_ev()],
        hypotheses_supported=["H_PROCESS_INJECTION"],
    )]
    out = tmp_path / "stix.json"
    emit_bundle("c1", findings, {}, out)
    bundle = json.loads(out.read_text())
    aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert aps
    ap = aps[0]
    refs = ap["external_references"]
    assert any(r["source_name"] == "mitre-attack" for r in refs)
    assert any(r["external_id"].startswith("T") for r in refs)


def test_indicator_class_capped_on_excess(tmp_path):
    """If a single IOC class exceeds _MAX_INDICATORS_PER_CLASS, emit
    the sorted-first N and note truncation in the report description.
    Primarily a guardrail against pathological bodyfile extraction."""
    cap = _MAX_INDICATORS_PER_CLASS
    huge = {f"203.0.113.{i // 254}_{i}" for i in range(cap + 100)}
    # Not real IPs — simulate the worst-case volume without the regex
    iocs = {"sha256": {f"{i:064x}" for i in range(cap + 50)}}
    out = tmp_path / "stix.json"
    emit_bundle("c-cap", _dummy_findings(), iocs, out)
    bundle = json.loads(out.read_text())
    inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(inds) == cap
    reports = [o for o in bundle["objects"] if o["type"] == "report"]
    assert reports and "Truncated" in reports[0]["description"]


def test_empty_iocs_still_emits_valid_bundle(tmp_path):
    out = tmp_path / "stix.json"
    emit_bundle("c1", [], {}, out)
    bundle = json.loads(out.read_text())
    # Identity + Report always present; no indicators/attack-patterns
    types = [o["type"] for o in bundle["objects"]]
    assert "identity" in types
    assert "report" in types
    assert "indicator" not in types


def test_single_quote_in_ioc_value_does_not_break_pattern(tmp_path):
    """STIX patterns use single quotes; strip any apostrophes from values
    to avoid generating invalid patterns."""
    iocs = {"domain": {"bad'domain.example.com"}}
    out = tmp_path / "stix.json"
    emit_bundle("c1", _dummy_findings(), iocs, out)
    bundle = json.loads(out.read_text())
    inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
    # Pattern must be syntactically valid — no mid-quote split
    assert inds[0]["pattern"].count("'") == 2
