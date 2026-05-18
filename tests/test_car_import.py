"""Tests for el.skills.car_import — MITRE Cyber Analytics Repository
loader.

CAR analytics often ship a sigma implementation snippet inside their
YAML. The skill extracts that snippet, decorates it with the
analytic's coverage[] block as ATT&CK tags + a `car.<ID>` provenance
tag, then hands the result to the existing sigma_engine for normal
parsing + matching.

Pins:
  - sigma snippet extraction (skip non-sigma implementations)
  - coverage[] → attack.tNNNN[.sss] tag injection
  - existing snippet tags preserved (union, no clobber)
  - CAR analytics without a sigma impl silently skipped
  - malformed YAML doesn't break the load loop
  - rule.file_path round-trips back to the original CAR YAML (not
    the ephemeral temp-dir path the parser uses internally)
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from el.skills.car_import import (
    CarAnalytic,
    _coverage_to_attack_tags,
    _extract_sigma_snippet,
    _materialise_sigma_yaml,
    load_car_rules,
    parse_analytic,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_analytic(dir: Path, car_id: str, *, sigma_yaml: str | None,
                     coverage: list[dict] | None = None,
                     title: str = "Test analytic") -> Path:
    """Write a CAR-shaped YAML to disk. Returns the path."""
    impls = []
    if sigma_yaml is not None:
        impls.append({
            "name": "Sigma rule",
            "type": "sigma",
            "code": sigma_yaml,
        })
        # Always include a non-sigma impl too — pseudocode is the
        # one CAR always carries. Tests that real-CAR analytics
        # carrying multiple impls are handled correctly.
        impls.append({
            "name": "Pseudocode",
            "type": "pseudocode",
            "code": "processes = ...",
        })
    doc = {
        "id": car_id,
        "title": title,
        "description": f"Description for {car_id}",
        "coverage": coverage or [{"technique": "T1059", "coverage": "Moderate"}],
        "implementations": impls,
    }
    p = dir / f"{car_id}.yaml"
    p.write_text(yaml.safe_dump(doc))
    return p


_MINIMAL_SIGMA = """\
title: Inline-decoded base64 in PowerShell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains: 'FromBase64String'
  condition: selection
level: medium
"""


# ---------------------------------------------------------------------------
# _extract_sigma_snippet — find the right implementation
# ---------------------------------------------------------------------------

def test_extract_picks_sigma_implementation():
    impls = [
        {"name": "Splunk", "type": "splunk-search", "code": "search ..."},
        {"name": "Sigma", "type": "sigma", "code": "title: foo"},
        {"name": "Pseudo", "type": "pseudocode", "code": "x = y"},
    ]
    assert _extract_sigma_snippet(impls) == "title: foo"


def test_extract_returns_empty_when_no_sigma_impl():
    impls = [
        {"name": "Splunk", "type": "splunk-search", "code": "search ..."},
        {"name": "Pseudo", "type": "pseudocode", "code": "x = y"},
    ]
    assert _extract_sigma_snippet(impls) == ""


def test_extract_handles_none_impls():
    assert _extract_sigma_snippet(None) == ""
    assert _extract_sigma_snippet([]) == ""


def test_extract_ignores_empty_sigma_code():
    """A sigma impl entry with whitespace-only `code` field must
    not pass through — treat as if no sigma impl."""
    impls = [{"name": "Sigma", "type": "sigma", "code": "   \n   "}]
    assert _extract_sigma_snippet(impls) == ""


# ---------------------------------------------------------------------------
# _coverage_to_attack_tags — CAR coverage → SIGMA-style tags
# ---------------------------------------------------------------------------

def test_coverage_to_attack_tags_simple_technique():
    cov = [{"technique": "T1190", "coverage": "Moderate"}]
    assert _coverage_to_attack_tags(cov) == ["attack.t1190"]


def test_coverage_to_attack_tags_with_subtechnique():
    """CAR stores `subtechnique: '001'` (zero-padded) vs SIGMA's
    `attack.t1003.001` dotted form. Helper bridges that."""
    cov = [{"technique": "T1003", "subtechnique": "001"}]
    assert _coverage_to_attack_tags(cov) == ["attack.t1003.001"]


def test_coverage_to_attack_tags_multi_entry():
    cov = [
        {"technique": "T1190"},
        {"technique": "T1059", "subtechnique": "001"},
    ]
    assert _coverage_to_attack_tags(cov) == [
        "attack.t1190", "attack.t1059.001",
    ]


def test_coverage_to_attack_tags_handles_empty():
    assert _coverage_to_attack_tags(None) == []
    assert _coverage_to_attack_tags([]) == []


def test_coverage_to_attack_tags_skips_malformed_entries():
    """Defensive: a coverage entry without a `technique` field
    must be skipped, not crash."""
    cov = [
        {"technique": "T1059"},
        {"coverage": "Moderate"},   # missing technique
        "not a dict",                # wrong type
    ]
    assert _coverage_to_attack_tags(cov) == ["attack.t1059"]


# ---------------------------------------------------------------------------
# parse_analytic — read one CAR YAML
# ---------------------------------------------------------------------------

def test_parse_analytic_minimal(tmp_path):
    p = _write_analytic(tmp_path, "CAR-2020-09-001",
                         sigma_yaml=_MINIMAL_SIGMA)
    a = parse_analytic(p)
    assert a is not None
    assert a.car_id == "CAR-2020-09-001"
    assert a.title == "Test analytic"
    assert "FromBase64String" in a.sigma_code


def test_parse_analytic_rejects_non_car_id(tmp_path):
    """Files that aren't CAR analytics (no CAR-* id) return None
    so a directory of mixed YAMLs doesn't pick up SIGMA rules by
    accident."""
    p = tmp_path / "random.yaml"
    p.write_text(yaml.safe_dump({"id": "random-id", "title": "Not CAR"}))
    assert parse_analytic(p) is None


def test_parse_analytic_handles_missing_id(tmp_path):
    p = tmp_path / "headless.yaml"
    p.write_text(yaml.safe_dump({"title": "No id field"}))
    assert parse_analytic(p) is None


def test_parse_analytic_handles_malformed_yaml(tmp_path):
    """Garbage YAML must not raise — return None and let the
    caller skip."""
    p = tmp_path / "broken.yaml"
    p.write_text("this is: not: valid: yaml: [\nbroken")
    assert parse_analytic(p) is None


# ---------------------------------------------------------------------------
# _materialise_sigma_yaml — tag injection
# ---------------------------------------------------------------------------

def test_materialise_injects_car_provenance_tag(tmp_path):
    p = _write_analytic(tmp_path, "CAR-2020-09-001",
                         sigma_yaml=_MINIMAL_SIGMA,
                         coverage=[{"technique": "T1059", "subtechnique": "001"}])
    a = parse_analytic(p)
    rendered = _materialise_sigma_yaml(a)
    doc = yaml.safe_load(rendered)
    assert "car.CAR-2020-09-001" in doc["tags"]
    assert "attack.t1059.001" in doc["tags"]


def test_materialise_preserves_existing_tags(tmp_path):
    """If the CAR-embedded sigma snippet already declares tags,
    the merger must union — not clobber. CAR analytics often
    include richer tags than the coverage[] block alone (e.g.
    `attack.persistence`, `windows`, `linux` keywords)."""
    sigma_with_tags = (
        "title: x\n"
        "tags:\n"
        "  - attack.persistence\n"
        "  - windows\n"
        "detection:\n"
        "  selection:\n"
        "    EventID: 1\n"
        "  condition: selection\n"
    )
    p = _write_analytic(tmp_path, "CAR-2020-09-002",
                         sigma_yaml=sigma_with_tags,
                         coverage=[{"technique": "T1059"}])
    a = parse_analytic(p)
    rendered = _materialise_sigma_yaml(a)
    doc = yaml.safe_load(rendered)
    tags = doc["tags"]
    # Original tags survive
    assert "attack.persistence" in tags
    assert "windows" in tags
    # CAR-injected tags also present
    assert "car.CAR-2020-09-002" in tags
    assert "attack.t1059" in tags


def test_materialise_deduplicates_tags(tmp_path):
    """If the analytic's snippet already carries an
    attack.t1059 tag and the coverage[] block also adds t1059,
    the merge must dedupe — no double-tagged rule."""
    sigma_with_dup = (
        "title: x\n"
        "tags:\n"
        "  - attack.t1059\n"
        "detection:\n"
        "  selection:\n"
        "    EventID: 1\n"
        "  condition: selection\n"
    )
    p = _write_analytic(tmp_path, "CAR-2020-09-003",
                         sigma_yaml=sigma_with_dup,
                         coverage=[{"technique": "T1059"}])
    a = parse_analytic(p)
    rendered = _materialise_sigma_yaml(a)
    doc = yaml.safe_load(rendered)
    assert doc["tags"].count("attack.t1059") == 1


def test_materialise_handles_malformed_snippet(tmp_path):
    """A sigma snippet that itself is broken YAML must return ""
    rather than raise — caller will skip the analytic."""
    p = _write_analytic(tmp_path, "CAR-2020-09-004",
                         sigma_yaml="not: valid: [yaml")
    a = parse_analytic(p)
    assert _materialise_sigma_yaml(a) == ""


# ---------------------------------------------------------------------------
# load_car_rules — end-to-end directory walk
# ---------------------------------------------------------------------------

def test_load_car_rules_returns_parsed_sigma_rules(tmp_path):
    """Full pipeline — CAR YAML on disk → SigmaRule object the
    existing engine recognises."""
    _write_analytic(tmp_path, "CAR-2020-09-005",
                     sigma_yaml=_MINIMAL_SIGMA,
                     coverage=[{"technique": "T1059", "subtechnique": "001"}])
    rules = load_car_rules(tmp_path)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.id == "CAR-2020-09-005"
    assert "car.CAR-2020-09-005" in rule.tags
    assert "attack.t1059.001" in rule.tags
    assert rule.skipped_reason == ""


def test_load_car_rules_skips_non_sigma_analytics(tmp_path):
    """An analytic with only pseudocode / Splunk implementations
    is silently skipped — we can't run those."""
    _write_analytic(tmp_path, "CAR-2020-09-006",
                     sigma_yaml=None)  # no sigma impl
    rules = load_car_rules(tmp_path)
    assert rules == []


def test_load_car_rules_handles_empty_dir(tmp_path):
    rules = load_car_rules(tmp_path)
    assert rules == []


def test_load_car_rules_handles_missing_dir(tmp_path):
    rules = load_car_rules(tmp_path / "does-not-exist")
    assert rules == []


def test_load_car_rules_skips_malformed_analytics(tmp_path):
    """One broken analytic must not break the load loop —
    surviving analytics still get returned."""
    _write_analytic(tmp_path, "CAR-2020-09-007",
                     sigma_yaml=_MINIMAL_SIGMA)
    (tmp_path / "broken.yaml").write_text("not: valid: [yaml")
    rules = load_car_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].id == "CAR-2020-09-007"


def test_load_car_rules_file_path_points_at_original_car_yaml(tmp_path):
    """The internal materialiser writes to a temp dir that gets
    cleaned up. Pin that rule.file_path points at the ORIGINAL
    CAR YAML on disk — so operator-facing error messages /
    debug logs cite the actual source-of-truth file the analyst
    can edit."""
    car_path = _write_analytic(tmp_path, "CAR-2020-09-008",
                                 sigma_yaml=_MINIMAL_SIGMA)
    rules = load_car_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].file_path == car_path
    # And — critically — the file still exists (rule.file_path is
    # not a vanished temp file).
    assert rules[0].file_path.is_file()


def test_load_car_rules_with_multiple_analytics(tmp_path):
    """Multiple analytics → multiple rules; ordering reflects
    sigma_engine's walk (deterministic across runs)."""
    for i, tid in enumerate(["T1059", "T1003", "T1190"]):
        _write_analytic(tmp_path, f"CAR-2020-09-0{10+i}",
                         sigma_yaml=_MINIMAL_SIGMA,
                         coverage=[{"technique": tid}])
    rules = load_car_rules(tmp_path)
    assert len(rules) == 3
    by_id = {r.id: r for r in rules}
    assert "CAR-2020-09-010" in by_id
    assert "CAR-2020-09-011" in by_id
    assert "CAR-2020-09-012" in by_id


def test_load_car_rules_single_file_input(tmp_path):
    """When called with a single .yaml file (not a directory),
    just process that one file."""
    car_path = _write_analytic(tmp_path, "CAR-2020-09-013",
                                 sigma_yaml=_MINIMAL_SIGMA)
    rules = load_car_rules(car_path)
    assert len(rules) == 1
    assert rules[0].id == "CAR-2020-09-013"
