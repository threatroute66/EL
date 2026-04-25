"""MITRE CAR analytic loader + per-technique coverage map.

Closes the gap-doc Detection-engineering deferred row "MITRE CAR
analytic import (overlaps SIGMA)". Sibling format to SIGMA — same
hunt-rule role, different vendor; loads JSON/YAML files into
CarAnalytic records and surfaces which analytics cover a case's
observed techniques.
"""
import json
from pathlib import Path

import pytest

from el.skills import mitre_car as car


def _stage(tmp_path: Path, contents: dict) -> Path:
    """Drop a CAR analytic JSON into `tmp_path/car/<filename>`."""
    car_dir = tmp_path / "car"
    car_dir.mkdir()
    for name, body in contents.items():
        (car_dir / name).write_text(json.dumps(body))
    return car_dir


def test_load_analytics_parses_canonical_json(tmp_path):
    car_dir = _stage(tmp_path, {
        "CAR-2014-04-001.json": {
            "id": "CAR-2014-04-001",
            "title": "User Logon Type 3 from External IP",
            "description": "Detect remote network logons (T1078.002).",
            "coverage": [{"technique": "T1078.002"},
                          {"technique": "T1021.002"}],
            "tactics": ["lateral-movement"],
            "platforms": ["windows"],
        },
    })
    analytics = car.load_analytics(car_dir)
    assert len(analytics) == 1
    a = analytics[0]
    assert a.car_id == "CAR-2014-04-001"
    assert "T1078.002" in a.technique_ids
    assert "T1021.002" in a.technique_ids
    assert a.tactics == ["lateral-movement"]


def test_extract_technique_ids_from_description_text(tmp_path):
    """Some CAR files put the T-id in the description rather than in
    a `coverage` array. Regex-fallback should still pick them up."""
    car_dir = _stage(tmp_path, {
        "CAR-x.json": {
            "title": "Some hunt",
            "description": "Detects T1003.001 LSASS memory dumping.",
        },
    })
    analytics = car.load_analytics(car_dir)
    assert analytics[0].technique_ids == ["T1003.001"]


def test_coverage_for_techniques_filters_to_observed(tmp_path):
    car_dir = _stage(tmp_path, {
        "a.json": {"title": "A", "coverage": [{"technique": "T1003.001"}]},
        "b.json": {"title": "B", "coverage": [{"technique": "T1059.001"}]},
        "c.json": {"title": "C", "coverage": [{"technique": "T1003.001"},
                                                 {"technique": "T1078"}]},
    })
    cov = car.coverage_for_techniques(["T1003.001", "T1059.001"], car_dir)
    assert set(cov.keys()) == {"T1003.001", "T1059.001"}
    # Two analytics for T1003.001 (a + c), one for T1059.001 (b)
    assert len(cov["T1003.001"]) == 2
    assert len(cov["T1059.001"]) == 1


def test_missing_dir_returns_empty_safely(tmp_path):
    # No CAR directory at all
    assert car.load_analytics(tmp_path / "nope") == []
    assert car.coverage_for_techniques(["T1003"], tmp_path / "nope") == {}


def test_malformed_json_is_skipped(tmp_path):
    car_dir = tmp_path / "car"
    car_dir.mkdir()
    (car_dir / "bad.json").write_text("{not valid json")
    (car_dir / "good.json").write_text(json.dumps(
        {"title": "Good", "coverage": [{"technique": "T1003"}]}))
    out = car.load_analytics(car_dir)
    assert len(out) == 1
    assert out[0].title == "Good"
