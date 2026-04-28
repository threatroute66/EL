"""Phase 0 contract tests for el.case_metadata.

The case_metadata module records analyst-supplied context (investigator,
objective, external case number, incident date) on top of the
deterministic intake manifest. These tests lock in the contract:

  - All fields optional with sensible defaults
  - is_empty() distinguishes annotated vs un-annotated cases
  - JSON round-trip preserves every field including the date type
  - load() returns an empty CaseMetadata for cases that predate the feature
"""
from datetime import date

import pytest

from el.case_metadata import (
    CASE_METADATA_FILENAME,
    CaseMetadata,
    load,
    path_for,
    save,
)


def test_default_metadata_is_empty():
    m = CaseMetadata()
    assert m.is_empty()
    assert m.case_number is None
    assert m.incident_date is None
    assert m.investigator_name is None
    assert m.objective_statement is None


def test_partial_metadata_is_not_empty():
    m = CaseMetadata(investigator_name="M. Cingoz")
    assert not m.is_empty()


def test_full_metadata_round_trip(tmp_path):
    m = CaseMetadata(
        case_number="IR-2026-0001",
        incident_date=date(2026, 4, 15),
        investigator_name="M. Cingoz",
        objective_statement="Determine whether the laptop was used for data exfiltration.",
    )
    save(tmp_path, m)
    p = path_for(tmp_path)
    assert p.exists() and p.name == CASE_METADATA_FILENAME

    loaded = load(tmp_path)
    assert loaded.case_number == "IR-2026-0001"
    assert loaded.incident_date == date(2026, 4, 15)
    assert loaded.investigator_name == "M. Cingoz"
    assert loaded.objective_statement.startswith("Determine")
    assert not loaded.is_empty()


def test_load_missing_file_returns_empty(tmp_path):
    """Cases predating this feature have no case_metadata.json. The
    renderer must not crash — it should see an empty CaseMetadata and
    fall back to neutral placeholders."""
    m = load(tmp_path)
    assert isinstance(m, CaseMetadata)
    assert m.is_empty()


def test_save_creates_parent_directory(tmp_path):
    target = tmp_path / "nested" / "case-x"
    save(target, CaseMetadata(investigator_name="X"))
    assert (target / CASE_METADATA_FILENAME).exists()
