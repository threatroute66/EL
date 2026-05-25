"""Contract tests for el/intel/attack_capacities.py.

The capacity mapping is the Diamond Model's bridge between observed
ATT&CK techniques (the *how*) and the Capability Capacity vertex
(*what those techniques can reach*) per Caltagirone/Pendergast/Betz
2013 §4.2.

Locks in:
  * Direct lookup for known techniques returns a non-empty string
  * Sub-technique falls back to parent (T1003.099 → T1003)
  * Unknown techniques return None (not a placeholder)
  * COVERAGE GUARANTEE — every technique in attack_tactics.TECHNIQUE_TACTIC
    (the canonical EL-emitted set) MUST have a capacity entry. New
    technique additions that forget to update attack_capacities.py
    will fail this test.
"""
from __future__ import annotations

import pytest

from el.intel.attack_capacities import (
    TECHNIQUE_CAPACITY,
    capacity_for,
    uncovered_techniques,
)
from el.intel.attack_tactics import TECHNIQUE_TACTIC


def test_known_technique_returns_capacity():
    cap = capacity_for("T1003")
    assert cap is not None
    assert "credential" in cap.lower()


def test_known_subtechnique_returns_specific_capacity():
    """Specific sub-technique gets its own line, distinct from
    the parent's general capacity."""
    parent = capacity_for("T1003")
    sub = capacity_for("T1003.001")  # LSASS Memory specifically
    assert parent is not None and sub is not None
    assert sub != parent
    assert "LSASS" in sub or "lsass" in sub.lower()


def test_subtechnique_falls_back_to_parent_when_unmapped():
    """A made-up sub-technique like T1003.999 still resolves via
    the parent T1003. This is intentional — sub-technique
    splits in MITRE shift over time, and the parent's capacity
    is always a defensible upper bound."""
    cap = capacity_for("T1003.999")
    assert cap is not None
    assert cap == capacity_for("T1003")


def test_unknown_technique_returns_none():
    """No mapping for a completely unknown ID — callers can decide
    whether to skip or emit a tactic-level placeholder."""
    assert capacity_for("T9999.999") is None
    assert capacity_for("") is None
    assert capacity_for("not-a-technique") is None


def test_no_techniques_emitted_by_el_lack_capacity_coverage():
    """COVERAGE GUARANTEE. Every technique EL knows how to emit
    (catalogued in attack_tactics.TECHNIQUE_TACTIC) must have a
    Capacity string — either directly mapped or resolvable via
    the parent-technique fallback. This is the regression test
    that fires when a new technique ID is added to
    attack_tactics.py without a paired capacity entry."""
    missing = uncovered_techniques()
    assert missing == [], (
        f"the following EL-emitted techniques have no Capacity "
        f"mapping in attack_capacities.TECHNIQUE_CAPACITY (add "
        f"an entry for each, or document why a tactic-level "
        f"fallback is acceptable): {missing}"
    )


def test_capacity_strings_are_plain_english():
    """Capacity descriptions must not contain ATT&CK technique IDs
    or internal hypothesis tag names — the Diamond renderer surfaces
    these to non-technical readers in the Capability vertex. (Per
    the AI brief constraints set in executive_ai.py.)"""
    for tid, cap in TECHNIQUE_CAPACITY.items():
        # Allow T-IDs in tracking comments but the string itself
        # mustn't carry an ATT&CK ID that the reader would have to
        # look up.
        assert "T1" not in cap, (
            f"capacity for {tid} contains an ATT&CK ID: {cap!r}")
        assert "H_" not in cap, (
            f"capacity for {tid} contains a hypothesis tag: {cap!r}")
        assert len(cap) > 10, (
            f"capacity for {tid} is too terse to be useful: "
            f"{cap!r}")


@pytest.mark.parametrize("tid", sorted(TECHNIQUE_TACTIC.keys())[:20])
def test_random_sample_of_el_techniques_have_meaningful_capacity(tid):
    """Spot-check the first 20 canonical EL technique IDs — each
    must resolve to a non-trivial capacity. This is paranoia on top
    of the coverage guarantee."""
    cap = capacity_for(tid)
    assert cap is not None
    assert isinstance(cap, str) and len(cap) > 10
