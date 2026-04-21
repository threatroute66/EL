"""Tests for el.intel.long_tail — IOC rarity bucketing."""
import pytest

from el.intel import long_tail as lt


# ---------------------------------------------------------------------------
# Bucket thresholds
# ---------------------------------------------------------------------------

def test_bucket_rare_at_zero_one_two():
    assert lt.bucket_for_case_count(0) == "rare"
    assert lt.bucket_for_case_count(1) == "rare"
    assert lt.bucket_for_case_count(2) == "rare"


def test_bucket_uncommon_three_to_ten():
    assert lt.bucket_for_case_count(3) == "uncommon"
    assert lt.bucket_for_case_count(10) == "uncommon"


def test_bucket_common_eleven_to_fifty():
    assert lt.bucket_for_case_count(11) == "common"
    assert lt.bucket_for_case_count(50) == "common"


def test_bucket_ubiquitous_above_fifty():
    assert lt.bucket_for_case_count(51) == "ubiquitous"
    assert lt.bucket_for_case_count(500) == "ubiquitous"


# ---------------------------------------------------------------------------
# score() — per-value rarity
# ---------------------------------------------------------------------------

def test_score_extracts_distinct_case_count():
    obs = [
        {"case_id": "a", "ioc_type": "ipv4"},
        {"case_id": "a", "ioc_type": "ipv4"},    # same case counted once
        {"case_id": "b", "ioc_type": "ipv4"},
    ]
    r = lt.score("1.1.1.1", obs)
    assert r.case_count == 2
    assert r.bucket == "rare"


def test_score_empty_observations_is_rare():
    r = lt.score("x.example.com", [])
    assert r.case_count == 0
    assert r.bucket == "rare"


def test_score_handles_missing_case_id():
    obs = [{"case_id": "a"}, {"ioc_type": "domain"}]
    r = lt.score("x", obs)
    # Only 'a' has a case_id → count = 1
    assert r.case_count == 1


# ---------------------------------------------------------------------------
# Batch scoring + suppression
# ---------------------------------------------------------------------------

def test_score_many_returns_per_value_dict():
    lookup = {
        "rare-ip": [{"case_id": "c1"}],
        "common-domain": [{"case_id": f"c{i}"} for i in range(20)],
    }
    scored = lt.score_many(lookup)
    assert scored["rare-ip"].bucket == "rare"
    assert scored["common-domain"].bucket == "common"


def test_should_suppress_only_ubiquitous():
    assert not lt.should_suppress("rare")
    assert not lt.should_suppress("uncommon")
    assert not lt.should_suppress("common")
    assert lt.should_suppress("ubiquitous")


def test_confidence_modifier_tiers():
    assert lt.confidence_modifier("rare") == "high"
    assert lt.confidence_modifier("uncommon") == "medium"
    assert lt.confidence_modifier("common") == "low"
    assert lt.confidence_modifier("ubiquitous") == "insufficient"


# ---------------------------------------------------------------------------
# Coordinator integration — ubiquitous IOC doesn't get a Finding; rare
# IOC carries the rarity_bucket fact in its evidence.
# ---------------------------------------------------------------------------

def test_coordinator_suppresses_ubiquitous_ioc(tmp_path, monkeypatch):
    """Emulate a cross-case lookup that returned a 51-prior-case IOC
    (ubiquitous). The coordinator should NOT insert a ledger row for it."""
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import list_findings, open_ledger
    from el.orchestrator.coordinator import Coordinator

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-long-tail-suppress")
    with open_ledger(m.case_dir):
        pass

    coord = Coordinator()
    ctx = AgentContext(case_id="t-long-tail-suppress",
                       case_dir=m.case_dir, input_path=src,
                       manifest=m.__dict__)
    # Ubiquitous = 51 distinct prior cases
    prior = {"8.8.8.8": [{"case_id": f"c{i}",
                           "ioc_type": "ipv4",
                           "observed_utc": "2024-01-01T00:00:00",
                           "agent": "x"}
                          for i in range(51)]}
    coord._emit_cross_case_findings(ctx, prior, {})

    findings = list_findings(m.case_dir, case_id=ctx.case_id)
    assert not any("8.8.8.8" in f.claim for f in findings), \
        "ubiquitous IOC should have been suppressed"


def test_coordinator_emits_rare_ioc_with_bucket(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import list_findings, open_ledger
    from el.orchestrator.coordinator import Coordinator

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-long-tail-rare")
    with open_ledger(m.case_dir):
        pass

    coord = Coordinator()
    ctx = AgentContext(case_id="t-long-tail-rare",
                       case_dir=m.case_dir, input_path=src,
                       manifest=m.__dict__)
    prior = {"attacker.example.com": [{"case_id": "prev-apt-case",
                                         "ioc_type": "domain",
                                         "observed_utc": "2024-01-01T00:00:00",
                                         "agent": "x"}]}
    coord._emit_cross_case_findings(ctx, prior, {})

    findings = list_findings(m.case_dir, case_id=ctx.case_id)
    matched = [f for f in findings if "attacker.example.com" in f.claim]
    assert matched, "rare IOC finding should have been emitted"
    assert "[rare]" in matched[0].claim
    assert matched[0].evidence[0].extracted_facts.get("rarity_bucket") == "rare"
