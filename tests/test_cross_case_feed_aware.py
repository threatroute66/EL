"""The cross-case finding emitter distinguishes feed-sourced priors
from real EL-case priors.

Feed pulls land in knowledge.sqlite under
``case_id='feed:misp:<server>'`` / ``feed:taxii:<collection>'``.
``lookup_iocs`` already filters them in (case_id != current_case_id),
so without intervention they'd surface as fake cross-case overlap
("previously observed in 1 case(s): feed:misp:..."). The wire-up
splits feed cases out of the real-case count and rewords the claim
so reports read accurately.
"""
import json
from pathlib import Path

import pytest

from el import knowledge as kb
from el.evidence import intake as intake_mod
from el.evidence.ledger import list_findings, open_ledger


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    return tmp_path


def _make_case(isolated, cid):
    src = isolated / f"{cid}.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=cid)
    with open_ledger(m.case_dir):
        pass
    return m


def _emit_lookup_findings(case_dir, case_id, prior):
    """Direct entry into Coordinator._emit_cross_case_findings — we
    don't need a full investigate() run, just the ledger write."""
    from el.agents.base import AgentContext
    from el.orchestrator.coordinator import Coordinator
    ctx = AgentContext(case_id=case_id, case_dir=case_dir,
                        input_path=case_dir / "x.bin",
                        manifest={})
    Coordinator()._emit_cross_case_findings(ctx, prior, ioc_sets={})


def test_feed_only_prior_renders_external_feed_match(isolated):
    """Only a MISP-feed observation exists for this IOC — claim must
    say 'External-feed match' and name the feed source rather than
    pretending it's another case."""
    kb.record_iocs("feed:misp:https://misp.example.org",
                   "threat_feeds",
                   {"ipv4": ["203.0.113.42"]})
    m = _make_case(isolated, "case-X")
    prior = kb.lookup_iocs(["203.0.113.42"], current_case_id="case-X")
    _emit_lookup_findings(Path(m.case_dir), "case-X", prior)
    findings = list_findings(Path(m.case_dir), case_id="case-X")
    cross = [f for f in findings if f.agent == "knowledge_lookup"]
    assert cross, "expected a feed-derived knowledge_lookup finding"
    f = cross[0]
    assert "External-feed match" in f.claim
    assert "misp.example.org" in f.claim
    assert f.confidence == "low"
    # Evidence facts split feed sources from real cases
    facts = f.evidence[0].extracted_facts
    assert facts["external_feed_sources"]
    assert facts["previously_seen_in_cases"] == []
    # Admiralty drops to C2 for feed-only priors
    assert f.evidence[0].source_reliability == "C"
    assert f.evidence[0].info_credibility == "2"


def test_real_case_prior_renders_cross_case_overlap(isolated):
    """A real EL case observed the IOC — claim text stays the
    classic 'Cross-case overlap' shape, no feed contamination."""
    kb.record_iocs("real-case-A", "memory_forensicator",
                   {"ipv4": ["198.51.100.5"]})
    m = _make_case(isolated, "case-Y")
    prior = kb.lookup_iocs(["198.51.100.5"], current_case_id="case-Y")
    _emit_lookup_findings(Path(m.case_dir), "case-Y", prior)
    findings = list_findings(Path(m.case_dir), case_id="case-Y")
    cross = [f for f in findings if f.agent == "knowledge_lookup"]
    assert cross
    f = cross[0]
    assert "Cross-case overlap" in f.claim
    assert "real-case-A" in f.claim
    assert "External" not in f.claim
    facts = f.evidence[0].extracted_facts
    assert facts["previously_seen_in_cases"] == ["real-case-A"]
    assert facts["external_feed_sources"] == []
    # Real-case prior keeps B2 (analyst-vetted)
    assert f.evidence[0].source_reliability == "B"


def test_hybrid_prior_real_and_feed_mentions_both(isolated):
    """Same IOC observed in BOTH a real case AND a feed pull. Claim
    leads with the real cross-case overlap (the stronger signal) but
    also notes the feed presence."""
    kb.record_iocs("real-case-Z", "network_analyst",
                   {"domain": ["evil.example"]})
    kb.record_iocs("feed:taxii:coll-1", "threat_feeds",
                   {"domain": ["evil.example"]})
    m = _make_case(isolated, "case-Q")
    prior = kb.lookup_iocs(["evil.example"], current_case_id="case-Q")
    _emit_lookup_findings(Path(m.case_dir), "case-Q", prior)
    findings = list_findings(Path(m.case_dir), case_id="case-Q")
    cross = [f for f in findings if f.agent == "knowledge_lookup"]
    assert cross
    f = cross[0]
    assert "Cross-case overlap" in f.claim
    assert "real-case-Z" in f.claim
    assert "external feed" in f.claim
    facts = f.evidence[0].extracted_facts
    assert facts["previously_seen_in_cases"] == ["real-case-Z"]
    assert facts["external_feed_sources"] == ["feed:taxii:coll-1"]
