"""Admiralty-code source-reliability tags on EvidenceItem.

Closes the gap-doc Intel-depth bullet "Admiralty-code source-
reliability tags". Tests cover:
  - schema-level field validation (A-F + X for source, 1-6 + X for info)
  - tool→tier default lookup (court-vetted parsers vs heuristics
    vs feeds vs operator notes)
  - downgrade / best aggregation helpers
  - default values are "X X" so existing call sites validate
"""
import pytest
from pydantic import ValidationError

from el.intel import admiralty as ad
from el.schemas.finding import EvidenceItem, Finding


# --- tool tier mapping --------------------------------------------------

def test_court_vetted_parsers_default_to_a1():
    assert ad.for_tool("vol3") == ("A", "1")
    assert ad.for_tool("EvtxECmd") == ("A", "1")
    assert ad.for_tool("MFTECmd") == ("A", "1")
    assert ad.for_tool("plaso") == ("A", "1")
    assert ad.for_tool("regipy") == ("A", "1")


def test_heuristic_matchers_default_to_a2():
    assert ad.for_tool("yara") == ("A", "2")
    assert ad.for_tool("yara_hunt") == ("A", "2")
    assert ad.for_tool("diec") == ("A", "2")
    assert ad.for_tool("tlsh") == ("A", "2")


def test_log_scrapers_default_to_b2():
    assert ad.for_tool("iis_w3c") == ("B", "2")
    assert ad.for_tool("webserver_access") == ("B", "2")
    assert ad.for_tool("auditd") == ("B", "2")
    assert ad.for_tool("zeek") == ("B", "2")


def test_external_feeds_default_to_c2():
    assert ad.for_tool("misp") == ("C", "2")
    assert ad.for_tool("taxii") == ("C", "2")
    assert ad.for_tool("threat_feeds") == ("C", "2")


def test_operator_notes_default_to_f3():
    assert ad.for_tool("operator") == ("F", "3")
    assert ad.for_tool("manual") == ("F", "3")


def test_unknown_tool_returns_x_x():
    assert ad.for_tool("nonsense_xyz") == ("X", "X")
    assert ad.for_tool("") == ("X", "X")


def test_tool_lookup_strips_version_suffix():
    """vol3-2.20.0 / yara-4.5 / EvtxECmd-1.4.5 — version suffix
    stripped before lookup."""
    assert ad.for_tool("vol3-2.20.0") == ("A", "1")
    assert ad.for_tool("yara-4.5") == ("A", "2")


def test_tool_lookup_case_insensitive():
    assert ad.for_tool("Vol3") == ("A", "1")
    assert ad.for_tool("YARA") == ("A", "2")


def test_tool_lookup_strips_dot_exe():
    assert ad.for_tool("EvtxECmd.exe") == ("A", "1")


# --- helpers ------------------------------------------------------------

def test_is_valid():
    assert ad.is_valid("A", "1")
    assert ad.is_valid("F", "6")
    assert ad.is_valid("X", "X")
    assert not ad.is_valid("Z", "1")
    assert not ad.is_valid("A", "9")


def test_describe_human_readable():
    text = ad.describe("A", "1")
    assert text.startswith("A1")
    assert "Completely reliable" in text
    assert "Confirmed" in text
    text2 = ad.describe("X", "X")
    assert "Unset" in text2


def test_downgrade_steps_credibility():
    assert ad.downgrade(("A", "1")) == ("A", "2")
    assert ad.downgrade(("A", "1"), by=2) == ("A", "3")
    # Floor at 6
    assert ad.downgrade(("A", "5"), by=10) == ("A", "6")
    # Already-6 / X are no-ops
    assert ad.downgrade(("A", "6")) == ("A", "6")
    assert ad.downgrade(("A", "X")) == ("A", "X")


def test_best_picks_strongest():
    assert ad.best([("A", "1"), ("B", "2"), ("C", "3")]) == ("A", "1")
    assert ad.best([("B", "2"), ("A", "3")]) == ("A", "3")
    assert ad.best([("X", "X")]) == ("X", "X")
    assert ad.best([]) == ("X", "X")


def test_best_skips_invalid():
    assert ad.best([("Z", "1"), ("B", "2")]) == ("B", "2")


# --- EvidenceItem schema ------------------------------------------------

def _ev(**kw) -> EvidenceItem:
    base = dict(tool="vol3", version="2.20", command="vol3 ...",
                output_sha256="ab" * 32, output_path="/tmp/out.txt")
    base.update(kw)
    return EvidenceItem(**base)


def test_evidence_item_defaults_to_x_x():
    e = _ev()
    assert e.source_reliability == "X"
    assert e.info_credibility == "X"
    assert e.admiralty == "XX"


def test_evidence_item_accepts_admiralty_pair():
    e = _ev(source_reliability="A", info_credibility="1")
    assert e.admiralty == "A1"


def test_evidence_item_rejects_invalid_reliability():
    with pytest.raises(ValidationError):
        _ev(source_reliability="Z", info_credibility="1")


def test_evidence_item_rejects_invalid_credibility():
    with pytest.raises(ValidationError):
        _ev(source_reliability="A", info_credibility="9")


def test_finding_with_admiralty_evidence_validates():
    """Adding admiralty fields shouldn't break the existing
    high-confidence-needs-evidence contract."""
    f = Finding(
        case_id="c1", agent="memory_forensicator",
        claim="malfind detected RWX region in lsass",
        confidence="high",
        evidence=[_ev(source_reliability="A", info_credibility="1")],
    )
    assert f.evidence[0].admiralty == "A1"


def test_existing_evidence_still_valid_without_admiralty_kwargs():
    """Migration safety: code paths that don't set admiralty still
    construct a valid EvidenceItem (defaults handle it)."""
    f = Finding(
        case_id="c1", agent="x", claim="legacy", confidence="low",
        evidence=[_ev()],
    )
    assert f.evidence[0].source_reliability == "X"
