"""Phase 0 contract tests for el.reporting.glossary.

The glossary is the single source of plain-English translations for
DFIR jargon that surfaces in the executive (non-expert) report tier.
These tests lock in the contract:

  - Known tokens (T-IDs, hypothesis tags, anomaly codes, lateral-movement
    codes, common DFIR terms) translate to non-empty plain text
  - Missing tokens fall through to the original token (renderer never
    invents translations)
  - entries_used() finds every glossary term in a passage of prose, so
    the executive report's appendix is complete
"""
import pytest

from el.reporting import glossary


# --- known tokens translate -------------------------------------------------

@pytest.mark.parametrize("term", [
    "H_INSIDER_EMAIL_EXFIL",
    "H_APT_ESPIONAGE",
    "H_ANTI_FORENSICS",
    "T1003.001",
    "T1566.002",
    "MACB_TIMESTOMP_SKEW",
    "LSASS_OUTSIDE_SYSTEM32",
    "ps_remoting/inbound_pssession",
    "wmi/event_consumer_registration",
    "EVTX",
    "Prefetch",
    "iLEAPP",
])
def test_known_terms_have_translations(term):
    plain = glossary.translate(term)
    expl = glossary.explain(term)
    entry = glossary.lookup(term)
    assert plain != term, f"{term} should translate to plain English"
    assert plain and expl
    assert entry is not None
    assert entry.term == term


# --- missing tokens fall through -------------------------------------------

def test_unknown_term_falls_through():
    """The renderer must not invent translations. An unknown token
    is returned verbatim so an analyst sees that a glossary entry is
    missing rather than a fabricated definition."""
    assert glossary.translate("T9999.999") == "T9999.999"
    assert glossary.explain("H_NONEXISTENT_HYPOTHESIS") is None
    assert glossary.lookup("UNKNOWN_PATTERN") is None


# --- entries_used scans rendered text --------------------------------------

def test_entries_used_finds_terms_in_prose():
    """Simulates the exec renderer scanning a finished narrative for
    glossary-eligible terms before emitting the appendix."""
    sample = (
        "The leading hypothesis is H_INSIDER_EMAIL_EXFIL, supported by "
        "T1534 (internal spearphishing) and corroborated by EVTX records "
        "and Prefetch artifacts. A MACB_TIMESTOMP_SKEW anomaly was also "
        "flagged."
    )
    used = glossary.entries_used(sample)
    used_terms = {e.term for e in used}
    assert "H_INSIDER_EMAIL_EXFIL" in used_terms
    assert "T1534" in used_terms
    assert "EVTX" in used_terms
    assert "Prefetch" in used_terms
    assert "MACB_TIMESTOMP_SKEW" in used_terms


def test_entries_used_dedupes_repeated_terms():
    sample = "EVTX EVTX EVTX records"
    used = glossary.entries_used(sample)
    assert len(used) == 1
    assert used[0].term == "EVTX"


def test_entries_used_empty_text_returns_empty():
    assert glossary.entries_used("") == []
    assert glossary.entries_used("no jargon here") == []


def test_all_entries_nonempty():
    """Smoke test: at least every category we built has entries."""
    entries = glossary.all_entries()
    terms = {e.term for e in entries}
    # one representative term per category we registered
    for sentinel in (
        "H_RANSOMWARE",            # hypothesis
        "T1003",                   # ATT&CK
        "MACB_TIMESTOMP_SKEW",     # disk anomaly
        "ps_remoting/inbound_pssession",  # lateral
        "EVTX",                    # bare DFIR term
    ):
        assert sentinel in terms, f"missing category sentinel: {sentinel}"
    # every entry has non-empty plain + explanation
    for e in entries:
        assert e.plain.strip()
        assert e.explanation.strip()
