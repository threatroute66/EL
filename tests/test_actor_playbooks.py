"""APT actor-playbook fingerprinting.

Tests:
  - seed library is well-formed (canonical T-IDs, non-empty)
  - score_against_case is deterministic + monotonic
  - sub-technique tolerance: observed T1003.001 satisfies a
    playbook listing T1003 (and vice versa)
  - score_findings extracts observed T-IDs from a fabricated
    ledger correctly
  - ranking honours coverage × sqrt(|matched|)
"""
import re

import pytest

from el.intel import actor_playbooks as ap
from el.schemas.finding import EvidenceItem, Finding


_TID_RE = re.compile(r"^T\d{4}(\.\d+)?$")


def _ev(techs: list[str]) -> EvidenceItem:
    return EvidenceItem(
        tool="x", version="1", command="x",
        output_sha256="ab" * 32, output_path="/tmp/x",
        extracted_facts={"attack_techniques": techs},
    )


def _f(techs: list[str]) -> Finding:
    return Finding(
        case_id="c", agent="x", claim="t", confidence="medium",
        evidence=[_ev(techs)])


# --- seed library hygiene ----------------------------------------------

def test_playbook_library_non_empty():
    assert len(ap.PLAYBOOKS) >= 6


def test_each_playbook_has_canonical_fields():
    for pb in ap.PLAYBOOKS:
        assert pb.actor, "actor name required"
        assert pb.techniques, f"{pb.actor}: technique list empty"
        assert pb.references, f"{pb.actor}: references empty"
        for t in pb.techniques:
            assert _TID_RE.match(t), (
                f"{pb.actor}: malformed T-ID {t!r}")


def test_by_actor_lookup():
    idx = ap.by_actor()
    assert "FIN7" in idx
    assert "Lazarus" in idx
    assert idx["APT29"].actor == "APT29"


# --- scoring -----------------------------------------------------------

def test_empty_observed_returns_no_matches():
    assert ap.score_against_case([]) == []


def test_full_match_yields_coverage_one():
    fin7 = ap.by_actor()["FIN7"]
    matches = ap.score_against_case(fin7.techniques)
    top = matches[0]
    assert top.actor == "FIN7"
    assert top.coverage == 1.0
    assert top.missing == ()
    assert sorted(top.matched) == sorted(fin7.techniques)


def test_partial_match_below_full_above_zero():
    fin7 = ap.by_actor()["FIN7"]
    half = list(fin7.techniques)[: len(fin7.techniques) // 2]
    matches = ap.score_against_case(half)
    top = next(m for m in matches if m.actor == "FIN7")
    assert 0 < top.coverage < 1
    assert len(top.matched) == len(half)
    assert len(top.missing) == len(fin7.techniques) - len(half)


def test_no_overlap_yields_no_match():
    """Techniques completely disjoint from any seed playbook
    produce zero matches."""
    matches = ap.score_against_case(["T9999.999", "T8888"])
    assert matches == []


def test_subtechnique_tolerance_observed_satisfies_parent():
    """Lazarus playbook lists ``T1003`` (parent OS Credential
    Dumping). An observed sub-technique ``T1003.001`` should
    count toward that playbook."""
    matches = ap.score_against_case(["T1003.001"])
    laz = next((m for m in matches if m.actor == "Lazarus"), None)
    assert laz is not None
    assert "T1003" in laz.matched


def test_parent_tolerance_observed_parent_satisfies_subtechnique():
    """APT28's playbook lists ``T1003.003`` (NTDS); observing the
    parent ``T1003`` should still credit a partial match."""
    matches = ap.score_against_case(["T1003"])
    apt28 = next((m for m in matches if m.actor == "APT28"), None)
    assert apt28 is not None
    assert "T1003.003" in apt28.matched


def test_min_coverage_filter():
    """min_coverage=0.5 drops matches with <50% playbook coverage."""
    matches = ap.score_against_case(
        ["T1003.001"], min_coverage=0.5)
    # Single technique is unlikely to give 50% on any seed playbook
    # (smallest playbook has 6 techniques)
    assert all(m.coverage >= 0.5 for m in matches)


def test_min_matched_filter():
    matches = ap.score_against_case(
        ["T1059.001"], min_matched=2)
    # Exactly one observed technique → no match should pass min=2
    assert matches == []


def test_score_ranks_by_breadth_x_depth():
    """A 5/8 playbook match outranks a 1/4 playbook match because
    score = coverage × sqrt(|matched|) rewards both axes."""
    fin7 = ap.by_actor()["FIN7"]
    salty = ap.by_actor()["SaltTyphoon"]
    # Five FIN7 techniques + one SaltTyphoon technique
    observed = list(fin7.techniques[:5]) + [salty.techniques[0]]
    matches = ap.score_against_case(observed)
    actors = [m.actor for m in matches]
    assert actors[0] == "FIN7"


def test_normalize_tid_handles_lowercase():
    matches = ap.score_against_case(["t1003.001", "t1059.001"])
    laz = next(m for m in matches if m.actor == "Lazarus")
    assert "T1003" in laz.matched


# --- score_findings glue ----------------------------------------------

def test_score_findings_extracts_string_tids():
    findings = [_f(["T1059.001", "T1003.001"]),
                _f(["T1547.001"])]
    matches = ap.score_findings(findings)
    laz = next((m for m in matches if m.actor == "Lazarus"), None)
    assert laz is not None
    assert "T1059.001" in laz.matched
    assert "T1003" in laz.matched              # parent tolerance


def test_score_findings_extracts_tuple_tids():
    """Some detectors emit ``[(tid, name), ...]`` tuples in
    extracted_facts['attack_techniques']."""
    f = Finding(case_id="c", agent="x", claim="t",
                confidence="medium",
                evidence=[EvidenceItem(
                    tool="x", version="1", command="x",
                    output_sha256="ab" * 32,
                    output_path="/tmp/x",
                    extracted_facts={
                        "attack_techniques": [
                            ["T1059.001", "PowerShell"],
                            ("T1003.001", "LSASS")]})])
    matches = ap.score_findings([f])
    assert any("T1059.001" in m.matched for m in matches)


def test_score_findings_no_techniques_gives_no_matches():
    f = Finding(case_id="c", agent="x", claim="t",
                confidence="medium",
                evidence=[EvidenceItem(
                    tool="x", version="1", command="x",
                    output_sha256="ab" * 32,
                    output_path="/tmp/x")])
    assert ap.score_findings([f]) == []


# --- end-to-end: a real-shape FIN7 case ranks FIN7 first --------------

def test_fin7_shaped_case_ranks_fin7_first():
    """Construct a case observing the FIN7 kill-chain. FIN7 should
    be the top-ranked actor; other actors with overlapping
    techniques (T1003.001, T1021.002 etc.) may also match but at
    lower scores."""
    findings = [
        _f(["T1566.001", "T1204.002"]),    # Initial access + execution
        _f(["T1059.005", "T1218.005"]),    # VBA + mshta
        _f(["T1055"]),                      # Carbanak DLL injection
        _f(["T1003.001"]),                  # LSASS
        _f(["T1021.002"]),                  # SMB lateral
        _f(["T1486"]),                      # Encrypt impact
    ]
    matches = ap.score_findings(findings)
    assert matches, "expected at least one playbook match"
    assert matches[0].actor == "FIN7"
    assert matches[0].coverage >= 0.8       # 7/8 of FIN7's chain


def test_apt28_shaped_case_ranks_apt28_first():
    findings = [
        _f(["T1566.001", "T1204.002"]),
        _f(["T1547.001"]),
        _f(["T1059.003"]),
        _f(["T1003.003"]),
        _f(["T1071.001"]),
    ]
    matches = ap.score_findings(findings)
    assert matches[0].actor == "APT28"
