"""Contract tests for anti-forensics as a cross-cutting MODIFIER.

Per the investigative principle the operator stated: anti-forensic
indicators are a contextual variable in the likelihood calculation —
they help weigh how much to trust the ABSENCE of standard artifacts,
rather than competing as a motive. Before this change H_ANTI_FORENSICS
(and the shadow-copy / ADS family) kept *winning* the ACH on real
cases (LoneWolf, rocba, SRL-2018) because clean-up generates dozens of
high-confidence findings — but "the operator scrubbed evidence" is a
HOW, not a WHY.

Locks in:
  * Modifier hypotheses never appear in the ranked leader list
  * A real motive leads even when anti-forensic findings vastly
    outnumber it
  * anti_forensic_context() reports the index + per-indicator break
  * The benign/null hypothesis is discounted when tampering is present
  * No anti-forensic signal → context is None, no discount
"""
from __future__ import annotations

from el.intel.ach import (
    anti_forensic_context,
    score_findings,
    _benign_discount,
)
from el.intel.hypotheses import MODIFIER_IDS, BENIGN_ID
from el.schemas.finding import EvidenceItem, Finding


def _f(claim, supports, conf="high"):
    ev = EvidenceItem(tool="t", version="0", command="c",
                      output_sha256="0"*64, output_path="/x")
    return Finding(case_id="c", agent="a", confidence=conf, claim=claim,
                   evidence=[ev], hypotheses_supported=supports)


def test_modifiers_excluded_from_ranked():
    """None of the modifier ids may appear in the ranked competing list."""
    findings = [
        _f("VSS diff: Security.evtx deleted_in_live", ["H_SHADOW_COPY_ARTIFACT_DELETED", "H_ANTI_FORENSICS"]),
        _f("Disk anomaly [NTFS_ALTERNATE_DATA_STREAM]", ["H_NTFS_ADS_PRESENT"]),
        _f("timestomping detected", ["H_ANTI_FORENSICS"]),
    ]
    ranked, _ = score_findings(findings)
    ranked_ids = {r.hyp_id for r in ranked}
    assert ranked_ids.isdisjoint(MODIFIER_IDS), (
        f"modifier hypotheses leaked into ranked: "
        f"{ranked_ids & MODIFIER_IDS}")


def test_real_motive_leads_despite_many_anti_forensic_findings():
    """The SRL-2018 shape: a pile of anti-forensic findings + a smaller
    number of espionage-shaped findings. The motive (espionage) must
    lead the ranking, NOT anti-forensics."""
    findings = []
    # 30 anti-forensic findings (what used to dominate)
    for i in range(30):
        findings.append(_f(f"VSS diff {i}: deleted_in_live",
                            ["H_SHADOW_COPY_ARTIFACT_DELETED", "H_ANTI_FORENSICS"]))
    # 3 espionage findings
    for i in range(3):
        findings.append(_f(f"C2 beacon to external IP {i}",
                            ["H_APT_ESPIONAGE"]))
    ranked, _ = score_findings(findings)
    leader = ranked[0]
    assert leader.hyp_id == "H_APT_ESPIONAGE", (
        f"a real motive must lead, not anti-forensics; got {leader.hyp_id}")


def test_anti_forensic_context_reports_index_and_indicators():
    findings = [
        _f("VSS diff: Security.evtx deleted_in_live",
           ["H_SHADOW_COPY_ARTIFACT_DELETED", "H_ANTI_FORENSICS"]),
        _f("timestomping + zero-size system binary", ["H_ANTI_FORENSICS"]),
    ]
    ctx = anti_forensic_context(findings)
    assert ctx is not None
    assert ctx["index"] > 0
    assert ctx["benign_discount"] == _benign_discount(ctx["index"])
    ids = {i["hyp_id"] for i in ctx["indicators"]}
    assert "H_ANTI_FORENSICS" in ids
    assert ctx["contributing_finding_ids"]


def test_benign_discounted_when_tampering_present():
    """A 'no malicious activity' finding lifts benign; concurrent
    anti-forensic findings must claw that back — absence of artifacts
    on a scrubbed host is not innocence."""
    clean = _f("no non-baseline items observed; all signatures verified",
                [])
    tamper = [_f(f"VSS diff {i}: deleted_in_live",
                 ["H_SHADOW_COPY_ARTIFACT_DELETED", "H_ANTI_FORENSICS"])
              for i in range(10)]
    # Benign score WITHOUT tampering
    ranked_clean, _ = score_findings([clean])
    benign_alone = next(r.score for r in ranked_clean if r.hyp_id == BENIGN_ID)
    # Benign score WITH tampering present
    ranked_both, _ = score_findings([clean] + tamper)
    benign_discounted = next(r.score for r in ranked_both if r.hyp_id == BENIGN_ID)
    assert benign_discounted < benign_alone, (
        "benign must be discounted when anti-forensic tampering is present")


def test_no_anti_forensic_signal_means_no_context_no_discount():
    findings = [_f("C2 beacon to external IP", ["H_APT_ESPIONAGE"]),
                _f("no non-baseline items observed", [])]
    assert anti_forensic_context(findings) is None
    # Benign not discounted
    ranked, _ = score_findings(findings)
    benign = next(r.score for r in ranked if r.hyp_id == BENIGN_ID)
    ranked_solo, _ = score_findings([_f("no non-baseline items observed", [])])
    benign_solo = next(r.score for r in ranked_solo if r.hyp_id == BENIGN_ID)
    assert benign == benign_solo


def test_benign_discount_is_capped():
    """A pathological pile of tampering findings can't drive the
    benign discount unbounded — capped per _benign_discount."""
    from el.intel.ach import _BENIGN_DISCOUNT_CAP
    assert _benign_discount(2) == 1
    assert _benign_discount(1000) == _BENIGN_DISCOUNT_CAP
    assert _benign_discount(0) == 0
    assert _benign_discount(-5) == 0
