"""Contract tests for H_ILLICIT_ENTERPRISE.

The 2019 Narcos corpus exposed the gap: EL's hypotheses are
intrusion-centric, but Narcos is a criminal-enterprise scenario —
the devices are the subjects' own, not intrusion victims. Drug-trade
findings were mis-tagged H_INSIDER_DATA_EXFIL / H_OPPORTUNISTIC_
COMMODITY, so the case landed on a weak espionage lead with the
purpose-built narcotic detector unrepresented in the ranking.

H_ILLICIT_ENTERPRISE is the motive that fits. Locks in:
  * narcotic-lexicon evidence (tool el.narcotic_lexicon) lifts it +3
  * crypto-in-user-data (category btc_wallet) corroborates +1
  * darknet-marketplace language fires even on untagged findings +2
  * generic intrusion findings do NOT lift it
  * the benign/null hypothesis is refuted by it
  * it can LEAD on a Narcos-shaped finding set
"""
from __future__ import annotations

from el.intel.ach import score_findings
from el.intel.hypotheses import by_id
from el.schemas.finding import EvidenceItem, Finding


def _ev(tool="t", category=None):
    facts = {"category": category} if category else {}
    return EvidenceItem(tool=tool, version="0", command="c",
                        output_sha256="0"*64, output_path="/x",
                        extracted_facts=facts)


def _f(claim, supports=None, evidence=None, conf="medium"):
    return Finding(case_id="c", agent="a", confidence=conf, claim=claim,
                   evidence=evidence or [_ev()],
                   hypotheses_supported=supports or [])


def _score(f):
    return by_id()  # not used directly; helper below


def _illicit_score(findings):
    ranked, _ = score_findings(findings)
    row = next((r for r in ranked if r.hyp_id == "H_ILLICIT_ENTERPRISE"), None)
    return row.score if row else 0


# ---------------------------------------------------------------------------
# Lift signals
# ---------------------------------------------------------------------------

def test_narcotic_lexicon_lifts_plus_3():
    """A narcotic-lexicon finding (evidence tool el.narcotic_lexicon,
    tagged H_ILLICIT_ENTERPRISE) lifts the hypothesis +3 — the
    purpose-built drug-trade detector is the load-bearing signal."""
    f = _f("Narcotic-lexicon match in notes.txt: 4 strain term(s), "
           "2 weight marker(s), 3 price pattern(s).",
           supports=["H_ILLICIT_ENTERPRISE"],
           evidence=[_ev(tool="el.narcotic_lexicon")])
    assert _illicit_score([f]) == 3


def test_btc_wallet_corroborates_plus_1():
    """Cryptocurrency in user data (category btc_wallet) is a weaker
    corroborator — +1, not +3 — because crypto is dual-use."""
    f = _f("Browser history → BTC wallet address(es): 5 URL(s).",
           supports=["H_ILLICIT_ENTERPRISE"],
           evidence=[_ev(category="btc_wallet")])
    assert _illicit_score([f]) == 1


def test_darknet_language_fires_on_untagged_finding():
    """Explicit darknet-marketplace / money-laundering language is
    diagnostic on its own (untagged path, +2)."""
    f = _f("Browser history shows repeated visits to an AlphaBay "
           "darknet market vendor page.")
    assert _illicit_score([f]) == 2


def test_generic_illicit_tag_without_category_scores_2():
    f = _f("Contraband marketplace listing recovered.",
           supports=["H_ILLICIT_ENTERPRISE"],
           evidence=[_ev(tool="el.something_else")])
    assert _illicit_score([f]) == 2


# ---------------------------------------------------------------------------
# Negatives — must NOT lift on intrusion signal
# ---------------------------------------------------------------------------

def test_generic_intrusion_finding_does_not_lift():
    """Process injection / credential dumping (the signals that made
    Narcos land weakly on espionage) must NOT lift illicit-enterprise."""
    findings = [
        _f("Sensitive-import signature in PE: credential_dump",
           supports=["H_APT_ESPIONAGE", "H_CREDENTIAL_ACCESS"]),
        _f("Lateral movement [psexec/service_install]",
           supports=["H_LATERAL_MOVEMENT"]),
    ]
    assert _illicit_score(findings) == 0


def test_news_article_drug_mention_does_not_lift():
    """A passing 'drug' mention without the guarded marketplace /
    lexicon signal must not lift the hypothesis (FP guard)."""
    f = _f("Browser history: visited a news article about drug policy.")
    assert _illicit_score([f]) == 0


# ---------------------------------------------------------------------------
# Benign refutation + leadership
# ---------------------------------------------------------------------------

def test_benign_refuted_by_illicit_enterprise():
    clean = _f("no non-baseline items observed; all signatures verified",
                conf="high")
    benign_alone, _ = score_findings([clean])
    b0 = next(r.score for r in benign_alone if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    narco = _f("Narcotic-lexicon match in chat.txt: strains + prices.",
                supports=["H_ILLICIT_ENTERPRISE"],
                evidence=[_ev(tool="el.narcotic_lexicon")], conf="high")
    both, _ = score_findings([clean, narco])
    b1 = next(r.score for r in both if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    assert b1 < b0, "illicit-enterprise evidence must refute the null"


def test_illicit_enterprise_can_lead_on_narcos_shape():
    """A Narcos-shaped set (several narcotic-lexicon hits + crypto +
    some weak intrusion noise) must rank illicit-enterprise on top,
    not espionage."""
    findings = []
    for i in range(4):
        findings.append(_f(f"Narcotic-lexicon match in file{i}.txt",
                            supports=["H_ILLICIT_ENTERPRISE"],
                            evidence=[_ev(tool="el.narcotic_lexicon")]))
    findings.append(_f("Browser history → BTC wallet address(es)",
                       supports=["H_ILLICIT_ENTERPRISE"],
                       evidence=[_ev(category="btc_wallet")]))
    # weak intrusion noise (what used to win)
    findings.append(_f("Sensitive-import signature in PE",
                       supports=["H_APT_ESPIONAGE"]))
    ranked, _ = score_findings(findings)
    assert ranked[0].hyp_id == "H_ILLICIT_ENTERPRISE", (
        f"illicit-enterprise should lead on a Narcos-shaped set; "
        f"got {ranked[0].hyp_id}")
