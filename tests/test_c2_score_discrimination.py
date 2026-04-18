"""Three regression tests captured from the 265-case corpus stress test:
all cases were saturating at H_C2_BEACONING +4 because (1) generic 'tcp'/'udp'
keywords lifted C2, (2) Correlator's 'top destination IP' finding falsely
tagged H_C2_OR_REVERSE_SHELL, (3) knowledge_lookup findings were leaking into
ACH scoring via keyword matches on their claim text."""
from el.intel.ach import score_findings
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def test_generic_tcp_udp_in_claim_does_not_lift_c2():
    """The network_analyst's 'Parsed N packets across N TCP flows' claim
    should NOT lift H_C2_BEACONING. Only explicit C2-shaped findings should."""
    f = Finding(case_id="c", agent="network_analyst", confidence="high",
                claim="Parsed 9448 packets across 92 unique flows; 3 DNS query name(s)",
                evidence=[_ev()],
                hypotheses_supported=["H_NETWORK_TRAFFIC_OBSERVED"])
    ranked, _ = score_findings([f])
    c2 = next(r for r in ranked if r.hyp_id == "H_C2_BEACONING")
    assert c2.score == 0


def test_explicit_suspicious_port_finding_does_lift_c2():
    """A genuine suspicious-port finding should still drive H_C2_BEACONING."""
    f = Finding(case_id="c", agent="network_analyst", confidence="medium",
                claim="Connections observed to suspicious destination ports: {4444:1}",
                evidence=[_ev()],
                hypotheses_supported=["H_C2_OR_REVERSE_SHELL"])
    ranked, _ = score_findings([f])
    c2 = next(r for r in ranked if r.hyp_id == "H_C2_BEACONING")
    assert c2.score >= 3


def test_knowledge_lookup_findings_excluded_from_ach():
    """Tier 3 cross-case overlap is suggestive only — must NOT score any
    hypothesis even if its claim text matches keyword patterns."""
    f = Finding(case_id="c", agent="knowledge_lookup", confidence="low",
                claim="Cross-case overlap: ipv4 8.8.8.8 previously observed in case(s) "
                      "pcap-2020-trickbot. Suggestive only — beacon tcp connection.",
                evidence=[_ev()])
    ranked, fmut = score_findings([f])
    assert fmut[0].ach_score_delta == {}
    assert all(r.score == 0 for r in ranked)
