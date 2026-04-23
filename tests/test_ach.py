from el.intel.ach import diagnostic_findings, score_findings
from el.intel.hypotheses import HYPOTHESES
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def test_c2_finding_lifts_c2_beaconing_above_benign():
    f = Finding(case_id="c", agent="net", confidence="medium",
                claim="Connections observed to suspicious destination ports: {4444:1}",
                evidence=[_ev()],
                hypotheses_supported=["H_C2_OR_REVERSE_SHELL"])
    ranked, _ = score_findings([f])
    leader = ranked[0]
    assert leader.hyp_id == "H_C2_BEACONING"
    benign = next(r for r in ranked if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    assert benign.score < leader.score


def test_insufficient_findings_do_not_lift_benign():
    """'We couldn't analyze it' is not the same as 'it's clean'.
    Insufficient evidence must be NEUTRAL to all hypotheses, including benign.
    Otherwise a tool-failure cascade falsely concludes the host is clean."""
    f = Finding(case_id="c", agent="t", confidence="insufficient",
                claim="vol3 unavailable")
    ranked, _ = score_findings([f])
    benign = next(r for r in ranked if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    assert benign.score == 0


def test_explicit_baseline_match_lifts_benign():
    """Memory Baseliner reporting zero non-baseline items IS positive
    evidence the host is clean — that should lift benign."""
    from el.schemas.finding import EvidenceItem
    ev = EvidenceItem(tool="memory-baseliner", version="present", command="x",
                      output_sha256="0"*64, output_path="/tmp/x")
    f = Finding(case_id="c", agent="memory_forensicator", confidence="high",
                claim="Baseline comparison (proc): no non-baseline items observed",
                evidence=[ev])
    ranked, _ = score_findings([f])
    benign = next(r for r in ranked if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    assert benign.score > 0


def test_ach_score_delta_populated_on_findings():
    f = Finding(case_id="c", agent="m", confidence="high",
                claim="malfind flagged a region",
                evidence=[_ev()],
                hypotheses_supported=["H_PROCESS_INJECTION"])
    score_findings([f])
    assert f.ach_score_delta.get("H_APT_ESPIONAGE", 0) > 0
    assert f.ach_score_delta.get("H_BENIGN_NO_INCIDENT", 0) < 0


def test_ransomware_keywords_dominate():
    f = Finding(case_id="c", agent="m", confidence="high",
                claim="vssadmin delete shadows /all observed; .lock extension files",
                evidence=[_ev()])
    ranked, _ = score_findings([f])
    assert ranked[0].hyp_id == "H_RANSOMWARE"


def test_diagnostic_ranking_picks_highest_variance():
    apt_finding = Finding(case_id="c", agent="m", confidence="high",
                          claim="malfind in lsass.exe — process injection",
                          evidence=[_ev()],
                          hypotheses_supported=["H_PROCESS_INJECTION"])
    bland_finding = Finding(case_id="c", agent="m", confidence="low",
                            claim="some bland observation with no specific signal",
                            evidence=[_ev()])
    score_findings([apt_finding, bland_finding])
    diag = diagnostic_findings([apt_finding, bland_finding], top_n=1)
    assert diag[0].finding_id == apt_finding.finding_id


def test_hypothesis_library_has_minimum_three_with_null():
    ids = {h.hyp_id for h in HYPOTHESES}
    assert "H_BENIGN_NO_INCIDENT" in ids
    assert len(HYPOTHESES) >= 3


def test_scan_recon_outranks_c2_on_scan_probe_traffic():
    """Evidence shape from the /mnt/hgfs/pcaps three-days-of-scans corpus:
    HTTP_ERROR_HEAVY + HTTP_SCRIPTED_UA + suspicious-port fan-out. Without
    H_SCAN_RECON the ACH engine lifted H_C2_BEACONING on every scan pcap
    (4 of 4 in the final batch). H_SCAN_RECON should now dominate."""
    findings = [
        Finding(case_id="c", agent="network_analyst", confidence="medium",
                claim=("Network anomaly [HTTP_ERROR_HEAVY]: HTTP error rate 62% — "
                       "367 x 4xx, 0 x 5xx out of 595 responses. "
                       "Scan / discovery / broken C2 pattern."),
                evidence=[_ev()]),
        Finding(case_id="c", agent="network_analyst", confidence="medium",
                claim=("Network anomaly [HTTP_SCRIPTED_UA]: Scripted-client "
                       "User-Agent(s) observed: go-http-client=38, curl/=33, "
                       "python-requests/=17."),
                evidence=[_ev()]),
        Finding(case_id="c", agent="network_analyst", confidence="medium",
                claim=("Connections observed to suspicious destination ports: "
                       "{5555: 57, 9001: 47, 8888: 139}"),
                evidence=[_ev()]),
    ]
    ranked, _ = score_findings(findings)
    leader = ranked[0]
    scan = next(r for r in ranked if r.hyp_id == "H_SCAN_RECON")
    c2 = next(r for r in ranked if r.hyp_id == "H_C2_BEACONING")
    assert leader.hyp_id == "H_SCAN_RECON", (
        f"expected H_SCAN_RECON leader; got {leader.hyp_id} "
        f"(scan={scan.score}, c2={c2.score})")
    assert scan.score > c2.score
