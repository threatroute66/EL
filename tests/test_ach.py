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


def test_only_insufficient_findings_lift_benign():
    f = Finding(case_id="c", agent="t", confidence="insufficient",
                claim="vol3 unavailable")
    ranked, _ = score_findings([f])
    benign = next(r for r in ranked if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    assert benign.score >= 1


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
