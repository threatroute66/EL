"""Regression test from a real DC memory image (case dc-03): when most
findings are 'insufficient' (Vol3 symbol mismatch on this Windows version),
the failure-message text must NOT score against any hypothesis. Otherwise
'netscan blocked by symbol mismatch' falsely lifts H_C2_BEACONING via
keyword match on 'netscan'."""
from el.intel.ach import score_findings
from el.intel.hypotheses import HYPOTHESES
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def test_insufficient_finding_does_not_score_any_hypothesis():
    f = Finding(case_id="c", agent="memory_forensicator", confidence="insufficient",
                claim="windows.netscan.NetScan blocked by Vol3 symbol mismatch — "
                      "tcpip.sys PDB not in cache. udp tcp connection.")
    ranked, mutated = score_findings([f])
    assert all(r.score == 0 for r in ranked)
    assert mutated[0].ach_score_delta == {}


def test_insufficient_excluded_but_grounded_findings_still_score():
    f1 = Finding(case_id="c", agent="x", confidence="insufficient",
                 claim="vol3 unavailable: netscan netstat")
    f2 = Finding(case_id="c", agent="memory_forensicator", confidence="high",
                 claim="malfind flagged a region in lsass.exe", evidence=[_ev()],
                 hypotheses_supported=["H_PROCESS_INJECTION"])
    ranked, _ = score_findings([f1, f2])
    leader = ranked[0]
    assert leader.hyp_id == "H_APT_ESPIONAGE"
    assert leader.score > 0
    benign = next(r for r in ranked if r.hyp_id == "H_BENIGN_NO_INCIDENT")
    assert benign.score < 0
