from el.intel.attack_map import map_case, map_finding
from el.schemas.finding import EvidenceItem, Finding, RedReview


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def test_hypothesis_maps_to_techniques():
    f = Finding(case_id="c", agent="memory", confidence="high",
                claim="malfind flagged 1 region(s)", evidence=[_ev()],
                hypotheses_supported=["H_PROCESS_INJECTION"])
    pairs = map_finding(f)
    assert ("T1055", "Process Injection") in pairs


def test_pattern_map_picks_up_lolbins():
    f = Finding(case_id="c", agent="memory", confidence="high",
                claim="rundll32.exe spawned by winword.exe", evidence=[_ev()])
    pairs = map_finding(f)
    tids = {tid for tid, _ in pairs}
    assert "T1218.011" in tids


def test_rule_id_in_red_review_notes_maps():
    f = Finding(case_id="c", agent="memory", confidence="high",
                claim="some unrelated text", evidence=[_ev()])
    f.red_review = RedReview(status="challenged",
                             challenger_notes="rule: [MALFIND_JIT_FALSE_POSITIVE] note text")
    pairs = map_finding(f)
    tids = {tid for tid, _ in pairs}
    assert "T1055" in tids


def test_map_case_aggregates_finding_ids():
    f1 = Finding(case_id="c", agent="m", confidence="high", claim="powershell.exe", evidence=[_ev()])
    f2 = Finding(case_id="c", agent="m", confidence="high", claim="powershell.exe again", evidence=[_ev()])
    agg = map_case([f1, f2])
    assert "T1059.001" in agg
    assert sorted(agg["T1059.001"]["evidence_finding_ids"]) == sorted([f1.finding_id, f2.finding_id])


def test_unmapped_returns_empty():
    f = Finding(case_id="c", agent="m", confidence="high",
                claim="completely benign-looking unmapped claim", evidence=[_ev()])
    assert map_finding(f) == []
