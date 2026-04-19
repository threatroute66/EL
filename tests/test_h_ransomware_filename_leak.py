"""Regression: `_h_ransomware` must not score on filename labels leaked
through threat_hunter's YARA-sweep claim or triage's input-classification.

Observed in the pcap-corpus loop: 43/79 fresh cases had H_RANSOMWARE as
the leading hypothesis solely because the pcap filename contained the
word 'ransomware' (e.g. "2016-12-09-Locky-ransomware.pcap") and
threat_hunter's claim "YARA sweep of <filename>: N hit(s)" matched the
'ransom' substring.
"""
from el.intel.ach import score_findings
from el.intel.hypotheses import _h_ransomware
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def test_threat_hunter_filename_leak_does_not_lift_ransomware():
    """Realistic corpus claim — triggered the 43/79 FP batch."""
    f = Finding(
        case_id="c", agent="threat_hunter", confidence="high",
        claim="YARA sweep of 2016-12-09-Afraidgate-Rig-V-sends-Locky-ransomware.pcap: 7 hit(s) across 7 unique IOC rule(s)",
        evidence=[_ev()],
        hypotheses_supported=["H_IOC_CORROBORATED"],
    )
    assert _h_ransomware(f) == 0


def test_triage_filename_leak_also_excluded():
    f = Finding(
        case_id="c", agent="triage", confidence="high",
        claim="Input identified as pcap (libpcap) from magic bytes: 2017-...-ransomware.pcap",
        evidence=[_ev()],
        hypotheses_supported=[],
    )
    assert _h_ransomware(f) == 0


def test_real_ransomware_behavior_still_lifts():
    """vssadmin delete shadows from a real detection claim still scores."""
    f = Finding(
        case_id="c", agent="disk_forensicator", confidence="high",
        claim="Shadow-copy deletion trace: vssadmin delete shadows /all /quiet",
        evidence=[_ev()],
        hypotheses_supported=["H_RANSOMWARE"],
    )
    assert _h_ransomware(f) >= 3


def test_ransom_note_phrase_still_lifts():
    """Real ransom note content references still score — the fix only
    removed the bare 'ransom' substring (which matched 'ransomware' in
    filenames). Specific phrases still work."""
    f = Finding(
        case_id="c", agent="disk_anomaly", confidence="medium",
        claim="README.TXT ransom note observed in multiple user folders",
        evidence=[_ev()],
    )
    assert _h_ransomware(f) >= 3


def test_locky_extension_still_lifts():
    f = Finding(
        case_id="c", agent="disk_anomaly", confidence="medium",
        claim="Files with .locky extensions observed across 12 directories",
        evidence=[_ev()],
    )
    # `.lock` keyword matches `.locky`
    assert _h_ransomware(f) >= 3


def test_ach_ranking_no_longer_dominated_by_filename_leak():
    """End-to-end: a finding shaped like the batch FP (threat_hunter
    with filename containing 'ransomware') should NOT make H_RANSOMWARE
    the leading hypothesis."""
    f = Finding(
        case_id="c", agent="threat_hunter", confidence="high",
        claim="YARA sweep of 2017-cerber-ransomware-traffic.pcap: 2 hit(s)",
        evidence=[_ev()],
        hypotheses_supported=["H_IOC_CORROBORATED"],
    )
    ranked, _ = score_findings([f])
    by = {r.hyp_id: r.score for r in ranked}
    # Ransomware score is 0 now
    assert by["H_RANSOMWARE"] == 0


def test_crypto_in_filename_does_not_lift_via_cryptoshield():
    """Same class of FP — filename 'CryptoShield' should not match
    via substring 'encrypt' either (they don't overlap, but guard)."""
    f = Finding(
        case_id="c", agent="threat_hunter", confidence="high",
        claim="YARA sweep of 2017-02-28-EITest-Rig-EK-sends-CryptoShield-ransomware.pcap: 5 hit(s)",
        evidence=[_ev()],
    )
    assert _h_ransomware(f) == 0
