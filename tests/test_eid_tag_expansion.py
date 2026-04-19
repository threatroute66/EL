"""PR-P: Windows Event ID → hypothesis / ATT&CK mapping expansion.

Before PR-P, attack_map.py knew about 5 EIDs (4625/1102/4697/4698/4720)
and hypothesis scoring ignored all H_EID_* tags except via vague
claim-text matches. Hunt Evil + Windows Forensics poster catalog far
more event IDs that each point at a specific technique.

These tests lock in:
  1. Every newly-added H_EID_* tag resolves to ≥1 ATT&CK technique
  2. Scoring rules lift the right hypothesis when H_EID_* tags appear
  3. Log-clearing + WMI-subscription tags REFUTE H_BENIGN_NO_INCIDENT
"""
import pytest

from el.intel.ach import score_findings
from el.intel.attack_map import HYPOTHESIS_MAP, map_case
from el.schemas.finding import EvidenceItem, Finding


EID_TAGS_BY_CATEGORY = {
    # auth / logon
    "auth": ["H_EID_4624", "H_EID_4625", "H_EID_4634", "H_EID_4648",
             "H_EID_4672", "H_EID_4768", "H_EID_4769", "H_EID_4776"],
    # account management
    "account": ["H_EID_4720", "H_EID_4722", "H_EID_4725", "H_EID_4726",
                "H_EID_4728", "H_EID_4732", "H_EID_4740", "H_EID_4756"],
    # process execution
    "proc": ["H_EID_4688"],
    # scheduled tasks
    "task": ["H_EID_4698", "H_EID_4699", "H_EID_4700", "H_EID_4701", "H_EID_4702"],
    # services
    "service": ["H_EID_4697", "H_EID_7034", "H_EID_7035", "H_EID_7036",
                "H_EID_7040", "H_EID_7045"],
    # shares
    "share": ["H_EID_5140", "H_EID_5145"],
    # anti-forensic
    "antifor": ["H_EID_1102", "H_EID_104"],
    # PowerShell
    "ps": ["H_EID_4103", "H_EID_4104", "H_EID_400", "H_EID_403", "H_EID_800"],
    # WinRM
    "winrm": ["H_EID_91", "H_EID_168"],
    # WMI
    "wmi": ["H_EID_5857", "H_EID_5860", "H_EID_5861"],
    # RDP
    "rdp": ["H_EID_1149", "H_EID_4778", "H_EID_4779",
            "H_EID_21", "H_EID_22", "H_EID_25"],
}


ALL_EID_TAGS = sorted({t for tags in EID_TAGS_BY_CATEGORY.values() for t in tags})


# ---------------------------------------------------------------------------
# attack_map: every tag has ≥1 technique
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tag", ALL_EID_TAGS)
def test_every_eid_tag_has_attack_mapping(tag):
    assert tag in HYPOTHESIS_MAP, f"{tag} missing from HYPOTHESIS_MAP"
    techs = HYPOTHESIS_MAP[tag]
    assert techs, f"{tag} maps to empty technique list"
    for tid, name in techs:
        assert tid.startswith("T"), f"{tag} → {tid!r} not a T-id"
        assert name, f"{tag} → technique name empty"


def test_map_case_emits_techniques_from_eid_tags():
    """A Finding tagged with an EID surfaces its ATT&CK techniques via
    map_case — confirms the wiring is end-to-end."""
    ev = EvidenceItem(tool="t", version="0", command="x",
                      output_sha256="0"*64, output_path="/tmp/x")
    f = Finding(
        case_id="c", agent="log_analyst", confidence="high",
        claim="security.evtx 7045 fired for PSEXESVC",
        evidence=[ev],
        hypotheses_supported=["H_EID_7045"],
    )
    techs = map_case([f])
    assert "T1543.003" in techs
    assert "T1569.002" in techs


# ---------------------------------------------------------------------------
# Scoring: EID tags lift the right hypotheses
# ---------------------------------------------------------------------------

def _finding(tags: list[str], claim: str = "test") -> Finding:
    ev = EvidenceItem(tool="t", version="0", command="x",
                      output_sha256="0"*64, output_path="/tmp/x")
    return Finding(case_id="c", agent="log_analyst", confidence="medium",
                   claim=claim, evidence=[ev], hypotheses_supported=tags)


def test_eid_7045_lifts_persistence_service():
    ranked, _ = score_findings([_finding(["H_EID_7045"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_PERSISTENCE_SERVICE"] >= 2


def test_eid_4698_lifts_persistence_scheduled_task():
    ranked, _ = score_findings([_finding(["H_EID_4698"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_PERSISTENCE_SCHEDULED_TASK"] >= 2


def test_eid_1149_lifts_lateral_movement():
    ranked, _ = score_findings([_finding(["H_EID_1149"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_LATERAL_MOVEMENT"] >= 2


def test_eid_4778_lifts_lateral_movement():
    ranked, _ = score_findings([_finding(["H_EID_4778"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_LATERAL_MOVEMENT"] >= 2


def test_eid_91_winrm_lifts_lateral_movement():
    ranked, _ = score_findings([_finding(["H_EID_91"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_LATERAL_MOVEMENT"] >= 2


def test_eid_5140_share_lifts_lateral_movement():
    ranked, _ = score_findings([_finding(["H_EID_5140"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_LATERAL_MOVEMENT"] >= 2


def test_eid_4625_lifts_brute_force():
    ranked, _ = score_findings([_finding(["H_EID_4625"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_BRUTE_FORCE"] >= 2


def test_eid_1102_lifts_apt_and_refutes_benign():
    ranked, _ = score_findings([_finding(["H_EID_1102"])])
    by = {r.hyp_id: r.score for r in ranked}
    # APT gets +2 on log-clear
    assert by["H_APT_ESPIONAGE"] >= 2
    # Benign refuted at -3
    assert by["H_BENIGN_NO_INCIDENT"] <= -3


def test_wmi_5860_subscription_refutes_benign():
    ranked, _ = score_findings([_finding(["H_EID_5860"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_BENIGN_NO_INCIDENT"] <= -3


def test_eid_4672_admin_logon_supports_apt_weakly():
    """Admin logon on its own is NOT strong APT signal — only +1."""
    ranked, _ = score_findings([_finding(["H_EID_4672"])])
    by = {r.hyp_id: r.score for r in ranked}
    assert by["H_APT_ESPIONAGE"] == 1


def test_eid_tags_combined_compound_score():
    """Realistic intrusion: 4672 admin logon + 4648 explicit cred +
    7045 service install + 1102 log clear = strong APT chain."""
    ranked, _ = score_findings([
        _finding(["H_EID_4672"]),
        _finding(["H_EID_4648"]),
        _finding(["H_EID_7045"]),
        _finding(["H_EID_1102"]),
    ])
    by = {r.hyp_id: r.score for r in ranked}
    # APT gets +1 (4672) +1 (4648) +2 (1102) = 4
    assert by["H_APT_ESPIONAGE"] >= 4
    # Persistence service gets +2 from 7045
    assert by["H_PERSISTENCE_SERVICE"] >= 2
    # Benign refuted by 1102
    assert by["H_BENIGN_NO_INCIDENT"] <= -3
