"""Mac + Mobile platform-specific hypotheses.

Closes the gap-doc bullets:
- macOS: H_MAC_LAUNCH_DAEMON_PERSISTENCE, H_MAC_TCC_BYPASS,
  H_MAC_FILELESS_AMFI_BYPASS
- Mobile: H_MOBILE_SPYWARE_PERSISTENCE, H_MOBILE_SIDELOADED_APP,
  H_MOBILE_MDM_ABUSE

Each must:
  1. Be registered in HYPOTHESES with a deterministic scorer
  2. Be mapped to MITRE ATT&CK techniques
  3. Be present in the tactic lookup so the heatmap doesn't drop them
  4. Refute the null hypothesis (H_BENIGN_NO_INCIDENT)
  5. Be lifted by the appropriate triage detector family
"""
import pytest

from el.intel import attack_map, attack_tactics, hypotheses
from el.schemas.finding import EvidenceItem, Finding


_NEW_HYPOTHESES = (
    "H_MAC_LAUNCH_DAEMON_PERSISTENCE",
    "H_MAC_TCC_BYPASS",
    "H_MAC_FILELESS_AMFI_BYPASS",
    "H_MOBILE_SPYWARE_PERSISTENCE",
    "H_MOBILE_SIDELOADED_APP",
    "H_MOBILE_MDM_ABUSE",
)


def _ev() -> EvidenceItem:
    return EvidenceItem(tool="x", version="1", command="x",
                         output_sha256="ab" * 32,
                         output_path="/tmp/x")


def _f(*tags) -> Finding:
    return Finding(
        case_id="c", agent="x", claim="t", confidence="medium",
        evidence=[_ev()], hypotheses_supported=list(tags),
    )


# --- Hypothesis registration ------------------------------------------

def test_all_six_registered():
    by_id = hypotheses.by_id()
    for h in _NEW_HYPOTHESES:
        assert h in by_id, f"{h} not registered in HYPOTHESES"


def test_each_scores_3_when_tag_present():
    by_id = hypotheses.by_id()
    for hid in _NEW_HYPOTHESES:
        f = _f(hid)
        assert by_id[hid].score(f) == 3, f"{hid} did not lift on its own tag"


def test_each_scores_0_when_unrelated():
    by_id = hypotheses.by_id()
    f = _f("H_OPPORTUNISTIC_COMMODITY")     # unrelated tag
    for hid in _NEW_HYPOTHESES:
        assert by_id[hid].score(f) == 0


# --- Null hypothesis refutation ---------------------------------------

def test_each_refutes_benign_null():
    by_id = hypotheses.by_id()
    benign = by_id["H_BENIGN_NO_INCIDENT"]
    for hid in _NEW_HYPOTHESES:
        s = benign.score(_f(hid))
        assert s < 0, (
            f"{hid} should refute H_BENIGN_NO_INCIDENT, got score={s}")


# --- ATT&CK mapping ---------------------------------------------------

def test_each_mapped_to_attack_techniques():
    for hid in _NEW_HYPOTHESES:
        techs = attack_map.HYPOTHESIS_MAP.get(hid)
        assert techs, f"{hid} has no ATT&CK mapping"
        assert all(tid.startswith("T") and "." in tid or tid.startswith("T")
                   for tid, _ in techs), f"{hid} has malformed T-IDs"


def test_macos_attack_ids_specific():
    """The Mac LaunchDaemon hypothesis must point at T1543.001 +
    T1543.004 (the actual macOS sub-techniques) — not the generic
    T1543.003 Windows-Service variant."""
    techs = dict(attack_map.HYPOTHESIS_MAP["H_MAC_LAUNCH_DAEMON_PERSISTENCE"])
    assert "T1543.001" in techs
    assert "T1543.004" in techs
    assert "T1543.003" not in techs                       # Windows-only


def test_tcc_bypass_attack_ids():
    techs = dict(attack_map.HYPOTHESIS_MAP["H_MAC_TCC_BYPASS"])
    assert "T1548.006" in techs                           # TCC Manipulation


def test_amfi_bypass_attack_ids():
    techs = dict(attack_map.HYPOTHESIS_MAP["H_MAC_FILELESS_AMFI_BYPASS"])
    assert "T1620" in techs                               # Reflective Code Loading


def test_mobile_mdm_abuse_attack_ids():
    techs = dict(attack_map.HYPOTHESIS_MAP["H_MOBILE_MDM_ABUSE"])
    assert "T1462" in techs                               # Mobile: Manipulate Device Comm


# --- Tactic-lookup coverage -------------------------------------------

def test_every_attack_id_has_tactic():
    """The heatmap projection drops any technique whose tactic is
    unknown — every T-ID we just added must be in the tactic table."""
    for hid in _NEW_HYPOTHESES:
        for tid, _name in attack_map.HYPOTHESIS_MAP[hid]:
            assert attack_tactics.tactic_for(tid), (
                f"{tid} (mapped from {hid}) missing from "
                f"TECHNIQUE_TACTIC")


# --- Triage-skill family wiring ---------------------------------------

def test_macos_triage_lifts_launch_daemon():
    from el.skills import macos_triage as mt
    assert "H_MAC_LAUNCH_DAEMON_PERSISTENCE" in mt.hypotheses_for(
        "launch_persistence_suspicious")


def test_ios_triage_lifts_spyware_for_jailbreak():
    from el.skills import ios_triage as it
    assert "H_MOBILE_SPYWARE_PERSISTENCE" in it.hypotheses_for(
        "jailbreak_indicator")


def test_ios_triage_lifts_sideloaded():
    from el.skills import ios_triage as it
    assert "H_MOBILE_SIDELOADED_APP" in it.hypotheses_for(
        "sideloaded_app")


def test_ios_triage_lifts_mdm_abuse():
    from el.skills import ios_triage as it
    assert "H_MOBILE_MDM_ABUSE" in it.hypotheses_for(
        "provisioning_profile")


def test_android_triage_lifts_spyware_for_root():
    from el.skills import android_triage as at
    assert "H_MOBILE_SPYWARE_PERSISTENCE" in at.hypotheses_for(
        "rooted_device")


def test_android_triage_lifts_sideloaded_apk():
    from el.skills import android_triage as at
    assert "H_MOBILE_SIDELOADED_APP" in at.hypotheses_for(
        "sideloaded_apk")


def test_android_triage_lifts_spyware_for_data_local_tmp():
    from el.skills import android_triage as at
    assert "H_MOBILE_SPYWARE_PERSISTENCE" in at.hypotheses_for(
        "data_local_tmp_executable")
