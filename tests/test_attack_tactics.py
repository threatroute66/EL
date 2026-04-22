"""Tier-3 ATT&CK technique→tactic lookup tests."""
import pytest

from el.intel.attack_tactics import (
    TACTICS, TECHNIQUE_TACTIC, group_by_tactic, tactic_for,
)


def test_all_tactics_are_standard_mitre_enterprise():
    """Sanity: tactic names match MITRE Enterprise nomenclature."""
    expected = {
        "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Exfiltration", "Impact",
    }
    assert set(TACTICS) == expected


def test_tactic_for_primary_technique():
    assert tactic_for("T1003.001") == "Credential Access"
    assert tactic_for("T1059.001") == "Execution"
    assert tactic_for("T1486") == "Impact"
    assert tactic_for("T1021.001") == "Lateral Movement"
    assert tactic_for("T1071") == "Command and Control"


def test_tactic_for_sub_technique_falls_back_to_parent():
    """Unmapped sub-techniques inherit their parent's tactic."""
    # T1059.006 isn't in the dict but T1059 is → Execution
    assert tactic_for("T1059.006") == "Execution"
    # Fully unknown returns None
    assert tactic_for("T9999.999") is None
    assert tactic_for("") is None


def test_group_by_tactic_preserves_order():
    techniques = {
        "T1486": {"name": "a", "evidence_finding_ids": []},
        "T1003": {"name": "b", "evidence_finding_ids": []},
        "T1059": {"name": "c", "evidence_finding_ids": []},
    }
    grouped = group_by_tactic(techniques)
    # Iteration order follows TACTICS list for buckets that got hits
    keys = list(grouped.keys())
    # Execution (T1059) comes before Credential Access (T1003) which
    # comes before Impact (T1486)
    assert keys.index("Execution") < keys.index("Credential Access")
    assert keys.index("Credential Access") < keys.index("Impact")


def test_group_by_tactic_handles_unknown():
    techniques = {
        "T9999": {"name": "fake", "evidence_finding_ids": []},
        "T1003": {"name": "lsass", "evidence_finding_ids": []},
    }
    grouped = group_by_tactic(techniques)
    assert "Credential Access" in grouped
    assert "Unmapped" in grouped
    assert grouped["Unmapped"][0][0] == "T9999"


def test_every_technique_in_el_vocabulary_has_a_tactic():
    """Regression: any technique mentioned in EL code must be in the
    lookup OR be a sub-technique whose parent is mapped. This locks
    in the coverage so the heatmap doesn't silently drop techniques
    as the emission vocabulary grows."""
    import subprocess
    result = subprocess.run(
        ["grep", "-rhoE", r'"T[0-9]{4}(\.[0-9]+)?"', "/opt/EL/el/"],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.skip("grep unavailable")
    seen = sorted({line.strip('"') for line in result.stdout.splitlines()})
    missing = [t for t in seen if tactic_for(t) is None]
    assert not missing, (
        f"Techniques emitted by EL code but unmapped in attack_tactics: "
        f"{missing}. Add them to TECHNIQUE_TACTIC.")
