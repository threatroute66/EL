"""Lookup: MITRE ATT&CK technique ID → primary tactic name.

Scoped to the 103 technique IDs EL currently emits across
el/intel/attack_map.py, skill wrappers, and agent extracted_facts.

Many ATT&CK techniques are polytactic (T1053 Scheduled Task spans
Execution + Persistence + Privilege Escalation, for example). For
the heatmap we assign each technique the *primary* tactic most
commonly cited in ATT&CK documentation — the one an analyst would
pick first when bucketing. Sub-techniques follow the parent's
primary tactic unless they're exclusively tied to a different one.

MITRE Mobile-only technique IDs (T1404, T1444, T1476, T1478) map
to Enterprise-equivalent tactics so the heatmap stays one-grid.
"""
from __future__ import annotations


TACTICS = (
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)


TECHNIQUE_TACTIC: dict[str, str] = {
    # Initial Access
    "T1078":      "Initial Access",
    "T1078.004":  "Initial Access",
    "T1189":      "Initial Access",
    "T1190":      "Initial Access",
    "T1566.001":  "Initial Access",
    "T1566.002":  "Initial Access",
    "T1476":      "Initial Access",  # Mobile: Deliver Malicious App
    # Execution
    "T1047":      "Execution",
    "T1053":      "Execution",
    "T1053.003":  "Execution",
    "T1053.005":  "Execution",
    "T1059":      "Execution",
    "T1059.001":  "Execution",
    "T1059.003":  "Execution",
    "T1059.004":  "Execution",
    "T1059.005":  "Execution",
    "T1203":      "Execution",
    "T1204.002":  "Execution",
    "T1569":      "Execution",
    "T1569.002":  "Execution",
    # Persistence
    "T1098":      "Persistence",
    "T1098.001":  "Persistence",
    "T1098.003":  "Persistence",
    "T1098.004":  "Persistence",
    "T1098.007":  "Persistence",
    "T1136.001":  "Persistence",
    "T1197":      "Persistence",
    "T1543":      "Persistence",
    "T1543.001":  "Persistence",
    "T1543.003":  "Persistence",
    "T1543.004":  "Persistence",
    "T1546.003":  "Persistence",
    "T1547":      "Persistence",
    "T1547.006":  "Persistence",
    "T1574.002":  "Persistence",
    "T1574.006":  "Persistence",
    # Privilege Escalation
    "T1055":      "Privilege Escalation",
    "T1055.012":  "Privilege Escalation",
    "T1068":      "Privilege Escalation",
    "T1404":      "Privilege Escalation",  # Mobile PrivEsc
    "T1548.002":  "Privilege Escalation",
    "T1548.003":  "Privilege Escalation",
    # Defense Evasion
    "T1027":      "Defense Evasion",
    "T1027.002":  "Defense Evasion",
    "T1036.005":  "Defense Evasion",
    "T1070":      "Defense Evasion",
    "T1070.001":  "Defense Evasion",
    "T1070.003":  "Defense Evasion",
    "T1218":      "Defense Evasion",
    "T1218.005":  "Defense Evasion",
    "T1218.010":  "Defense Evasion",
    "T1218.011":  "Defense Evasion",
    "T1444":      "Defense Evasion",  # Mobile: Masquerade as Legit App
    "T1478":      "Defense Evasion",  # Mobile: Install Insecure Config
    "T1556.006":  "Defense Evasion",
    "T1565.001":  "Defense Evasion",   # Stored Data Manipulation
    "T1562.001":  "Defense Evasion",
    "T1562.007":  "Defense Evasion",
    "T1564.001":  "Defense Evasion",
    "T1564.008":  "Defense Evasion",
    # Credential Access
    "T1003":      "Credential Access",
    "T1003.001":  "Credential Access",
    "T1110":      "Credential Access",
    "T1110.001":  "Credential Access",
    "T1110.003":  "Credential Access",
    "T1528":      "Credential Access",
    "T1552.001":  "Credential Access",
    "T1555":      "Credential Access",
    "T1555.006":  "Credential Access",
    "T1558.001":  "Credential Access",
    "T1558.003":  "Credential Access",
    # Discovery
    "T1016":      "Discovery",
    "T1046":      "Discovery",
    "T1087.004":  "Discovery",
    "T1595":      "Discovery",
    # Lateral Movement
    "T1021":      "Lateral Movement",
    "T1021.001":  "Lateral Movement",
    "T1021.002":  "Lateral Movement",
    "T1021.004":  "Lateral Movement",
    "T1021.006":  "Lateral Movement",
    "T1534":      "Lateral Movement",
    "T1570":      "Lateral Movement",
    # Collection
    "T1039":      "Collection",
    "T1074.001":  "Collection",
    "T1114.002":  "Collection",
    "T1114.003":  "Collection",
    # Command and Control
    "T1071":      "Command and Control",
    "T1071.001":  "Command and Control",
    "T1071.004":  "Command and Control",
    "T1095":      "Command and Control",
    "T1105":      "Command and Control",
    "T1219":      "Command and Control",
    "T1568.001":  "Command and Control",
    "T1568.002":  "Command and Control",
    "T1571":      "Command and Control",
    # Exfiltration
    "T1041":      "Exfiltration",
    "T1048.003":  "Exfiltration",
    "T1567":      "Exfiltration",
    # Impact
    "T1485":      "Impact",
    "T1486":      "Impact",
    "T1489":      "Impact",
    "T1490":      "Impact",
    "T1496":      "Impact",
    "T1531":      "Impact",
    "T1537":      "Impact",
}


def tactic_for(technique_id: str) -> str | None:
    """Return the primary tactic for a given technique_id, or None
    if unknown (unmapped techniques go in 'Unmapped' bucket in the
    heatmap caller, not here)."""
    if not technique_id:
        return None
    tid = technique_id.strip()
    if tid in TECHNIQUE_TACTIC:
        return TECHNIQUE_TACTIC[tid]
    # Fall back to parent technique for unmapped sub-techniques
    if "." in tid:
        parent = tid.split(".", 1)[0]
        return TECHNIQUE_TACTIC.get(parent)
    return None


def group_by_tactic(
    techniques: dict[str, dict],
) -> dict[str, list[tuple[str, dict]]]:
    """Bucket a {tid → info} dict by tactic. Returns ordered by
    TACTICS then by technique id within each tactic. Techniques
    with no tactic assignment land in a trailing 'Unmapped' bucket."""
    buckets: dict[str, list[tuple[str, dict]]] = {t: [] for t in TACTICS}
    unmapped: list[tuple[str, dict]] = []
    for tid, info in techniques.items():
        tac = tactic_for(tid)
        if tac and tac in buckets:
            buckets[tac].append((tid, info))
        else:
            unmapped.append((tid, info))
    for b in buckets.values():
        b.sort(key=lambda kv: kv[0])
    unmapped.sort(key=lambda kv: kv[0])
    result = {t: items for t, items in buckets.items() if items}
    if unmapped:
        result["Unmapped"] = unmapped
    return result


__all__ = ["TACTICS", "TECHNIQUE_TACTIC", "tactic_for", "group_by_tactic"]
