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
    "T1133":      "Initial Access",
    "T1189":      "Initial Access",
    "T1190":      "Initial Access",
    "T1566":      "Initial Access",        # Phishing (parent)
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
    "T1609":      "Execution",            # Container Administration Command
    "T1610":      "Defense Evasion",      # Deploy Container
    "T1611":      "Privilege Escalation", # Escape to Host
    "T1613":      "Discovery",            # Container and Resource Discovery
    # Persistence
    "T1098":      "Persistence",
    "T1098.001":  "Persistence",
    "T1098.003":  "Persistence",
    "T1098.004":  "Persistence",
    "T1098.007":  "Persistence",
    "T1136":      "Persistence",           # Create Account (parent)
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
    "T1548.006":  "Privilege Escalation",  # Mac TCC Manipulation
    # Defense Evasion
    "T1027":      "Defense Evasion",
    "T1027.002":  "Defense Evasion",
    "T1027.007":  "Defense Evasion",   # Dynamic API Resolution (AMFI bypass)
    "T1112":      "Defense Evasion",   # Modify Registry
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
    "T1556":      "Defense Evasion",   # Modify Authentication Process (TCC bypass)
    "T1556.006":  "Defense Evasion",
    "T1620":      "Defense Evasion",   # Reflective Code Loading (AMFI bypass)
    "T1565.001":  "Defense Evasion",   # Stored Data Manipulation
    "T1622":      "Defense Evasion",   # Debugger Evasion
    "T1505.003":  "Persistence",       # Server Software Component: Web Shell
    "T1547.001":  "Persistence",       # Registry Run Keys / Startup Folder
    "T1562.001":  "Defense Evasion",
    "T1562.007":  "Defense Evasion",
    "T1564.001":  "Defense Evasion",
    "T1564.004":  "Defense Evasion",   # Hide Artifacts: NTFS File Attributes (ADS)
    "T1564.008":  "Defense Evasion",
    # Credential Access
    "T1003":      "Credential Access",
    "T1003.001":  "Credential Access",
    "T1110":      "Credential Access",
    "T1110.001":  "Credential Access",
    "T1110.003":  "Credential Access",
    "T1528":      "Credential Access",
    "T1552.001":  "Credential Access",
    "T1552.007":  "Credential Access",   # Unsecured Credentials: Container API
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
    "T1481":      "Command and Control",  # Mobile: Web Service C2
    "T1462":      "Defense Evasion",       # Mobile: Manipulate Device Communication (MDM abuse)
    "T1571":      "Command and Control",
    "T1572":      "Command and Control",  # Protocol Tunneling (e.g. ssh -L VNC)
    # Exfiltration
    "T1041":      "Exfiltration",
    "T1048.003":  "Exfiltration",
    "T1567":      "Exfiltration",
    # Impact
    "T1485":      "Impact",
    "T1561":      "Impact",       # Disk Wipe
    "T1561.001":  "Impact",       # Disk Wipe: Disk Content Wipe
    "T1561.002":  "Impact",       # Disk Wipe: Disk Structure Wipe
    "T1486":      "Impact",
    "T1489":      "Impact",
    "T1490":      "Impact",
    "T1496":      "Impact",
    "T1531":      "Impact",
    "T1537":      "Impact",
    # ---- Techniques introduced by el/intel/attack_capacities.py ----
    # The Diamond Capacity map references these technique IDs; every
    # technique in EL's vocabulary must also carry a primary tactic so
    # the Activity Thread can phase-bucket it. Primary tactic = the one
    # MITRE lists first / an analyst would pick first when bucketing.
    "T1005":      "Collection",            # Data from Local System
    "T1018":      "Discovery",             # Remote System Discovery
    "T1033":      "Discovery",             # System Owner/User Discovery
    "T1036":      "Defense Evasion",       # Masquerading
    "T1048":      "Exfiltration",          # Exfil Over Alternative Protocol
    "T1052":      "Exfiltration",          # Exfil Over Physical Medium
    "T1052.001":  "Exfiltration",          # …over USB
    "T1056":      "Collection",            # Input Capture (also Cred Access)
    "T1056.001":  "Collection",            # Keylogging
    "T1057":      "Discovery",             # Process Discovery
    "T1069":      "Discovery",             # Permission Groups Discovery
    "T1074":      "Collection",            # Data Staged
    "T1082":      "Discovery",             # System Information Discovery
    "T1083":      "Discovery",             # File and Directory Discovery
    "T1087":      "Discovery",             # Account Discovery
    "T1090":      "Command and Control",   # Proxy
    "T1090.003":  "Command and Control",   # Multi-hop Proxy (Tor)
    "T1102":      "Command and Control",   # Web Service
    "T1113":      "Collection",            # Screen Capture
    "T1119":      "Collection",            # Automated Collection
    "T1135":      "Discovery",             # Network Share Discovery
    "T1140":      "Defense Evasion",       # Deobfuscate/Decode
    "T1213":      "Collection",            # Data from Information Repositories
    "T1497":      "Defense Evasion",       # Virtualization/Sandbox Evasion
    "T1530":      "Collection",            # Data from Cloud Storage
    "T1550":      "Lateral Movement",      # Use Alternate Auth Material
    "T1550.002":  "Lateral Movement",      # Pass the Hash
    "T1550.003":  "Lateral Movement",      # Pass the Ticket
    "T1552":      "Credential Access",     # Unsecured Credentials
    "T1558":      "Credential Access",     # Steal/Forge Kerberos Tickets
    "T1562":      "Defense Evasion",       # Impair Defenses
    "T1573":      "Command and Control",   # Encrypted Channel
    "T1574":      "Persistence",           # Hijack Execution Flow
    "T1574.001":  "Persistence",           # DLL Search-Order Hijacking
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
