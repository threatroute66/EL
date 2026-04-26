"""MITRE ATT&CK technique mapping.

Two layers:
  - RULE_MAP: explicit, lossless mapping from rule_id (Rule-Based Challenger)
    or hypothesis tag to one or more (technique_id, name) pairs.
  - PATTERN_MAP: claim-text pattern fallback for findings not tagged with a
    rule or hypothesis.

Mappings are intentionally narrow — broad mappings produce false attribution.
Anything not explicitly mapped returns []. Empty mapping is honest; over-mapping
is sycophancy.
"""
from __future__ import annotations

import re

Technique = tuple[str, str]


RULE_MAP: dict[str, list[Technique]] = {
    "OFFICE_SPAWN_SHELL_BENIGN_AUTOMATION": [
        ("T1566.001", "Phishing: Spearphishing Attachment"),
        ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
        ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    ],
    "MALFIND_JIT_FALSE_POSITIVE": [("T1055", "Process Injection")],
    "LOLBIN_CMDLINE_BENIGN_USE": [("T1218", "System Binary Proxy Execution")],
    "NETSCAN_CONNECTION_NEEDS_ENRICHMENT": [("T1071", "Application Layer Protocol")],
}


HYPOTHESIS_MAP: dict[str, list[Technique]] = {
    "H_PROCESS_INJECTION": [("T1055", "Process Injection")],
    "H_PROCESS_HOLLOWING": [("T1055.012", "Process Injection: Process Hollowing")],
    "H_INITIAL_ACCESS_DOC_MACRO": [
        ("T1566.001", "Phishing: Spearphishing Attachment"),
        ("T1204.002", "User Execution: Malicious File"),
    ],
    "H_LIVING_OFF_THE_LAND": [("T1218", "System Binary Proxy Execution")],
    "H_C2_OR_REVERSE_SHELL": [
        ("T1071", "Application Layer Protocol"),
        ("T1571", "Non-Standard Port"),
    ],
    "H_SCAN_RECON": [
        ("T1595", "Active Scanning"),
        ("T1046", "Network Service Discovery"),
    ],
    "H_CREDENTIAL_ACCESS": [
        ("T1003.001", "OS Credential Dumping: LSASS Memory"),
        ("T1003", "OS Credential Dumping"),
    ],
    "H_LATERAL_MOVEMENT": [
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
        ("T1569.002", "System Services: Service Execution"),
    ],
    "H_PERSISTENCE_SCHEDULED_TASK": [
        ("T1053.005", "Scheduled Task/Job: Scheduled Task"),
    ],
    "H_PERSISTENCE_SERVICE": [
        ("T1543.003", "Create or Modify System Process: Windows Service"),
    ],
    # macOS-specific persistence + integrity-bypass.
    "H_MAC_LAUNCH_DAEMON_PERSISTENCE": [
        ("T1543.001", "Create or Modify System Process: Launch Agent"),
        ("T1543.004", "Create or Modify System Process: Launch Daemon"),
    ],
    "H_MAC_TCC_BYPASS": [
        ("T1548.006", "Abuse Elevation Control Mechanism: TCC Manipulation"),
        ("T1556", "Modify Authentication Process"),
    ],
    "H_MAC_FILELESS_AMFI_BYPASS": [
        ("T1620", "Reflective Code Loading"),
        ("T1027.007", "Obfuscated Files or Information: Dynamic API Resolution"),
    ],
    # Mobile (iOS + Android) — uses MITRE ATT&CK Mobile T-IDs where
    # they exist; falls back to enterprise IDs for shared concepts.
    "H_MOBILE_SPYWARE_PERSISTENCE": [
        ("T1547", "Boot or Logon Autostart Execution"),
        ("T1404", "Exploitation for Privilege Escalation"),
    ],
    "H_MOBILE_SIDELOADED_APP": [
        ("T1476", "Deliver Malicious App via Other Means"),
        ("T1444", "Masquerade as Legitimate Application"),
    ],
    "H_MOBILE_MDM_ABUSE": [
        ("T1481", "Web Service"),
        ("T1462", "Manipulate Device Communication"),
    ],
    "H_INSIDER_EMAIL_EXFIL": [
        ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol"),
        ("T1534", "Internal Spearphishing"),
        ("T1566.002", "Phishing: Spearphishing Link"),
    ],
    # Windows Event ID → ATT&CK technique mappings. These tags are
    # emitted by LateralMovementAnalyst (PR-G) and any future detector
    # that walks chainsaw/hayabusa output. Expanded in PR-P to cover
    # the Hunt-Evil + Windows Forensics "Account Usage" + lateral-
    # movement destination-side EID matrix.
    #
    # Authentication + logon
    "H_EID_4624": [("T1078", "Valid Accounts")],                       # Successful logon (subtyped by LogonType)
    "H_EID_4625": [("T1110", "Brute Force")],                           # Failed logon
    "H_EID_4634": [("T1078", "Valid Accounts")],                       # Logoff (context)
    "H_EID_4648": [("T1078", "Valid Accounts")],                       # Explicit-cred logon (RunAs)
    "H_EID_4672": [("T1078", "Valid Accounts"),                        # Special privileges (admin)
                    ("T1548.002", "Abuse Elevation: Bypass UAC")],
    # Kerberos auth (domain controllers)
    "H_EID_4768": [("T1558.003", "Steal/Forge Kerberos Tickets: Kerberoasting")],  # TGT
    "H_EID_4769": [("T1558.003", "Steal/Forge Kerberos Tickets: Kerberoasting")],  # Service ticket
    "H_EID_4776": [("T1110", "Brute Force")],                           # NTLM auth
    # Account management (T1136 create, T1098 modify, T1531 impact)
    "H_EID_4720": [("T1136.001", "Create Account: Local Account")],
    "H_EID_4722": [("T1098", "Account Manipulation")],                 # account enabled
    "H_EID_4725": [("T1531", "Account Access Removal")],                # account disabled
    "H_EID_4726": [("T1531", "Account Access Removal")],                # account deleted
    "H_EID_4728": [("T1098.007", "Account Manipulation: Group Membership")],  # global group member added
    "H_EID_4732": [("T1098.007", "Account Manipulation: Group Membership")],  # local group member added
    "H_EID_4740": [("T1110", "Brute Force")],                           # account locked out
    "H_EID_4756": [("T1098.007", "Account Manipulation: Group Membership")],  # universal group member added
    # Process execution (requires "Audit Process Tracking" enabled)
    "H_EID_4688": [("T1059", "Command and Scripting Interpreter")],
    # Scheduled tasks (T1053.005)
    "H_EID_4698": [("T1053.005", "Scheduled Task/Job: Scheduled Task")],   # task created
    "H_EID_4699": [("T1053.005", "Scheduled Task/Job: Scheduled Task"),
                    ("T1070", "Indicator Removal")],                       # task deleted
    "H_EID_4700": [("T1053.005", "Scheduled Task/Job: Scheduled Task")],   # task enabled
    "H_EID_4701": [("T1053.005", "Scheduled Task/Job: Scheduled Task")],   # task disabled
    "H_EID_4702": [("T1053.005", "Scheduled Task/Job: Scheduled Task")],   # task updated
    # Services (T1543.003)
    "H_EID_4697": [("T1543.003", "Create or Modify System Process: Windows Service")],
    "H_EID_7034": [("T1489", "Service Stop")],                          # service crashed
    "H_EID_7035": [("T1569.002", "System Services: Service Execution")],
    "H_EID_7036": [("T1569.002", "System Services: Service Execution")],
    "H_EID_7040": [("T1543.003", "Create or Modify System Process: Windows Service")],
    "H_EID_7045": [("T1543.003", "Create or Modify System Process: Windows Service"),
                    ("T1569.002", "System Services: Service Execution")],
    # File shares + object access
    "H_EID_5140": [("T1021.002", "Remote Services: SMB/Windows Admin Shares")],  # share access
    "H_EID_5145": [("T1021.002", "Remote Services: SMB/Windows Admin Shares")],  # share file access
    # Anti-forensic
    "H_EID_1102": [("T1070.001", "Indicator Removal: Clear Windows Event Logs")],
    "H_EID_104":  [("T1070.001", "Indicator Removal: Clear Windows Event Logs")],   # System log cleared
    # PowerShell
    "H_EID_4103": [("T1059.001", "Command and Scripting Interpreter: PowerShell")],   # module logging
    "H_EID_4104": [("T1059.001", "Command and Scripting Interpreter: PowerShell")],   # script block
    "H_EID_400":  [("T1059.001", "Command and Scripting Interpreter: PowerShell")],
    "H_EID_403":  [("T1059.001", "Command and Scripting Interpreter: PowerShell")],
    "H_EID_800":  [("T1059.001", "Command and Scripting Interpreter: PowerShell")],
    # WinRM
    "H_EID_91":   [("T1021.006", "Remote Services: Windows Remote Management")],
    "H_EID_168":  [("T1021.006", "Remote Services: Windows Remote Management")],
    # WMI
    "H_EID_5857": [("T1047", "Windows Management Instrumentation")],
    "H_EID_5860": [("T1546.003", "Event Triggered Execution: WMI Event Subscription")],
    "H_EID_5861": [("T1546.003", "Event Triggered Execution: WMI Event Subscription")],
    # RDP
    "H_EID_1149": [("T1021.001", "Remote Services: Remote Desktop Protocol")],
    "H_EID_4778": [("T1021.001", "Remote Services: Remote Desktop Protocol")],
    "H_EID_4779": [("T1021.001", "Remote Services: Remote Desktop Protocol")],
    "H_EID_21":   [("T1021.001", "Remote Services: Remote Desktop Protocol")],
    "H_EID_22":   [("T1021.001", "Remote Services: Remote Desktop Protocol")],
    "H_EID_25":   [("T1021.001", "Remote Services: Remote Desktop Protocol")],
}


PATTERN_MAP: list[tuple[re.Pattern, list[Technique]]] = [
    (re.compile(r"powershell\.exe", re.IGNORECASE), [("T1059.001", "PowerShell")]),
    (re.compile(r"\bcmd\.exe\b", re.IGNORECASE), [("T1059.003", "Windows Command Shell")]),
    (re.compile(r"\bwscript\.exe|cscript\.exe\b", re.IGNORECASE), [("T1059.005", "Visual Basic")]),
    (re.compile(r"\bmshta\.exe\b", re.IGNORECASE), [("T1218.005", "Mshta")]),
    (re.compile(r"\brundll32\.exe\b", re.IGNORECASE), [("T1218.011", "Rundll32")]),
    (re.compile(r"\bregsvr32\.exe\b", re.IGNORECASE), [("T1218.010", "Regsvr32")]),
    (re.compile(r"\bbitsadmin\.exe\b", re.IGNORECASE), [("T1197", "BITS Jobs")]),
    (re.compile(r"malfind", re.IGNORECASE), [("T1055", "Process Injection")]),
    (re.compile(r"scheduled[_ ]?task", re.IGNORECASE), [("T1053.005", "Scheduled Task")]),
    (re.compile(r"port[s]?:\s*\{?\d", re.IGNORECASE), [("T1571", "Non-Standard Port")]),
]


def map_finding(finding) -> list[Technique]:
    """Return distinct (T-id, name) pairs implicated by this finding."""
    pairs: list[Technique] = []
    seen: set[str] = set()

    def add(items: list[Technique]) -> None:
        for tid, name in items:
            if tid in seen:
                continue
            seen.add(tid)
            pairs.append((tid, name))

    notes = finding.red_review.challenger_notes or ""
    for rule_id, items in RULE_MAP.items():
        if rule_id in notes:
            add(items)

    for hyp in finding.hypotheses_supported:
        if hyp in HYPOTHESIS_MAP:
            add(HYPOTHESIS_MAP[hyp])

    claim = finding.claim or ""
    for pat, items in PATTERN_MAP:
        if pat.search(claim):
            add(items)

    return pairs


def map_case(findings) -> dict[str, dict]:
    """Aggregate techniques across the whole case ledger."""
    agg: dict[str, dict] = {}
    for f in findings:
        for tid, name in map_finding(f):
            slot = agg.setdefault(tid, {"id": tid, "name": name, "evidence_finding_ids": []})
            slot["evidence_finding_ids"].append(f.finding_id)
    return agg
