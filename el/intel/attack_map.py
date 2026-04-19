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
    "H_INSIDER_EMAIL_EXFIL": [
        ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol"),
        ("T1534", "Internal Spearphishing"),
        ("T1566.002", "Phishing: Spearphishing Link"),
    ],
    "H_EID_4625": [("T1110", "Brute Force")],
    "H_EID_1102": [("T1070.001", "Indicator Removal: Clear Windows Event Logs")],
    "H_EID_4697": [("T1543.003", "Create or Modify System Process: Windows Service")],
    "H_EID_4698": [("T1053.005", "Scheduled Task/Job: Scheduled Task")],
    "H_EID_4720": [("T1136.001", "Create Account: Local Account")],
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
