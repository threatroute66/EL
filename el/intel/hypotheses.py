"""Case-level hypothesis library for ACH (Analysis of Competing Hypotheses).

Heuer's ACH demands ≥3 hypotheses on the table for any non-trivial case,
including a null hypothesis. Scoring is deterministic and per-finding:

  +3  strong support     |  the finding is hard to explain WITHOUT this hypothesis
  +1  weak support       |  consistent with, but not diagnostic
   0  neutral            |  no bearing
  -1  weak refute        |  mild tension
  -3  strong refute      |  the finding is hard to reconcile WITH this hypothesis

Scores are integer; we resist false-precision. The library is intentionally
narrow — over-broad scoring rules produce all-hypotheses-look-equal noise.
Add new hypotheses as new attack families come up in real cases.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from el.schemas.finding import Finding


@dataclass
class Hypothesis:
    hyp_id: str
    name: str
    description: str
    score: Callable[[Finding], int]


def _has_tag(tag: str) -> Callable[[Finding], bool]:
    return lambda f: tag in f.hypotheses_supported


def _claim_contains(*needles: str) -> Callable[[Finding], bool]:
    needles = tuple(n.lower() for n in needles)
    return lambda f: any(n in (f.claim or "").lower() for n in needles)


def _h_benign(f: Finding) -> int:
    s = 0
    if f.confidence == "insufficient":
        s += 1
    if f.confidence == "low":
        s += 1
    for tag in ("H_PROCESS_INJECTION", "H_C2_OR_REVERSE_SHELL",
                "H_INITIAL_ACCESS_DOC_MACRO", "H_LIVING_OFF_THE_LAND",
                "H_BEC_ACCOUNT_TAKEOVER", "H_CLOUD_PERSISTENCE",
                "H_BRUTE_FORCE", "H_LATERAL_MOVEMENT"):
        if tag in f.hypotheses_supported:
            s -= 3
    if _claim_contains("createaccesskey", "putbucketpolicy", "failed console",
                       "deactivatemfadevice", "consolelogin (×")(f):
        s -= 2
    return s


def _h_commodity(f: Finding) -> int:
    s = 0
    if _has_tag("H_PROCESS_INJECTION")(f): s += 1
    if _has_tag("H_LIVING_OFF_THE_LAND")(f): s += 1
    if _has_tag("H_C2_OR_REVERSE_SHELL")(f): s += 1
    return s


def _h_ransomware(f: Finding) -> int:
    s = 0
    if _claim_contains("vssadmin", "shadowcopy", "shadows /all", "delete shadows",
                       "wbadmin", ".lock", ".enc", "readme", "ransom",
                       "encrypt", "chacha", "rsa public")(f):
        s += 3
    if _has_tag("H_INITIAL_ACCESS_DOC_MACRO")(f): s += 1
    if _has_tag("H_LIVING_OFF_THE_LAND")(f): s += 1
    return s


def _h_apt(f: Finding) -> int:
    s = 0
    if _has_tag("H_PROCESS_INJECTION")(f): s += 3
    if _has_tag("H_INITIAL_ACCESS_DOC_MACRO")(f): s += 1
    if _has_tag("H_C2_OR_REVERSE_SHELL")(f): s += 1
    if _has_tag("H_LIVING_OFF_THE_LAND")(f): s += 1
    if _claim_contains("4624", "4672", "4769", "kerberos")(f):
        s += 1
    return s


def _h_insider(f: Finding) -> int:
    s = 0
    if _claim_contains("usb", "removable", "robocopy", "7-zip", "rar.exe",
                       "stage", "exfil", "uploaded")(f):
        s += 3
    if _claim_contains("4624", "logon", "4672")(f):
        s += 1
    return s


def _h_supply_chain(f: Finding) -> int:
    s = 0
    if _claim_contains("update.exe", "setup.exe", "msi", "signed", "vendor",
                       "publisher", "code-signing")(f):
        s += 1
    if _has_tag("H_PROCESS_INJECTION")(f): s += 1
    return s


def _h_bec(f: Finding) -> int:
    s = 0
    if _claim_contains("o365", "azuread", "graph.microsoft.com", "outlook",
                       "ews", "mailbox", "mailitemsaccessed")(f):
        s += 3
    if _has_tag("H_BEC_ACCOUNT_TAKEOVER")(f):
        s += 3
    if _claim_contains("consolelogin", "assumerole", "createloginprofile",
                       "deactivatemfadevice", "createaccesskey",
                       "failed console logins")(f):
        s += 2
    return s


def _h_brute_force(f: Finding) -> int:
    s = 0
    if _has_tag("H_BRUTE_FORCE")(f):
        s += 3
    if _claim_contains("4625", "logon_failed", "failed console logins",
                       "many failed", "kerberos pre-auth")(f):
        s += 2
    return s


def _h_cloud_persistence(f: Finding) -> int:
    s = 0
    if _has_tag("H_CLOUD_PERSISTENCE")(f):
        s += 3
    if _claim_contains("createaccesskey", "putbucketpolicy", "putbucketacl",
                       "attachuserpolicy", "attachrolepolicy",
                       "createloginprofile", "putuserpolicy", "putrolepolicy",
                       "deactivatemfadevice")(f):
        s += 2
    return s


def _h_c2_beaconing(f: Finding) -> int:
    s = 0
    if _has_tag("H_C2_OR_REVERSE_SHELL")(f): s += 3
    if _claim_contains("netscan", "connection", "tcp", "udp", "beacon", "sni",
                       "destination port")(f):
        s += 1
    return s


HYPOTHESES: list[Hypothesis] = [
    Hypothesis("H_BENIGN_NO_INCIDENT",
               "Benign / no incident",
               "Observations are explainable by routine activity; no malicious actor present.",
               _h_benign),
    Hypothesis("H_OPPORTUNISTIC_COMMODITY",
               "Opportunistic commodity malware",
               "Non-targeted commodity malware infection (info-stealer, cryptominer, loader).",
               _h_commodity),
    Hypothesis("H_RANSOMWARE",
               "Ransomware / extortion",
               "Encryption of files, shadow copy deletion, and ransom artifacts.",
               _h_ransomware),
    Hypothesis("H_APT_ESPIONAGE",
               "Targeted intrusion / espionage",
               "Targeted threat actor: persistence, lateral movement, credential theft, exfil.",
               _h_apt),
    Hypothesis("H_INSIDER_DATA_EXFIL",
               "Insider data exfiltration",
               "Authorised user staging and removing data.",
               _h_insider),
    Hypothesis("H_SUPPLY_CHAIN",
               "Supply-chain / trusted-vendor compromise",
               "Compromised software update, signed binary, or vendor channel.",
               _h_supply_chain),
    Hypothesis("H_BEC_ACCOUNT_TAKEOVER",
               "Business email compromise / account takeover",
               "Cloud identity abuse, mailbox manipulation, third-party app consent.",
               _h_bec),
    Hypothesis("H_C2_BEACONING",
               "Active command-and-control beaconing",
               "Established C2 channel; periodic outbound communication to attacker infrastructure.",
               _h_c2_beaconing),
    Hypothesis("H_BRUTE_FORCE",
               "Brute-force / password-spray",
               "High volume of failed authentications against accounts.",
               _h_brute_force),
    Hypothesis("H_CLOUD_PERSISTENCE",
               "Cloud persistence / privilege establishment",
               "Attacker establishing persistence in cloud IAM (new keys, policies, MFA tampering).",
               _h_cloud_persistence),
]


def by_id() -> dict[str, Hypothesis]:
    return {h.hyp_id: h for h in HYPOTHESES}
