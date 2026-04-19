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
    """Benign / null hypothesis. Lifted ONLY by positive baseline-style
    indicators ("no non-baseline items in Memory Baseliner", "all binaries
    signed by expected publisher"). NOT lifted by insufficient or low
    findings — 'we couldn't analyze it' is not 'it's clean'.
    """
    s = 0
    # Positive lift: explicit baseline-success findings
    if _claim_contains("no non-baseline items observed",
                       "no malicious activity",
                       "all signatures verified")(f):
        s += 2
    # Refute: any tag that points to active malice
    for tag in ("H_PROCESS_INJECTION", "H_C2_OR_REVERSE_SHELL",
                "H_INITIAL_ACCESS_DOC_MACRO", "H_LIVING_OFF_THE_LAND",
                "H_BEC_ACCOUNT_TAKEOVER", "H_CLOUD_PERSISTENCE",
                "H_BRUTE_FORCE", "H_LATERAL_MOVEMENT", "H_ROOTKIT",
                "H_PERSISTENCE_SERVICE", "H_INSIDER_EMAIL_EXFIL"):
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
    if _has_tag("H_CREDENTIAL_ACCESS")(f): s += 3
    if _has_tag("H_LATERAL_MOVEMENT")(f): s += 2
    if _has_tag("H_PERSISTENCE_SCHEDULED_TASK")(f): s += 1
    if _has_tag("H_PERSISTENCE_SERVICE")(f): s += 1
    if _claim_contains("4624", "4672", "4769", "kerberos",
                        "credential-access target")(f):
        s += 1
    return s


def _h_credential_access(f: Finding) -> int:
    s = 0
    if _has_tag("H_CREDENTIAL_ACCESS")(f): s += 3
    if _claim_contains("lsass", "credential-dumping", "mimikatz",
                        "credential-access target")(f):
        s += 2
    return s


def _h_insider_email_exfil(f: Finding) -> int:
    """Insider / compromised-account exfiltration via EMAIL. Distinct from
    the broader H_INSIDER_DATA_EXFIL (USB / staging / archiver) because
    email-exfil leaves very different evidence: mailbox artefacts, display-
    name spoofing, sensitive-attachment-to-external patterns. Separating
    the two lets ACH rank them independently — M57-Jean-shaped cases
    (pretexting email + confidential attachment to external webmail) can
    surface above generic "insider" or "APT" without keyword collision."""
    s = 0
    if _has_tag("H_INSIDER_EMAIL_EXFIL")(f):
        s += 3
    # Two narrow claim fingerprints from EmailForensicatorAgent:
    if _claim_contains("display-name/smtp mismatch")(f):
        s += 3
    if _claim_contains("sensitive attachment → external recipient",
                       "sensitive attachment -> external recipient")(f):
        s += 3
    # Bulk mail to a consumer webmail is weak corroboration (can also be
    # benign "send myself a copy" behaviour).
    if _claim_contains("external-recipient bulk attachment")(f):
        s += 1
    return s


def _h_insider(f: Finding) -> int:
    s = 0
    if _claim_contains("usb", "removable", "robocopy", "7-zip", "rar.exe",
                       "stage", "exfil", "uploaded")(f):
        s += 3
    # An email-exfil finding is also evidence for the generic insider
    # hypothesis, just weaker than for H_INSIDER_EMAIL_EXFIL itself —
    # keeps the two hypotheses ranked together when both apply.
    if (_has_tag("H_INSIDER_EMAIL_EXFIL")(f)
            or _claim_contains("display-name/smtp mismatch",
                               "sensitive attachment → external recipient")(f)):
        s += 1
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
    """Only lift on EXPLICIT C2-shaped tags or strongly-typed keywords.
    Earlier version keyword-matched 'tcp'/'udp' which lifted H_C2 on every
    pcap (network_analyst's 'Parsed N packets' claim mentions both). That
    saturated 95% of corpus runs at +4. The keyword set below is restricted
    to terms that only appear in actual C2-shaped findings (suspicious port,
    beacon, periodic check-in patterns)."""
    s = 0
    if _has_tag("H_C2_OR_REVERSE_SHELL")(f): s += 3
    if _claim_contains("suspicious destination ports", "beacon",
                        "periodic check-in", "c2 channel")(f):
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
               "Authorised user staging and removing data (USB / archiver / upload).",
               _h_insider),
    Hypothesis("H_INSIDER_EMAIL_EXFIL",
               "Insider / pretext exfiltration via email",
               "Mailbox evidence of spoofed-display-name or sensitive-attachment "
               "exfiltration to an external recipient. Distinct from the broader "
               "insider hypothesis because the evidence shape is email-specific.",
               _h_insider_email_exfil),
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
    Hypothesis("H_CREDENTIAL_ACCESS",
               "Credential access / dumping",
               "Malware or operator extracting credentials from system processes "
               "(lsass memory, SAM hive, Kerberos tickets). Mimikatz-class activity.",
               _h_credential_access),
    Hypothesis("H_LATERAL_MOVEMENT",
               "Lateral movement",
               "Operator pivoting between hosts via PsExec, WMIC, RDP, SSH, "
               "or admin-share file copy.",
               lambda f: 3 if "H_LATERAL_MOVEMENT" in f.hypotheses_supported else 0),
    Hypothesis("H_PERSISTENCE_SCHEDULED_TASK",
               "Persistence via scheduled task",
               "Attacker-installed scheduled task surviving reboot.",
               lambda f: 3 if "H_PERSISTENCE_SCHEDULED_TASK" in f.hypotheses_supported else 0),
    Hypothesis("H_PERSISTENCE_SERVICE",
               "Persistence via service",
               "Attacker-installed Windows service surviving reboot.",
               lambda f: 3 if "H_PERSISTENCE_SERVICE" in f.hypotheses_supported else 0),
]


def by_id() -> dict[str, Hypothesis]:
    return {h.hyp_id: h for h in HYPOTHESES}
