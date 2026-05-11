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


# Agents whose claims ECHO the input filename — if the corpus has
# honest labels (e.g. "2016-12-09-Locky-ransomware.pcap"), those labels
# leak into keyword-based hypothesis scoring. threat_hunter's claim is
# "YARA sweep of <filename>: N hit(s)"; triage's is "Input identified
# as X from magic bytes". Both legitimate signals come through specific
# TAGS (H_IOC_CORROBORATED, H_OS_WINDOWS, etc.), not through keyword
# matches on the claim text. Scorers below skip these agents to prevent
# corpus-label leakage.
_FILENAME_ECHO_AGENTS = frozenset({"threat_hunter", "triage"})


def _filename_safe(f: Finding) -> bool:
    """Return False when the finding is from an agent whose claim always
    contains the input filename — see _FILENAME_ECHO_AGENTS above."""
    return f.agent not in _FILENAME_ECHO_AGENTS


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
                "H_PERSISTENCE_SERVICE", "H_INSIDER_EMAIL_EXFIL",
                # macOS + Mobile platform-specific compromise tags
                # are deliberate signals; they refute the null the
                # same way a Windows persistence-service does.
                "H_MAC_LAUNCH_DAEMON_PERSISTENCE",
                "H_MAC_TCC_BYPASS",
                "H_MAC_FILELESS_AMFI_BYPASS",
                "H_MOBILE_SPYWARE_PERSISTENCE",
                "H_MOBILE_SIDELOADED_APP",
                "H_MOBILE_MDM_ABUSE",
                # PR-P: log-clearing + WMI event-consumer registration +
                # RDP-session EIDs are almost never benign in the DFIR
                # context.
                "H_EID_1102", "H_EID_104",
                "H_EID_5860", "H_EID_5861",
                # Anti-forensics is deliberate — benign activity does
                # not timestomp, zero-size, or sdelete system files.
                "H_ANTI_FORENSICS"):
        if tag in f.hypotheses_supported:
            s -= 3
    if _claim_contains("createaccesskey", "putbucketpolicy", "failed console",
                       "deactivatemfadevice", "consolelogin (×")(f):
        s -= 2
    return s


def _h_commodity(f: Finding) -> int:
    s = 0
    # Direct lift — a family-triage finding tagged H_OPPORTUNISTIC_COMMODITY
    # IS evidence for the commodity hypothesis. Missing this meant EK /
    # botnet attributions added 0 to the commodity score, and every
    # 2014-era EK pcap in batch-1 ended with ACH tied at 0.
    if _has_tag("H_OPPORTUNISTIC_COMMODITY")(f): s += 3
    if _has_tag("H_PROCESS_INJECTION")(f): s += 1
    if _has_tag("H_LIVING_OFF_THE_LAND")(f): s += 1
    if _has_tag("H_C2_OR_REVERSE_SHELL")(f): s += 1
    return s


def _h_ransomware(f: Finding) -> int:
    # Filename-label leak guard — see _filename_safe() docstring.
    if not _filename_safe(f):
        return 0
    s = 0
    if _claim_contains("vssadmin", "shadowcopy", "shadows /all", "delete shadows",
                       "wbadmin", ".lock", ".enc", "readme",
                       "ransom note", "ransom demand", "ransomware.",
                       "files encrypted", "files have been encrypted",
                       "encrypt your files", "encrypting files",
                       "chacha", "rsa public")(f):
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
    # PR-P: admin-logon + explicit-cred-use + Kerberos ticket requests
    # are APT fingerprints when chained with the above; weak alone.
    if _has_tag("H_EID_4672")(f): s += 1     # admin privileges assigned
    if _has_tag("H_EID_4648")(f): s += 1     # explicit-cred logon (RunAs)
    if _has_tag("H_EID_4769")(f): s += 1     # service ticket
    # Log-clearing is a core APT/intrusion signature
    if _has_tag("H_EID_1102")(f): s += 2
    if _has_tag("H_EID_104")(f):  s += 2
    # Anti-forensics (timestomping, log-clearing, system-binary wipe)
    # is a core APT playbook step, weak alone but corroborative when
    # combined with the above.
    if _has_tag("H_ANTI_FORENSICS")(f): s += 1
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
    # Explicit tag from UserActivityAgent (memory-only project-access
    # timeline) — Office MRU path resolves to a removable USB letter
    # AND the path contains corporate-project fragments. Higher-fidelity
    # than the keyword scorer below; tag-only finding still lifts.
    if _has_tag("H_INSIDER_DATA_STAGING")(f):
        s += 3
    # Filename-leak guard — pcap corpora occasionally include "exfil"
    # or "upload" in ground-truth labels; threat_hunter / triage claims
    # would echo them.
    if _filename_safe(f) and _claim_contains(
            "usb", "removable", "robocopy", "7-zip", "rar.exe",
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
    # Calibration item from docs/SRL-2018-shakedown.md #2:
    # `execution_corroborator` claims name binaries ("Outlook.exe ran
    # from C:\Program Files\..."); the substring `outlook` would lift
    # H_BEC trivially on every host that has Office installed (12-point
    # leak observed on wkstn-01 r4). The corroborator's job is "this
    # binary ran"; email/cloud hypothesis scoring belongs to
    # `email_forensicator` / `cloud_forensicator` whose claims carry
    # the contextual signals that aren't just a binary name.
    if (f.agent or "") == "execution_corroborator":
        return 0
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
    # PR-P: tag-based brute-force lift (H_EID_* set by LM agent + future
    # chainsaw integration). 4625 (failed logon) / 4776 (NTLM failure) /
    # 4740 (account lockout) all point at brute force or spray.
    for tag in ("H_EID_4625", "H_EID_4776", "H_EID_4740"):
        if _has_tag(tag)(f): s += 2
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


def _h_scan_recon(f: Finding) -> int:
    """Automated scanning / probing / reconnaissance traffic. Distinct from
    C2 because the evidence shape is opposite: wide fan-out to many
    destinations with high 4xx rate and scripted User-Agents, rather than
    periodic low-volume beacons to a single infrastructure. Added because
    /loop runs over the scans-and-probes corpus kept ranking H_C2_BEACONING
    first — the 'suspicious destination ports' signal alone is ambiguous
    between scan and C2, and without this hypothesis there was no better
    target for the HTTP_ERROR_HEAVY + HTTP_SCRIPTED_UA evidence.
    """
    if not _filename_safe(f):
        return 0
    s = 0
    # Tag-based lift — network_anomaly.py tags HTTP_ERROR_HEAVY and
    # HTTP_SCRIPTED_UA with H_SCAN_RECON directly.
    if _has_tag("H_SCAN_RECON")(f):
        s += 3
    # Strong lift — network_analyst's HTTP_ERROR_HEAVY anomaly literally
    # says "Scan / discovery / broken C2 pattern" in the claim body.
    if _claim_contains("http_error_heavy", "scan / discovery")(f):
        s += 3
    # Scripted-client UAs (go-http-client, curl, python-requests, masscan,
    # zgrab, nmap, zmap). Scripted automation, not a human browser.
    if _claim_contains("http_scripted_ua", "scripted-client user-agent",
                       "go-http-client", "python-requests", "python-urllib",
                       "masscan", "zgrab", "zmap",
                       "nmap scripting engine")(f):
        s += 2
    # Protocol-violation / stack-fingerprint noise that accompanies scanners.
    # Weak alone — just corroborates.
    if _claim_contains("syn_with_data", "syn_after_reset",
                       "dns_conn_count_too_large", "dns_truncated_len",
                       "protocol anomalies frequently accompany")(f):
        s += 1
    return s


def _h_anti_forensics(f: Finding) -> int:
    """Deliberate tampering with evidence trails — log clearing,
    timestomping, system-binary zeroing, sdelete.

    Distinct from H_APT_ESPIONAGE because benign insiders / commodity
    malware cleanup scripts can also tamper with artefacts; the two
    hypotheses can coexist with different score profiles. Ranking
    these separately lets ACH surface "this host was scrubbed" as a
    first-class conclusion even when the attacker's *other* signals
    are absent (the Rathbun anti-forensics reference image ships that
    exact shape — timestomping only, no C2, no credential access)."""
    s = 0
    # Direct tags from disk_anomaly.py + evtx_triage log-clearing events.
    if _has_tag("H_ANTI_FORENSICS")(f): s += 3
    if _has_tag("H_LOG_CLEARED")(f): s += 2
    # Timestomp + sdelete traces surface through the claim body.
    if _claim_contains("timestomp", "timestomping", "sdelete",
                        "secure delete", "b→m skew",
                        "zero-size system binary",
                        "all four macb timestamps zero")(f):
        s += 2
    # EID 1102 (audit-log cleared) + 104 (event-log cleared) —
    # already H_EID_1102 / H_EID_104 tags in the ledger.
    if _has_tag("H_EID_1102")(f): s += 2
    if _has_tag("H_EID_104")(f):  s += 2
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
    # Keyword scoring guarded against filename-label leak (pcap filenames
    # like "2020-*-cobalt-strike-beacon.pcap" echoed by threat_hunter).
    if _filename_safe(f) and _claim_contains(
            "suspicious destination ports", "beacon",
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
    Hypothesis("H_SCAN_RECON",
               "Automated scanning / probing / reconnaissance",
               "Internet-wide scanner or attacker reconnaissance traffic: high 4xx "
               "rate, scripted User-Agents, wide port fan-out. Typical for "
               "public-facing hosts capturing background scan noise.",
               _h_scan_recon),
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
               # PR-P: lift on H_LATERAL_MOVEMENT OR the EID tags that point
               # directly at remote-access / remote-exec techniques.
               lambda f: (3 if "H_LATERAL_MOVEMENT" in f.hypotheses_supported
                          else (2 if any(t in f.hypotheses_supported for t in (
                              "H_EID_5140", "H_EID_5145",    # admin-share
                              "H_EID_1149", "H_EID_4778",    # RDP
                              "H_EID_91", "H_EID_168",        # WinRM/PS-remoting
                              "H_EID_7045",                    # service install
                          )) else 0))),
    Hypothesis("H_PERSISTENCE_SCHEDULED_TASK",
               "Persistence via scheduled task",
               "Attacker-installed scheduled task surviving reboot.",
               lambda f: (3 if "H_PERSISTENCE_SCHEDULED_TASK" in f.hypotheses_supported
                          # PR-P: task-creation audit events add corroboration
                          else (2 if any(t in f.hypotheses_supported for t in (
                              "H_EID_4698", "H_EID_4702",
                          )) else 0))),
    Hypothesis("H_PERSISTENCE_SERVICE",
               "Persistence via service",
               "Attacker-installed Windows service surviving reboot.",
               lambda f: (3 if "H_PERSISTENCE_SERVICE" in f.hypotheses_supported
                          # PR-P: service-install events (7045 remote,
                          # 4697 subscription-audited) add corroboration
                          else (2 if ("H_EID_7045" in f.hypotheses_supported
                                       or "H_EID_4697" in f.hypotheses_supported)
                                else 0))),
    Hypothesis("H_ANTI_FORENSICS",
               "Anti-forensics / evidence tampering",
               "Deliberate tampering with evidence trails — timestomping, "
               "log clearing, sdelete / system-binary wipe. Stands alone "
               "when the attacker's other signals are absent but the "
               "tampering itself is visible (Rathbun VHDX shape).",
               _h_anti_forensics),
    # macOS-specific persistence + integrity-bypass hypotheses. The
    # Mac forensicator emits these instead of generic
    # H_PERSISTENCE_SERVICE so an analyst reading the ranking can
    # tell the difference between "Windows service installed" and
    # "LaunchDaemon plist dropped under /tmp" — the playbooks
    # diverge after the first cell.
    Hypothesis("H_MAC_LAUNCH_DAEMON_PERSISTENCE",
               "macOS LaunchAgent / LaunchDaemon persistence",
               "Attacker-installed plist under /Library/LaunchDaemons, "
               "/Library/LaunchAgents, ~/Library/LaunchAgents, or "
               "/System/Library/LaunchDaemons referencing a "
               "non-standard path (/tmp, /Users/Shared, hidden dot-"
               "directory). The Mac equivalent of "
               "H_PERSISTENCE_SERVICE.",
               lambda f: (3 if "H_MAC_LAUNCH_DAEMON_PERSISTENCE"
                          in f.hypotheses_supported else 0)),
    Hypothesis("H_MAC_TCC_BYPASS",
               "macOS TCC (Transparency / Consent / Control) bypass",
               "Attacker manipulating ~/Library/Application Support/"
               "com.apple.TCC/TCC.db or /Library/Application Support/"
               "com.apple.TCC/TCC.db to grant their binary "
               "FullDiskAccess / Camera / Microphone / Accessibility "
               "without user consent. Hallmark of macOS-targeted "
               "spyware (XCSSET, Silver Sparrow, NSO post-exploit).",
               lambda f: (3 if "H_MAC_TCC_BYPASS"
                          in f.hypotheses_supported else 0)),
    Hypothesis("H_MAC_FILELESS_AMFI_BYPASS",
               "macOS AMFI / fileless code-execution bypass",
               "Apple Mobile File Integrity bypass: unsigned binary "
               "executing via dyld injection, reflective Mach-O "
               "loading, or amfid hooking. Distinct from "
               "H_PROCESS_INJECTION because the AMFI surface is "
               "Apple-platform-specific.",
               lambda f: (3 if "H_MAC_FILELESS_AMFI_BYPASS"
                          in f.hypotheses_supported else 0)),
    # Mobile (iOS + Android) hypotheses. The Mobile forensicators
    # already emit family-specific tags; these are the case-level
    # rollups the ACH ranking actually scores against.
    Hypothesis("H_MOBILE_SPYWARE_PERSISTENCE",
               "Mobile spyware persistence",
               "Pegasus / Predator / FinSpy-class artifact patterns: "
               "DataUsage.sqlite anomalies, jailbreak indicators on "
               "non-jailbroken iOS, /data/local/tmp executables on "
               "Android, rooted-device markers on a phone the user "
               "didn't own-root. Strong APT-mobile fingerprint.",
               lambda f: (3 if "H_MOBILE_SPYWARE_PERSISTENCE"
                          in f.hypotheses_supported else 0)),
    Hypothesis("H_MOBILE_SIDELOADED_APP",
               "Mobile sideloaded application",
               "App installed outside the App Store / Play Store: "
               "iOS enterprise-signed IPA without matching MDM "
               "profile, Android APK installed via PackageInstaller "
               "from non-Play sources. Frequent vector for "
               "commodity Android trojans + iOS-targeted RATs.",
               lambda f: (3 if "H_MOBILE_SIDELOADED_APP"
                          in f.hypotheses_supported else 0)),
    Hypothesis("H_MOBILE_MDM_ABUSE",
               "Mobile MDM-profile abuse",
               "Unexpected mobile-device-management profile installed: "
               "iOS configuration profile granting full device control "
               "to an unknown URL, Android device-admin app the user "
               "doesn't recognise. The persistence ladder for "
               "lawful-intercept-grade and supply-chain mobile "
               "compromise.",
               lambda f: (3 if "H_MOBILE_MDM_ABUSE"
                          in f.hypotheses_supported else 0)),
    # Container / Kubernetes hypotheses. Triggered by Falco event-JSONL
    # ingestion + (future) container-explorer offline-state inspection.
    # The forensicators emit explicit tags; these case-level rollups are
    # what ACH actually scores.
    Hypothesis("H_CONTAINER_ESCAPE",
               "Container runtime escape",
               "Behavioural evidence of a container breaking the runtime "
               "boundary: writes to /proc/sys/, mount of host filesystems, "
               "kernel module load from inside a container, ptrace of a "
               "host PID, /var/run/docker.sock access from a non-privileged "
               "pod. Falco rule families like 'Container Escape via *' or "
               "Tracee 'cap_capable' anomalies are the diagnostic signal.",
               lambda f: (3 if "H_CONTAINER_ESCAPE"
                          in f.hypotheses_supported else 0)),
    Hypothesis("H_K8S_PRIVILEGE_ESCALATION",
               "Kubernetes privilege escalation",
               "RBAC abuse, ServiceAccount token theft, privileged-pod "
               "creation, hostPath/hostNetwork pod admission, "
               "exec/portforward into a privileged pod, or tampering with "
               "cluster-role bindings. Audit-log anomalies + Falco "
               "K8s rule hits diagnose this distinct from generic "
               "H_LATERAL_MOVEMENT (which is host-network-tier).",
               lambda f: (3 if "H_K8S_PRIVILEGE_ESCALATION"
                          in f.hypotheses_supported else 0)),
]


def by_id() -> dict[str, Hypothesis]:
    return {h.hyp_id: h for h in HYPOTHESES}
