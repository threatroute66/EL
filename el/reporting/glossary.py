"""Plain-English glossary for the executive (non-expert) report tier.

The analyst report renders ATT&CK T-IDs, ACH hypothesis tags
(H_INSIDER_EMAIL_EXFIL), disk-anomaly pattern IDs (MACB_TIMESTOMP_SKEW),
and Windows artifact names (Amcache, Prefetch, EVTX) verbatim — that's
the right vocabulary for an analyst.

The executive report needs the same facts in language a stakeholder
without DFIR training can read. This module is the single source of
truth for those translations: a static dict + helpers to (a) translate
a token to plain English and (b) collect every glossary term that
appeared in a rendered document so the renderer can emit a "what
these terms mean" appendix.

When an entry is missing, helpers return the original token — the
exec renderer treats that as a tier-2 fallback (still readable but
the term will look like jargon to a layperson). Adding entries is
the right fix; the renderer is not allowed to invent translations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class GlossaryEntry:
    term: str             # canonical token, e.g. "T1003.001"
    plain: str            # short replacement: "credential dumping (LSASS memory)"
    explanation: str      # one-sentence layperson explanation


# ---------------------------------------------------------------------------
# ACH hypotheses — investigation-level explanations the system tracks.
# ---------------------------------------------------------------------------
_HYPOTHESES: dict[str, tuple[str, str]] = {
    "H_ANTI_FORENSICS": (
        "evidence tampering",
        "Someone tried to hide their tracks by altering or deleting forensic artifacts.",
    ),
    "H_APT_ESPIONAGE": (
        "targeted intrusion",
        "A skilled, persistent attacker with a specific goal (intelligence, IP, sensitive data).",
    ),
    "H_BEC_ACCOUNT_TAKEOVER": (
        "business email compromise",
        "An attacker took control of an email account, typically to redirect payments or impersonate the user.",
    ),
    "H_BENIGN_NO_INCIDENT": (
        "no incident found",
        "The evidence does not show malicious activity — the system appears to have been used normally.",
    ),
    "H_BRUTE_FORCE": (
        "password guessing attack",
        "Many login attempts against a small or large set of accounts, looking for a password match.",
    ),
    "H_C2_BEACONING": (
        "command-and-control communication",
        "Malware on the host was reaching out to an attacker-controlled server for instructions.",
    ),
    "H_CLOUD_PERSISTENCE": (
        "cloud account backdoor",
        "An attacker established lasting access to a cloud account (e.g., new admin user, OAuth grant).",
    ),
    "H_CREDENTIAL_ACCESS": (
        "credential theft",
        "Passwords, hashes, or login tokens were extracted from the system's memory or storage.",
    ),
    "H_INSIDER_DATA_EXFIL": (
        "insider data theft",
        "Someone with legitimate access copied or removed data they were not authorized to take.",
    ),
    "H_INSIDER_EMAIL_EXFIL": (
        "data theft via email",
        "Someone with legitimate access sent confidential data to an outside recipient by email.",
    ),
    "H_LATERAL_MOVEMENT": (
        "spreading to other hosts",
        "An attacker pivoted from this host to other systems on the same network.",
    ),
    "H_MAC_FILELESS_AMFI_BYPASS": (
        "macOS code-execution bypass",
        "Malicious code ran on a Mac by evading Apple's signature-verification system.",
    ),
    "H_MAC_LAUNCH_DAEMON_PERSISTENCE": (
        "macOS startup persistence",
        "An attacker installed a Mac startup item so their code runs every reboot.",
    ),
    "H_MAC_TCC_BYPASS": (
        "macOS privacy bypass",
        "Code accessed protected resources (camera, microphone, files) without the user's consent.",
    ),
    "H_MOBILE_MDM_ABUSE": (
        "mobile device management abuse",
        "Attacker enrolled the phone into a management profile they control.",
    ),
    "H_MOBILE_SIDELOADED_APP": (
        "unofficial mobile app",
        "An app was installed outside the official store, bypassing normal review.",
    ),
    "H_MOBILE_SPYWARE_PERSISTENCE": (
        "mobile spyware",
        "Surveillance software was installed on the phone and configured to keep running.",
    ),
    "H_OPPORTUNISTIC_COMMODITY": (
        "common malware infection",
        "The host was hit by a widely-known malware family (banking trojan, infostealer, etc.).",
    ),
    "H_PERSISTENCE_SCHEDULED_TASK": (
        "scheduled-task backdoor",
        "Attacker added a Windows scheduled task so their code runs on a timer or at login.",
    ),
    "H_PERSISTENCE_SERVICE": (
        "Windows service backdoor",
        "Attacker installed a Windows service so their code keeps running across reboots.",
    ),
    "H_RANSOMWARE": (
        "ransomware attack",
        "Files were encrypted by an attacker who is demanding payment to restore them.",
    ),
    "H_SCAN_RECON": (
        "reconnaissance / probing",
        "Automated scans hit the host looking for known vulnerabilities or exposed services.",
    ),
    "H_SUPPLY_CHAIN": (
        "supply-chain compromise",
        "A trusted vendor's software or update was tampered with before reaching this host.",
    ),
    # Competing motives + evidence-state hypotheses that can lead the ACH
    # ranking or appear in the narrative. Every id in el.intel.hypotheses
    # HYPOTHESES must have a plain-language entry here (locked by
    # test_glossary_covers_all_hypotheses) so the executive headline never
    # falls back to "the leading theory cannot be summarised in plain language".
    "H_PRE_ATTACK_PLANNING": (
        "attack planning / lone-offender preparation",
        "User-authored content shows preparation for a physical attack — "
        "weapons and ammunition research, target or escape-route planning, "
        "manifesto-style writing.",
    ),
    "H_ILLICIT_ENTERPRISE": (
        "illicit-business device",
        "The device belongs to someone running a criminal business (drug "
        "trafficking, contraband marketplace, fraud, crypto-laundering) — "
        "not an intrusion victim.",
    ),
    "H_INSIDER_DEVICE_DESTRUCTION": (
        "deliberate device destruction",
        "The owner deliberately wiped or destroyed the disk's structure — "
        "for example an interrupted disk wipe that zeroed the partition "
        "table — to prevent forensic recovery.",
    ),
    "H_CONTAINER_ESCAPE": (
        "container escape",
        "A process broke out of its container to reach and act on the host.",
    ),
    "H_K8S_PRIVILEGE_ESCALATION": (
        "Kubernetes privilege escalation",
        "An attacker gained elevated rights within a Kubernetes cluster.",
    ),
    "H_DISK_ENCRYPTED": (
        "encrypted disk / volume",
        "All or part of the disk is encrypted at rest; its contents cannot "
        "be read without the key.",
    ),
    "H_NTFS_ADS_PRESENT": (
        "hidden NTFS data streams",
        "Data was tucked into NTFS alternate data streams — a place ordinary "
        "file listings do not show.",
    ),
    "H_SHADOW_COPY_ARTIFACT_DELETED": (
        "deleted shadow copies",
        "Windows shadow-copy snapshots that could hold earlier versions of "
        "files were deleted.",
    ),
    "H_NOT_CLEAN_BASELINE": (
        "comparison baseline is not clean",
        "The reference image used for comparison is itself not known-clean, "
        "so 'no difference found' is not proof the host is clean.",
    ),
    "H_PAIRED_CAPTURE_CANDIDATE": (
        "paired baseline capture",
        "This image looks like a same-host re-capture used for comparison "
        "rather than an independent clean reference.",
    ),
}


# ---------------------------------------------------------------------------
# ATT&CK technique IDs that surface most often in EL reports. Keep this
# list focused on what an executive actually sees; full ATT&CK is too
# long for a glossary. Add entries as new T-IDs become common in output.
# ---------------------------------------------------------------------------
_ATTACK: dict[str, tuple[str, str]] = {
    "T1003": (
        "credential dumping",
        "Extracting stored passwords or password hashes from the operating system.",
    ),
    "T1003.001": (
        "credential dumping (LSASS memory)",
        "Reading login secrets out of the Windows process that holds them in memory.",
    ),
    "T1021.002": (
        "lateral movement (SMB shares)",
        "Moving from one Windows host to another via shared folders / admin shares.",
    ),
    "T1048.003": (
        "data exfiltration over plaintext protocol",
        "Sending stolen data out over an unencrypted channel like FTP or HTTP.",
    ),
    "T1055": (
        "process injection",
        "Hiding malicious code by running it inside a legitimate process.",
    ),
    "T1070.001": (
        "log clearing",
        "Deleting Windows event logs to destroy a record of what happened.",
    ),
    "T1071": (
        "command-and-control over standard protocols",
        "Malware talking to its operator using common channels (HTTPS, DNS) so it blends in.",
    ),
    "T1218": (
        "abusing trusted system tools",
        "Running malicious payloads through built-in Windows utilities to evade detection.",
    ),
    "T1534": (
        "internal spearphishing",
        "Sending a phishing message from one compromised account to other internal users.",
    ),
    "T1543.003": (
        "Windows service persistence",
        "Installing a service so the attacker's code runs every time the system boots.",
    ),
    "T1566.002": (
        "phishing link",
        "Tricking the user into clicking a malicious URL in an email or message.",
    ),
    "T1569.002": (
        "service execution",
        "Running attacker code through the Windows service control mechanism.",
    ),
    "T1571": (
        "non-standard port",
        "Communicating over a port that's unusual for the chosen protocol, to avoid filters.",
    ),
}


# ---------------------------------------------------------------------------
# disk_anomaly pattern IDs — the codes that show up in disk_forensicator
# claims like "Disk anomaly [MACB_TIMESTOMP_SKEW]: ...".
# ---------------------------------------------------------------------------
_DISK_ANOMALY: dict[str, tuple[str, str]] = {
    "MACB_TIMESTOMP_SKEW": (
        "timestamp tampering",
        "A file's recorded creation date is far earlier than its modification date — a signature of someone faking when the file was made.",
    ),
    "SYSTEM_BINARY_ZERO_TIMESTAMPS": (
        "wiped system file (timestamps)",
        "A Windows system file has all of its timestamps zeroed out, which only happens through deliberate tampering.",
    ),
    "SYSTEM_BINARY_ZERO_SIZE": (
        "wiped system file (contents)",
        "A Windows system file's contents have been emptied — anti-forensic destruction of an executable.",
    ),
    "LSASS_OUTSIDE_SYSTEM32": (
        "fake credential process",
        "A program named lsass.exe was found in the wrong folder; the real one only lives in System32. This is malware disguising itself.",
    ),
    "SVCHOST_OUTSIDE_SYSTEM32": (
        "fake system process",
        "A program named svchost.exe was found in the wrong folder; the real one only lives in System32. This is malware disguising itself.",
    ),
    "EXE_IN_TEMP": (
        "executable in temp folder",
        "A program was launched from a temporary folder — common for droppers and second-stage malware.",
    ),
    "RECYCLE_BIN_EXE": (
        "executable hidden in recycle bin",
        "A program was placed inside the user's Recycle Bin and run from there to evade detection.",
    ),
    "MIMIKATZ_NAMED_BINARY": (
        "credential-stealing tool by name",
        "A file with a name commonly associated with the Mimikatz credential-dumping tool.",
    ),
    "PSEXEC_SERVICE_ARTIFACT": (
        "remote-execution tool trace",
        "Traces of PsExec, a sysadmin tool routinely abused by attackers to run code on remote hosts.",
    ),
    "VSSADMIN_DELETE_SHADOWS_TRACE": (
        "shadow-copy deletion",
        "The Volume Shadow Copy backups were deleted — a precursor to ransomware encryption to prevent easy recovery.",
    ),
    "SCHEDULED_TASK_NONMS": (
        "non-Microsoft scheduled task",
        "A scheduled task created by something other than Microsoft — could be legitimate software or attacker persistence.",
    ),
    "PYINSTALLER_TEMP_DIR": (
        "Python-bundled executable trace",
        "Leftovers from a Python program packaged as a single .exe — common for hobbyist malware.",
    ),
}


# ---------------------------------------------------------------------------
# Lateral movement detector codes (technique/subtechnique pairs).
# ---------------------------------------------------------------------------
_LATERAL: dict[str, tuple[str, str]] = {
    "ps_remoting/inbound_pssession": (
        "incoming PowerShell remote session",
        "Another host opened a PowerShell remote session into this host — a common lateral-movement technique.",
    ),
    "wmi/event_consumer_registration": (
        "WMI persistence registration",
        "Someone registered a WMI event handler — a stealthy way to make code run automatically when a trigger fires.",
    ),
    "anti_forensic/security_log_cleared": (
        "security log cleared",
        "The Windows Security event log was wiped (Event ID 1102). This is rare in normal operation and is a strong tampering signal.",
    ),
    "psexec/inbound": (
        "incoming PsExec connection",
        "Another host used PsExec to run a command on this host — sysadmin tool, but also common in attacks.",
    ),
}


# ---------------------------------------------------------------------------
# Common DFIR / Windows / mobile artifact terminology that turns up in
# claim text. Short entries because these will appear repeatedly.
# ---------------------------------------------------------------------------
_DFIR_TERMS: dict[str, tuple[str, str]] = {
    "EVTX": (
        "Windows event log",
        "The native Windows log format. EVTX files record sign-ins, service starts, security events, etc.",
    ),
    "MACB": (
        "file timestamps",
        "Shorthand for the four NTFS timestamps: Modified, Accessed, Changed, Born (created).",
    ),
    "MFT": (
        "filesystem catalog",
        "The Master File Table — NTFS's record of every file on the disk.",
    ),
    "ADS": (
        "alternate data stream",
        "A way to attach hidden extra data to an NTFS file. Sometimes used to conceal payloads.",
    ),
    "LSASS": (
        "Windows credential service",
        "The process that holds the live login secrets. A frequent target for credential theft.",
    ),
    "Prefetch": (
        "program-launch records",
        "Windows tracks recently launched programs in Prefetch files for performance — also evidence of execution.",
    ),
    "Amcache": (
        "program execution registry",
        "A Windows registry hive recording every program that has run on the host.",
    ),
    "Shimcache": (
        "compatibility cache",
        "A Windows cache of programs the system has seen, useful as a secondary record of execution.",
    ),
    "SRUM": (
        "system resource usage log",
        "A Windows database tracking which programs used network and CPU, with timestamps.",
    ),
    "NTFS": (
        "Windows filesystem",
        "The standard Windows disk format.",
    ),
    "EWF": (
        "forensic disk image format",
        "The standard format (.E01) for forensic copies of disks. Includes integrity hashes.",
    ),
    "YARA": (
        "malware-pattern matching",
        "A tool that scans files and memory for byte patterns associated with known malware families.",
    ),
    "ATT&CK": (
        "MITRE attack technique catalog",
        "An industry-standard taxonomy of attacker techniques, organized by goal (credential access, persistence, etc.).",
    ),
    "ACH": (
        "Analysis of Competing Hypotheses",
        "A structured analytic technique that scores multiple possible explanations against the same evidence.",
    ),
    "IOC": (
        "indicator of compromise",
        "A specific observable (IP, domain, file hash, etc.) associated with malicious activity.",
    ),
    "Volatility": (
        "memory analysis tool",
        "The standard open-source tool for extracting evidence from a memory image.",
    ),
    "Plaso": (
        "timeline tool",
        "An open-source tool that merges every dated artifact on a system into one chronological timeline.",
    ),
    "iLEAPP": (
        "iOS artifact parser",
        "A tool that extracts iPhone/iPad artifacts (apps, locations, messages) from a forensic image.",
    ),
    "Telegram": (
        "messaging app",
        "A widely-used encrypted messaging application.",
    ),
}


# ---------------------------------------------------------------------------
# Combined registry. Order is significant for collision resolution — earlier
# tables win for ambiguous tokens. (Currently no collisions; recorded in
# case future entries overlap.)
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, GlossaryEntry] = {}


def _build():
    for table in (_HYPOTHESES, _ATTACK, _DISK_ANOMALY, _LATERAL, _DFIR_TERMS):
        for term, (plain, explanation) in table.items():
            if term in _REGISTRY:
                continue
            _REGISTRY[term] = GlossaryEntry(term=term, plain=plain, explanation=explanation)


_build()


def translate(term: str) -> str:
    """Return the plain-English short form of `term`, or `term` itself
    if no entry exists. Case-sensitive — DFIR tokens are typically
    capitalized in code paths and the registry mirrors that."""
    entry = _REGISTRY.get(term)
    return entry.plain if entry else term


def explain(term: str) -> str | None:
    """Return the one-sentence layperson explanation, or None if the
    term has no registry entry."""
    entry = _REGISTRY.get(term)
    return entry.explanation if entry else None


def lookup(term: str) -> GlossaryEntry | None:
    """Return the full GlossaryEntry, or None if missing."""
    return _REGISTRY.get(term)


# Token forms found in EL output: T1003, T1003.001, H_INSIDER_EMAIL_EXFIL,
# MACB_TIMESTOMP_SKEW, ps_remoting/inbound_pssession.
_TOKEN_RE = re.compile(
    r"\b(?:"
    r"T\d{4}(?:\.\d{3})?"               # ATT&CK T-IDs
    r"|H_[A-Z][A-Z0-9_]+"                # ACH hypothesis tags
    r"|[A-Z]{2,}_[A-Z][A-Z0-9_]+"        # disk_anomaly-style codes
    r"|[a-z_]+/[a-z_]+"                  # lateral-movement-style codes
    r"|EVTX|MACB|MFT|ADS|LSASS|NTFS|EWF|YARA|ACH|IOC|SRUM"  # bare DFIR terms
    r"|Prefetch|Amcache|Shimcache|Volatility|Plaso|iLEAPP|Telegram"
    r")\b"
)


def entries_used(text: str) -> list[GlossaryEntry]:
    """Scan `text` and return every glossary entry whose term appears.
    Used by the executive renderer to build the report's glossary
    appendix — only terms actually present in the rendered prose are
    listed, not the entire registry."""
    seen: dict[str, GlossaryEntry] = {}
    for match in _TOKEN_RE.finditer(text):
        tok = match.group(0)
        entry = _REGISTRY.get(tok)
        if entry is None:
            continue
        seen[entry.term] = entry
    return sorted(seen.values(), key=lambda e: e.term)


def all_entries() -> list[GlossaryEntry]:
    """Return every registered entry, sorted by term. Useful for
    tests and for pre-rendering a complete glossary if needed."""
    return sorted(_REGISTRY.values(), key=lambda e: e.term)
