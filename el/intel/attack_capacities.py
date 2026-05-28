"""Lookup: MITRE ATT&CK technique ID → Diamond Model 'Capacity' string.

Per Caltagirone/Pendergast/Betz (2013) §4.2:

  Capability Capacity = all of the vulnerabilities and exposures
  that can be utilized by the individual capability regardless of
  victim.

In other words: the techniques the operator was observed using
imply a set of victim assets / authentication materials / control
surfaces that those techniques can reach. The Capacity vertex
captures *that derived reach*, separately from the Techniques row
(the *how*) and the Infrastructure vertex (the *where*).

The mapping below is plain-English (no technique IDs, no MITRE
sub-tactic taxonomy) so it surfaces to a non-expert reader without
needing a glossary. Techniques EL emits but doesn't have a tailored
capacity for fall back to a per-tactic placeholder via
``capacity_for(technique_id)``.

This is hand-curated for the ~50 techniques EL actually emits across
all agents, not exhaustive. New technique IDs added to
``el/intel/attack_tactics.py`` should get a Capacity entry here too
— ``test_attack_capacities.py`` enforces that no EL-emitted
technique falls back to the generic placeholder silently.
"""
from __future__ import annotations

from el.intel.attack_tactics import TECHNIQUE_TACTIC


# Hand-curated capacity strings. Keys are MITRE technique IDs.
# Values are one-line plain-English descriptions of what each
# technique gives the operator access to.
TECHNIQUE_CAPACITY: dict[str, str] = {
    # ----- Initial Access ------------------------------------------------
    "T1078":     "valid account credentials (any source — purchased, "
                  "phished, default, or insider)",
    "T1078.004": "cloud-account credentials (IAM users, OAuth tokens, "
                  "service-principal keys)",
    "T1133":     "external remote-service exposure (VPN, RDP, "
                  "SSH, Citrix, ICA, public RDP gateways)",
    "T1189":     "drive-by browser exploitation against any user who "
                  "visits a watering-hole site",
    "T1190":     "exposed network-facing application vulnerabilities "
                  "(unpatched web apps, public services)",
    "T1566":     "user-mediated payload delivery via any social-"
                  "engineering channel (email, message, voice, web)",
    "T1566.001": "user-mediated payload delivery via attachment in "
                  "email or message",
    "T1566.002": "user-mediated payload delivery via link in email or "
                  "message",
    "T1476":     "user-mediated mobile-app delivery (sideload / store "
                  "abuse on Android or iOS)",
    # ----- Execution -----------------------------------------------------
    "T1047":     "arbitrary command execution via Windows Management "
                  "Instrumentation (local or remote)",
    "T1053":     "scheduled or one-shot task execution as any user the "
                  "scheduler can impersonate (often SYSTEM)",
    "T1053.003": "Linux/macOS cron-driven scheduled execution",
    "T1053.005": "Windows Task Scheduler execution (local or remote, "
                  "often as SYSTEM)",
    "T1059":     "arbitrary command execution via any installed "
                  "interpreter (shells, scripting languages)",
    "T1059.001": "PowerShell command + script-block execution with the "
                  "current user's privileges",
    "T1059.003": "Windows cmd.exe command execution",
    "T1059.004": "Unix shell (bash/zsh/sh) command execution",
    "T1059.005": "Visual Basic / VBScript execution (legacy Office, "
                  "Windows Script Host)",
    "T1203":     "arbitrary code execution via client-application "
                  "vulnerability (browser, document parser, IM)",
    "T1204.002": "arbitrary code execution via user opening a "
                  "malicious file (double-click delivery payload)",
    "T1569":     "remote service-control execution (PSExec-class "
                  "tools, sc.exe, Service Control Manager abuse)",
    "T1569.002": "remote service-creation execution (PSExec-style "
                  "binary planted + started as a Windows service)",
    "T1609":     "container administration command (kubectl exec, "
                  "docker exec, runtime-direct shell into a pod)",
    # ----- Persistence ---------------------------------------------------
    "T1098":     "account-permission modification for persistent "
                  "access (group membership, additional credentials)",
    "T1098.001": "cloud-account additional credentials (access keys, "
                  "passwords, SSH keys added to existing accounts)",
    "T1098.003": "global-admin / domain-admin role grant",
    "T1098.004": "SSH authorised_keys append for persistent access",
    "T1098.007": "additional local-account credentials added to an "
                  "existing principal",
    "T1136":     "new local or domain account created for persistent "
                  "access",
    "T1136.001": "new local Windows account for persistent access",
    "T1197":     "background intelligent transfer service (BITS) "
                  "abuse — file download/execution + persistence",
    "T1543":     "system process / service / launch-item creation for "
                  "boot-survival",
    "T1543.001": "macOS LaunchAgent (per-user, runs on login)",
    "T1543.003": "Windows service creation (runs at boot or on demand "
                  "as SYSTEM)",
    "T1543.004": "macOS LaunchDaemon (system-wide, runs at boot as "
                  "root)",
    "T1546.003": "WMI event-consumer registration (fires on system "
                  "events — boot, logon, interval timer)",
    "T1547":     "boot- or logon-time autostart via OS-blessed "
                  "registry/path entries",
    "T1547.001": "Windows Run/RunOnce registry key autostart",
    "T1574":     "DLL search-order hijack / sideload (legitimate "
                  "process loads attacker-controlled library)",
    "T1574.001": "DLL search-order hijack via missing dependency",
    # ----- Privilege Escalation -----------------------------------------
    "T1055":     "in-process code execution via injection into a "
                  "trusted process (often SYSTEM-level)",
    "T1055.001": "DLL injection into a trusted running process",
    "T1055.012": "process hollowing — replace the image of a trusted "
                  "process while it's loading",
    "T1068":     "kernel- or driver-level code execution via local "
                  "privilege-escalation vulnerability",
    "T1611":     "container-to-host breakout via runtime / kernel "
                  "vulnerability — root on the host node",
    # ----- Defense Evasion ----------------------------------------------
    "T1014":     "rootkit — kernel-mode driver or hooking that hides "
                  "processes, files, drivers, or network connections from "
                  "the OS and security tools",
    "T1027":     "obfuscated / packed / encoded payload that evades "
                  "static signature-based detection",
    "T1036":     "process / file / service masquerading as a trusted "
                  "system component",
    "T1036.005": "image-name masquerade (lsass.exe etc.) in a non-"
                  "system path",
    "T1070":     "host-side log / artifact deletion to defeat "
                  "investigation",
    "T1070.001": "Windows Event Log clearing (wevtutil cl, EventLog "
                  "service stop+delete)",
    "T1070.004": "file deletion to remove dropped tooling / staged "
                  "data after use",
    "T1070.006": "timestomp — set MACB timestamps to evade time-"
                  "windowed investigation",
    "T1112":     "registry-value modification for evasion / "
                  "persistence concealment",
    "T1140":     "in-memory decoding of obfuscated payload before "
                  "execution",
    "T1218":     "execution proxied through a Windows-signed binary "
                  "(rundll32, regsvr32, mshta — LOLBins)",
    "T1497":     "VM / sandbox / debugger evasion at runtime",
    "T1562":     "security-tooling impairment (AV/EDR/host firewall "
                  "stop, registry tamper, eventlog disable)",
    "T1610":     "deploy attacker-controlled container into the "
                  "orchestrator as a pivot",
    # ----- Credential Access --------------------------------------------
    "T1003":     "OS credential dumping — LSASS memory, SAM/SYSTEM "
                  "hives, NTDS.dit, DPAPI master keys, lsasrv private "
                  "secrets",
    "T1003.001": "LSASS process memory dump (mimikatz-class extraction "
                  "of cleartext / NT hashes / Kerberos TGT/TGS)",
    "T1003.002": "Security Account Manager (SAM) database extraction "
                  "— local-account NT hashes",
    "T1003.003": "NTDS.dit extraction (domain-controller — every "
                  "domain account NT hash + history)",
    "T1003.006": "DCSync via replication-protocol abuse (no need to "
                  "touch the DC's filesystem)",
    "T1110":     "credential brute-force / spray against any auth "
                  "endpoint (RDP, SMB, web login, Kerberos)",
    "T1110.001": "single-account password guessing",
    "T1110.003": "password spray — one password tried against many "
                  "accounts to evade lockout",
    "T1552":     "credentials at rest in files / registry / source "
                  "control (AWS access keys, .ssh keys, vault.json)",
    "T1552.001": "credentials in files at rest (rootkey.csv, "
                  ".aws/credentials, configs)",
    "T1555":     "credentials from password stores (browser saved "
                  "passwords, Keychain, KWallet, lastpass dump)",
    "T1555.003": "browser-stored credentials (Chrome/Edge Login Data, "
                  "Firefox logins.json)",
    "T1556":     "authentication-process tamper for credential capture "
                  "(custom LSA package, password filter)",
    "T1558":     "Kerberos ticket request / forge abuse",
    "T1558.003": "Kerberoasting — request RC4 service tickets for "
                  "SPNs and offline-crack the encrypted blob",
    # ----- Discovery -----------------------------------------------------
    "T1018":     "remote-host enumeration (net view, nltest, AD ldap "
                  "query, Bloodhound graph)",
    "T1033":     "logged-in user enumeration",
    "T1046":     "network service discovery (port scan, nmap, custom "
                  "tcp scanner)",
    "T1057":     "running-process enumeration",
    "T1069":     "permission / group / role enumeration",
    "T1082":     "system information discovery (hostname, OS version, "
                  "patch level, hardware)",
    "T1083":     "filesystem / directory enumeration",
    "T1087":     "account enumeration (local users, domain users, "
                  "cloud principals)",
    "T1135":     "network share discovery (net view \\\\host, smb "
                  "enumeration)",
    "T1613":     "container + image + registry enumeration",
    # ----- Lateral Movement ---------------------------------------------
    "T1021":     "remote service authentication into another host "
                  "(RDP, SMB, WinRM, SSH, VNC)",
    "T1021.001": "RDP into another host using captured credentials",
    "T1021.002": "SMB/admin-share access into another host (file copy "
                  "+ remote service execution)",
    "T1021.006": "PowerShell Remoting (WinRM) into another host",
    "T1550":     "alternate authentication material reuse (pass-the-"
                  "hash, pass-the-ticket, OAuth token replay)",
    "T1550.002": "pass-the-hash — authenticate with NT hash instead of "
                  "cleartext password",
    "T1550.003": "pass-the-ticket / overpass-the-hash — replay a "
                  "Kerberos TGT/TGS",
    # ----- Collection ---------------------------------------------------
    "T1005":     "local data of interest collected from the filesystem "
                  "(documents, source code, configs)",
    "T1056":     "user input capture (keylogger, browser-form grab, "
                  "credential prompt overlay)",
    "T1056.001": "keylogger — record every keystroke",
    "T1074":     "data staged in a local directory before exfil",
    "T1074.001": "local data staging in a known temp/cache location",
    "T1113":     "screen capture",
    "T1119":     "automated collection of staged data (script that "
                  "walks files, classifies, prepares for exfil)",
    "T1213":     "data from internal repository (SharePoint, Confluence, "
                  "Jira, GitLab)",
    "T1530":     "data from cloud storage (S3, Azure Blob, GCS bucket)",
    "T1534":     "internal spear-phishing / lateral phish from a "
                  "compromised mailbox to other users",
    # ----- Command and Control ------------------------------------------
    "T1071":     "covert application-layer C2 over allowed outbound "
                  "protocols (HTTP/S, DNS, SMTP)",
    "T1071.001": "covert C2 over HTTP/HTTPS — blends with normal web "
                  "traffic",
    "T1071.004": "covert C2 over DNS — queries/responses encode "
                  "commands + data",
    "T1090":     "outbound traffic proxied through an intermediary "
                  "(internal-pivot proxy, external Tor)",
    "T1090.003": "outbound traffic routed through multi-hop anonymity "
                  "network (Tor)",
    "T1102":     "C2 channel hidden inside a legitimate web service "
                  "(Dropbox, GitHub gist, Twitter, Pastebin)",
    "T1105":     "additional tool transfer over the C2 channel (drop "
                  "second-stage payload)",
    "T1571":     "C2 over a non-standard port — evades port-based ACLs "
                  "but still uses a standard protocol",
    "T1573":     "encrypted-channel C2 (symmetric- or asymmetric-key "
                  "tunnel over arbitrary transport)",
    # ----- Exfiltration -------------------------------------------------
    "T1041":     "exfiltration over the existing C2 channel — no "
                  "second connection to detect",
    "T1048":     "exfiltration over an alternative protocol (separate "
                  "channel from the C2)",
    "T1052":     "exfiltration over physical medium (USB drive, "
                  "external HDD, optical disc)",
    "T1052.001": "exfiltration over USB removable media",
    "T1567":     "exfiltration to a third-party web service (cloud "
                  "storage / paste site / personal webmail)",
    "T1567.002": "exfiltration to cloud-storage service (Dropbox, "
                  "GoogleDrive, OneDrive, Box)",
    # ----- Discovery (additional) ---------------------------------------
    "T1016":     "network configuration discovery (ipconfig / ip a / "
                  "route / DNS settings)",
    "T1039":     "data collection from network shared drives",
    "T1595":     "external active reconnaissance (host scan, web "
                  "spider, vulnerability scanner against targets)",
    "T1620":     "in-process reflective code loading (DLL/PE mapped "
                  "from memory without disk write)",
    "T1622":     "debugger / instrumentation detection at runtime",
    # ----- Mobile-only --------------------------------------------------
    "T1404":     "mobile privilege escalation (root / jailbreak)",
    "T1444":     "mobile masquerading as legitimate app for sideload",
    "T1462":     "mobile carrier-network exploitation (rogue base "
                  "station / SS7 abuse)",
    "T1478":     "mobile installation of insecure / unapproved root "
                  "certificate to intercept TLS",
    "T1481":     "mobile C2 over web service (cloud message broker, "
                  "social-media DM, push-notification channel)",
    # ----- Email / collection (additional) ------------------------------
    "T1114.002": "remote mailbox access (IMAP/EWS/Graph against a "
                  "remote server using captured credentials)",
    "T1114.003": "mail-forwarding rule that silently sends incoming "
                  "messages to an attacker-controlled inbox",
    "T1565.001": "stored-data tamper (file content modified at rest "
                  "to mislead investigation or downstream automation)",
    # ----- Persistence (additional) -------------------------------------
    "T1505.003": "Exchange / IIS / web-server module backdoor (web "
                  "shell or transport-agent code that survives reboot)",
    "T1564.001": "hidden file / directory attribute used to conceal "
                  "tooling from casual filesystem inspection",
    "T1564.004": "NTFS alternate data stream used to conceal payload "
                  "or staged data",
    "T1564.008": "hidden mail-folder rule used to silently divert / "
                  "delete responses",
    # ----- Privilege Escalation (additional) ----------------------------
    "T1548.002": "Windows UAC bypass (auto-elevate trusted binary, "
                  "fodhelper / sdclt token-piggyback, COM hijack)",
    "T1548.003": "Linux setuid / setgid abuse to escalate from user "
                  "to root",
    "T1548.006": "Linux capability abuse (CAP_SYS_ADMIN, CAP_NET_ADMIN "
                  "granted to a binary the operator can run)",
    # ----- C2 / Lateral (additional) -------------------------------------
    "T1095":     "non-application-layer C2 (raw TCP, ICMP, custom "
                  "protocol that doesn't look like HTTP/DNS/etc.)",
    "T1219":     "remote-access software (TeamViewer, AnyDesk, ScreenConnect "
                  "— legitimate tool used as backdoor)",
    "T1528":     "OAuth application consent grant — the user "
                  "approved a malicious app's access to their account",
    "T1537":     "data transfer to attacker-controlled cloud account "
                  "via cloud-native sync (cross-tenant copy)",
    "T1568.001":  "fast-flux DNS (rapid IP rotation to evade IP-based "
                   "blocklisting of C2)",
    "T1568.002":  "domain-generation-algorithm (DGA) C2 resolution",
    "T1570":      "lateral tool transfer — push payload from foothold "
                   "to a peer host via the existing access",
    "T1572":      "C2 over a tunnelled protocol (SSH/SOCKS/HTTP proxy "
                   "tunnel hiding the real traffic underneath)",
    # ----- Impact -------------------------------------------------------
    "T1485":     "destructive file deletion (data destruction)",
    "T1561":     "disk wipe — zeroing the partition table / boot sectors "
                  "or overwriting volume contents to destroy the disk",
    "T1486":     "file encryption for impact (ransomware)",
    "T1490":     "inhibit system recovery (delete shadow copies, "
                  "disable Windows backup, wipe restore points)",
    "T1489":     "service-stop for impact (kill databases / backups "
                  "before encryption)",
    "T1496":     "compute-resource hijack (cryptominer, password-"
                  "cracker, distributed-compute abuse)",
    "T1531":     "account-access removal (delete / disable / change "
                  "passwords to lock the legitimate user out)",
}


def capacity_for(technique_id: str) -> str | None:
    """Return the plain-English Capacity line for *technique_id*,
    or None when there's no mapping.

    Looks up the full sub-technique first; if absent, falls back to
    the parent technique (so e.g. T1059.099 falls back to T1059's
    capacity). Returns None — not a placeholder string — when both
    lookups fail; callers can choose to emit a tactic-level
    placeholder or skip the technique entirely.
    """
    if not technique_id:
        return None
    if technique_id in TECHNIQUE_CAPACITY:
        return TECHNIQUE_CAPACITY[technique_id]
    # Sub-technique fallback to parent — T1003.099 → T1003
    if "." in technique_id:
        parent = technique_id.split(".", 1)[0]
        if parent in TECHNIQUE_CAPACITY:
            return TECHNIQUE_CAPACITY[parent]
    return None


# Coverage check — must round-trip every technique ID in
# attack_tactics.TECHNIQUE_TACTIC (the canonical EL-emitted set).
# Used by the test to enforce that new technique mappings get a
# capacity entry too.
def uncovered_techniques() -> list[str]:
    """Return technique IDs from TECHNIQUE_TACTIC that have no
    Capacity mapping (neither direct nor parent fallback). Used by
    test_attack_capacities.py to fail when a new EL-emitted
    technique was added without a capacity line."""
    return sorted(
        tid for tid in TECHNIQUE_TACTIC
        if capacity_for(tid) is None
    )
