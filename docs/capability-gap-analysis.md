# EL Capability Gap Analysis — SANS Poster Review

_Synthesis of 18 SANS DFIR posters (FOR500, FOR508, FOR509, FOR510,
FOR572, FOR585, FOR610, SEC542, Detection Engineering, CTI, Memory
Forensics cheatsheet, Windows Forensic Analysis Playbook, SIFT
Cheatsheet, Windows Apps, Linux IR/TH, Intelligence Analysts Playbook,
DFIR-CTI trifold, DFIR START). Written 2026-04-21._

EL was compared against each poster to identify concrete additions —
specific artifact paths, tool names, vol3 plugins, Event IDs, protocol
analyses, cloud log sources, rule formats. Scope was limited to items
within EL's design philosophy (tool-output-as-evidence, rule-based
detectors, Heuer ACH). macOS/APFS (FOR518) and Mobile (FOR585)
intentionally excluded — those would be greenfield subprojects, not
extensions.

## Top 6 picks (highest leverage per unit of effort)

**1. SIGMA rule ingestion** — single biggest force multiplier. The
SigmaHQ community rule library has thousands of Windows/Linux/cloud
detection rules in portable YAML. EL already has the target log
streams (EvtxECmd CSV, Zeek logs, Suricata alerts). A
`sigma_engine` skill + new `SigmaAnalystAgent` that loads a rule pack
and applies it to those streams would multiply our attack-pattern
coverage by orders of magnitude without hand-writing detectors. Tag
each resulting Finding with the Sigma rule ID and MITRE technique.
Complements the rule-based Red Reviewer — deterministic, grounded,
auditable.

**2. Kerberos wire-level analysis** — corroborates our EVTX-based
Kerberoasting detector at the network layer. AS-REQ / AS-REP /
TGS-REQ / TGS-REP extraction from pcap with RC4-HMAC flagging fires
even when audit logs are disabled or cleared (we saw EID 1102
log-clear six times in SRL-2018). Fits inside the existing
`network_analyst` via Zeek's `kerberos.log` or a scapy parser.

**3. M365 Unified Audit Log + Azure Sign-in Logs** — largest
cloud gap. EL only does AWS CloudTrail. Identity is the modern
breach surface; M365 UAL and Entra sign-in logs capture BEC,
MFA-bypass, OAuth consent abuse, anomalous-geography auth. JSON
ingestion, same shape as our existing `cloudtrail` skill. New
`cloud_identity` agent or extension of `cloud_forensicator`.

**4. Windows Timeline (ActivitiesCache.db) + BAM/DAM** — two
first-class user-activity artifacts already within
`extract_windows_artifacts` reach. `ActivitiesCache.db` is a SQLite
DB at `%LOCALAPPDATA%\ConnectedDevicesPlatform\L.<user>\` that
records every foreground app + document touched. BAM/DAM lives at
`SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` and
records every executable run per user. Both parse trivially.

**5. PowerShell ScriptBlock decoded extraction** — we count EID 4104
today but don't decode the payload. Real attacker usage is near-always
obfuscated (base64 + gzip + IEX). Decoding + pattern-matching on the
decoded script (Mimikatz sentinels, EncodedCommand, Invoke-Expression
pipelines, URL downloaders) is high-signal and self-contained.

**6. `capa` + `FLOSS` integration for `malware_triage`** — migrate
from our 14-family fingerprint library to capability enumeration
tied directly to MITRE ATT&CK (capa outputs ATT&CK techniques per
binary). Dumped `malfind --dump` regions + extracted PE droppers
become structured capability findings.

## Category-by-category additions (prioritized within each)

### Windows artifact coverage

**High priority (already inside EZ Tools or SIFT tool reach):**
- `ActivitiesCache.db` — Windows 10/11 Timeline. SQLite. WxTCmd parser exists in SIFT.
- BAM/DAM subtree — parsed by RECmd with the Kroll batch; just not surfaced as a per-finding.
- RecentDocs / OpenSave-MRU under `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer` — same.
- CapabilityAccess — `SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore` — app permissions audit.
- Volume Shadow Copy mounting via `vss_carver` (SIFT alias already exists on host) to run the same disk pipeline against snapshots.
- User Access Log (UAL) on Windows Server — `C:\Windows\System32\LogFiles\Sum\*.mdb` — per-user service access.

**Medium:**
- Windows Error Reporting (WER) queue — `%ProgramData%\Microsoft\Windows\WER\ReportQueue\` — crashes often coincide with exploitation.
- Recycle Bin metadata (RBCmd wrapper exists, just re-surface).
- Thumb caches (carve embedded JPEGs for file-of-interest corroboration).
- SmartScreen data.

**Highest-impact single add:** `ActivitiesCache.db` parser — fires every case with user activity and cross-correlates with execution artifacts.

### Memory forensics (vol3 plugin set expansion)

Every plugin below is already in vol3; EL just doesn't run it.

**High:**
- `windows.modules.Modules` + `windows.modscan.ModScan` — loaded vs. pool-scanned kernel drivers. Rootkit detection via the diff.
- `windows.ldrmodules.LdrModules` — three-list DLL diff (`InLoad`/`InInit`/`InMem`). Flags unlinked DLLs.
- `windows.handles.Handles` — open file / pipe / key handles. Identifies which process holds a staging file.
- `windows.getsids.GetSIDs` — per-process SIDs. Completes the process-anomaly matrix (user account check we explicitly defer today).

**Medium:**
- `windows.ssdt.SSDT` + `windows.driverirp.DriverIRP` — kernel-mode hook detection.
- `windows.dumpfiles.DumpFiles` + `windows.filescan.FileScan` — carve files out of memory (essential for exfil reconstruction).
- `windows.mftscan.MFTScan` — reconstruct filesystem from memory when no disk image is available.
- `yarascan` — scan the raw memory image with our generated YARA rules (we YARA the dumped malfind regions but not the parent image).

**Highest-impact single add:** `windows.modules.Modules` + `modscan` for rootkit / unlinked-driver detection.

### Malware RE / static analysis

- **`capa`** (Mandiant) — ATT&CK capability extraction on binaries. Tag Findings with the technique IDs it returns.
- **`FLOSS`** — decode obfuscated strings (stacked-strings, tight-loop encodes).
- **`Detect-It-Easy`** / `diec` — packer + compiler detection.
- `pefile` wrapper — Rich Header, imphash, per-section entropy, anomalous imports (lsass handle APIs, memory APIs, process APIs).
- `ssdeep` / `tlsh` — fuzzy hashing for family attribution across cases.
- VBA / XLM / PDF object-stream deobfuscators (`olevba`, `pcodedmp`, `xlmdeobfuscator`, `rtfobj`, `pdfparser`) — office-doc droppers.

**Highest-impact single add:** `capa` integration — direct ATT&CK-technique corroboration on every dumped PE.

### Network forensics depth

- **Kerberos protocol parsing** from pcap — AS-REQ / AS-REP / TGS-REQ / TGS-REP, RC4-HMAC flagging. Complements PR-E at the network layer.
- SMB2 write-operation detection — lateral file-staging visibility.
- DHCP option 55 fingerprinting — device discovery from DHCP leases.
- DGA detection via domain-label entropy + n-gram model.
- DNS tunneling detection — query-size anomaly, special record types (TXT/NULL), NXDOMAIN burst, high-frequency unique labels.
- NetFlow / IPFIX / AWS VPC Flow Log ingestion.
- Passive DNS historical correlation (pDNS feed via Farsight or equivalent).
- TLS JA3/JA4 fingerprint + Umbrella-top-1M allowlisting for noise reduction.

**Highest-impact single add:** Kerberos wire parsing — catches Kerberoasting + golden-ticket indicators without requiring Windows audit.

### Detection engineering

- **SIGMA rule ingestion** (top pick).
- MITRE CAR analytic import (sibling format to Sigma).
- Rule-tagging metadata (experimental / test / production) for the local challenger rule set.
- Threat-intel feed enrichment — MISP / OTX TAXII client for pre-enrichment of extracted IOCs.
- Forward/reverse DNS enrichment on IP-only IOCs.
- Long-tail statistical anomaly scoring — an IOC's rarity in the cross-case knowledge DB becomes a confidence modifier.

**Highest-impact single add:** SIGMA rule loader + applier.

### Command-line / PowerShell forensics

- PowerShell ScriptBlock (EID 4104) — decoded payload + malicious pattern match.
- Transcription logs under `Documents\PowerShell_transcript_*.txt`.
- Module logging (EID 4103) parameter-level audit.
- PSReadline history at `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.
- Windows clipboard history.
- cmd.exe DOSKEY history (rare, only if enabled).
- Linux shell histories — `.bash_history`, `.zsh_history`, `.mysql_history`, `.python_history`, `.lesshst`, `.viminfo`.

**Highest-impact single add:** ScriptBlock decoding + malicious-pattern scan.

### Cloud forensics expansion

- **M365 Unified Audit Log** (JSON; `Get-UnifiedAuditLog` export).
- **Azure Sign-in Logs** and Azure Activity Logs (Entra/AAD JSON export).
- **GCP Cloud Audit Log** subtypes: Admin Activity, Data Access, System Event, Policy Denied.
- **Google Workspace** Admin Audit, OAuth events, Drive audit, Gmail audit.
- AWS VPC Flow Logs + AWS GuardDuty findings.
- Azure Storage + GCP Cloud Storage access logs.

**Highest-impact single add:** M365 Unified Audit Log — biggest identity-compromise blind spot today.

### Application artifacts (Windows-Apps poster)

Pick candidates by prevalence on enterprise endpoints:

- **Microsoft Teams** IndexedDB / LevelDB — `%APPDATA%\Microsoft\Teams\`
- **Slack** — `%APPDATA%\Slack\` (IndexedDB + Local Storage + logs)
- **Microsoft Edge** User Data — same Chrome-shaped SQLite schema
- **OneDrive** client state + `SyncEngine.log`
- **Dropbox** `sync_history.db`, `config.dbx`
- **TeamViewer** `connections_incoming.txt` + log files
- **AnyDesk** `connection_trace.txt` + `*.trace`
- Discord, Viber, Evernote, 1Password (credentials DB existence, not content).

**Highest-impact single add:** TeamViewer + AnyDesk parsers — lightweight; detection of unauthorized remote-access tools is high-signal-for-low-code.

### Linux forensics (new agent territory)

If Linux disk/memory images are in the pipeline, a `LinuxForensicator`
agent parallel to `DiskForensicator`:

- auditd — `/var/log/audit/audit.log` via `aureport` / `ausearch`.
- systemd journal — `/var/log/journal/` binary — `journalctl` wrapper.
- Auth logs — `/var/log/auth.log`, `/var/log/secure`, `utmp/wtmp/btmp`.
- Shell histories (per-user).
- Cron — `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron`.
- SSH — `authorized_keys`, `known_hosts`, historical `ssh_config`.
- `/etc/ld.so.preload` — classic library-injection persistence.
- Package manager — `/var/log/apt/history.log`, `/var/log/dpkg.log`, `/var/log/yum.log`.
- Webserver — nginx / Apache access logs with anomaly detection for unusual UAs.
- Rootkit scanners — `chkrootkit`, `rkhunter`, Lynis.

**Highest-impact single add:** `auditd` parser + `ld.so.preload` persistence detector.

### CTI / intel methodology

- STIX 2.1 **import** (we only export) — ingest threat feeds into the knowledge DB with provenance tag `{source: external_feed}`.
- MISP / TAXII client for pull.
- Diamond Model activity grouping (Rule of 2) as a Kùzu graph view.
- Admiralty-code source-reliability tags on evidence.
- Key Assumptions Check structured-technique template in reports.
- Formal ACH matrix markdown export (consistency × inconsistency grid per hypothesis).
- Passive DNS + TLS cert-reuse pivoting for infrastructure correlation.

**Highest-impact single add:** STIX 2.1 import so external threat feeds enrich the cross-case IOC store without hand-curation.

## Deliberately out of scope (would be separate subprojects)

- **macOS / APFS forensics (FOR518)** — new disk agent, new plugin set for HFS+/APFS, distinct tool chain. Viable as a follow-up project; not a simple extension.
- **Mobile (FOR585 Android/iOS)** — same. Would need Cellebrite/Magnet-format image readers, iOS backup parsers, Android ADB collection; separate value-stream.
- **Web-app pentesting (SEC542)** — offensive, not defensive forensics. Out of EL's charter.

## Pre-ranked shortlist for follow-up sessions

| Tier | Addition | Reason |
|---|---|---|
| 1 | SIGMA rule ingestion | Force-multiplier; applies to streams we already produce |
| 1 | Kerberos wire parsing | Cross-layer corroboration; survives log clearing |
| 1 | M365 UAL + Azure Sign-in | Biggest cloud blind spot; identity = modern breach vector |
| 2 | ActivitiesCache.db + BAM/DAM | Trivial addition; high per-case signal |
| 2 | PowerShell 4104 decoded | We see the count; we should see the content |
| 2 | `capa` + `FLOSS` | ATT&CK on dumped binaries; replaces brittle fingerprint strings |
| 3 | vol3 modules / modscan / ldrmodules / handles / getsids | Rootkit + process-anomaly completeness |
| 3 | Linux forensics agent | Depends on whether Linux evidence is expected |
| 3 | Teams / Slack / OneDrive parsers | Frequent on enterprise endpoints |
| 4 | Diamond Model / ACH matrix export | Reporting polish |
| 4 | STIX 2.1 import + MISP/TAXII | Knowledge-DB enrichment |

None of these are committed to. They're a menu informed by the posters;
shakedown evidence on the next real cases should still drive ordering.
