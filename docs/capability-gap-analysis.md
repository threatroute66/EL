# EL Capability Gap Analysis — SANS Poster Review

_Synthesis of 18 SANS DFIR posters (FOR500, FOR508, FOR509, FOR510,
FOR572, FOR585, FOR610, SEC542, Detection Engineering, CTI, Memory
Forensics cheatsheet, Windows Forensic Analysis Playbook, SIFT
Cheatsheet, Windows Apps, Linux IR/TH, Intelligence Analysts Playbook,
DFIR-CTI trifold, DFIR START). Written 2026-04-21._

EL was compared against each poster to identify concrete additions —
specific artifact paths, tool names, vol3 plugins, Event IDs, protocol
analyses, cloud log sources, rule formats. Scope covers items within
EL's design philosophy (tool-output-as-evidence, rule-based detectors,
Heuer ACH). Web-app pentesting (SEC542) is the only domain left out —
it's offensive, not defensive forensics, and doesn't fit the charter.
macOS/APFS and Mobile *are* in scope (see those sections below for
concrete agent + skill outlines).

## Top 6 picks (highest leverage per unit of effort)

**1. SIGMA rule ingestion** — ✅ **SHIPPED.** Native evaluator in
`el.skills.sigma_engine` + `SigmaAnalystAgent` wired after
`CredentialAnalystAgent`. Supports the modifier set covering ~90% of
community Windows rules (`contains`, `startswith`, `endswith`, `re`,
`all`, `cased`, `gt/gte/lt/lte`) and the full condition grammar
(`and` / `or` / `not` / parens / `1 of X` / `all of X` with wildcards).
MITRE ATT&CK techniques extracted from rule tags; tag-to-hypothesis
map lifts `H_CREDENTIAL_ACCESS` from `attack.credential_access`, etc.
`EventID`-indexed pre-filter keeps per-row cost small on large CSVs.
Real-data validation: the RC4 Kerberoasting starter rule fires 124
times on `srl-dc-disk-r3`, exactly matching the `credential_analyst`
count from PR-E — cross-layer corroboration confirmed.

**2. Kerberos wire-level analysis** — ✅ **SHIPPED.** New
`el.skills.kerberos_triage` over Zeek's `kerberos.log` + three
detectors wired into `network_analyst._run_kerberos_triage`:
RC4-HMAC TGS-REQ (Kerberoasting), AS-REQ failure burst
(brute force + password spray), `krbtgt/` service in TGS-REQ
(golden-ticket smell). Mirrors the EVTX `credential_analyst` at
the wire layer; fires even when Windows auditing is disabled or
cleared. Technique-to-hypothesis map lines up with PR-E so ACH sees
cross-layer reinforcement.

**3. M365 Unified Audit Log + Azure Sign-in Logs** — ✅ **SHIPPED.**
`cloud_forensicator` now sniffs the input shape and dispatches across
AWS CloudTrail (existing), Azure Entra sign-in logs, and M365 UAL.
Two new skills:
- `el.skills.azure_signin` — 4 detectors: sign-in brute / spray,
  legacy-auth bypass (IMAP / POP3 / SMTP / EAS / older Office
  clients — all MFA bypasses on success), Entra risk-classifier
  trigger (`riskLevelAggregated=high` or `riskState=atRisk`),
  impossible travel (same principal, two countries, 60-min window).
- `el.skills.m365_audit` — 4 detectors: inbox-rule external forward
  (BEC persistence; tenant-domain anchor supported), MailItemsAccessed
  bulk (≥50 per user — post-compromise scraping), OAuth consent
  grant (illicit-consent attack surface), UserLoginFailed burst with
  brute / spray tiers matching PR-E.
Tenant domains supplied via `ctx.shared["tenant_domains"]` for
accurate external-forward detection. Silent-dispatch when input
isn't a known cloud-log shape.

**4. Windows Timeline (ActivitiesCache.db) + BAM/DAM** — ✅ **SHIPPED.**
Two new skills consumed by `WindowsArtifactAgent`:
- `el.skills.bam_dam` — walks `SYSTEM\\ControlSet00{1,2}\\Services\\{bam,dam}\\[State\\]UserSettings\\<SID>` via regipy (new pure-Python dep). Decodes the 8-byte FILETIME prefix in each REG_BINARY into per-user last-run timestamps; surfaces entries whose executable path sits in Temp / AppData / Downloads / ProgramData / Public as a dedicated high-confidence finding.
- `el.skills.win_timeline` — reads `ActivitiesCache.db` as SQLite (URI `mode=ro&immutable=1` so evidence stays untouched). Parses `AppId` JSON to extract both packaged PFNs and Win32 paths; normalises `Payload` to surface `displayText`, `activationUri`, `appPath`. Same suspicious-path overlay emits a second finding.
- `extract_windows_artifacts` extended to walk `<user>\\AppData\\Local\\ConnectedDevicesPlatform\\L.*\\` and copy `ActivitiesCache.db[-wal/-shm]` into `exports/windows-artifacts/timeline/` with per-user filename prefixes.
Real-data validation: `bam_dam.parse_system_hive` on the SRL-2018 wkstn-01 SYSTEM hive returns 39 entries across 5 SIDs (all UWP packages — that machine had no attacker-invoked binaries, so the suspicious overlay correctly stays silent).

**5. PowerShell ScriptBlock decoded extraction** — ✅ **SHIPPED.**
`el.skills.powershell_triage` pulls every EID 4104 row out of the
EvtxECmd CSV, lifts `ScriptBlockText` out of the prefix EvtxECmd
adds, finds inline base64 blobs, and decodes them (plain base64 →
text, plus gzip wbits 31/-15/15 for `IO.Compression.GZipStream`
cradles). Pattern families: Mimikatz (`Invoke-Mimikatz`,
`sekurlsa::`, `kerberos::`, `lsadump::`), AMSI bypass
(`AmsiUtils`, `amsiInitFailed`, `PatchAmsi`), and download cradles
(`Net.WebClient.DownloadString`, `IEX (New-Object …)`). Emits
per-family `PSHit` rows consumed by `PowerShellAnalystAgent` →
Findings tagged H_CREDENTIAL_ACCESS / H_APT_ESPIONAGE /
H_LIVING_OFF_THE_LAND.

**6. `capa` + `FLOSS` integration for `malware_triage`** — ✅ **SHIPPED
(mostly already there, now actually working).** capa + FLOSS subprocess
wrappers already existed; they were silent because (a) capa ships
without rules when installed as a library and (b) `_run_capa` skipped
every raw-shellcode dump. Fixed both:
- `el.skills.capa._rules_dir()` resolves a rule pack from
  `EL_CAPA_RULES` → `/opt/EL/rules/capa/` (documented in
  `docs/capa-rules.md`; directory gitignored so upstream clones drift
  independently).
- `analyze()` injects `-r <rules>` when a pack resolves.
- `malware_triage._run_capa` now runs on shellcode dumps with
  `--format sc<arch>` (reads `ctx.shared["mem_arch"]`; defaults to
  `sc64`). Real-data proof: `srl-admin-memory/pid.8884.vad.…dmp` now
  yields 5 capability rules + T1027 obfuscation attribution (was 0
  before because capa silently exited with no rules loaded).

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
- `windows.ssdt.SSDT` + `windows.driverirp.DriverIRP` — kernel-mode hook detection. ✅ Shipped.
- `windows.filescan.FileScan` ✅ + `windows.mftscan.MFTScan` ✅ + `windows.dumpfiles.DumpFiles` ✅ shipped. Dumpfiles runs against malfind-flagged PIDs via `memory_forensicator._carve_dumpfiles` with an 8-PID cap (caps runtime on big workstation images); carved DLL / EXE handles feed the threat_hunter YARA sweep.
- ✅ **`windows.vadyarascan.VadYaraScan`** — shipped via `el.skills.vol3.yarascan()` + `threat_hunter._vol3_yarascan`. Process-attributed YARA matches (PID + ImageFileName + VA). Volume-noise suppression: rules firing ≥10× the case median (or ≥1000 absolute) auto-downgrade to LOW with no hypothesis lift, so generic Windows-DLL substrings can't drown real C2 hits. Validated against `srl2018-admin-memory` — `shieldbase.lan` × 9,822 + `1.3.33.17` × 40 surfaced as in-process hits.

**Highest-impact single add:** `windows.modules.Modules` + `modscan` for rootkit / unlinked-driver detection.

### Malware RE / static analysis

- ✅ **`capa`** + **`FLOSS`** — both shipped (see Top-6 #6).
- ◐ **`Detect-It-Easy`** / `diec` — packer + compiler detection: skill module `el.skills.detect_it_easy` exists but is **not yet wired into any agent** (no importer in `el/agents/`). Wrapper-done, consumer-pending.
- ✅ **`pefile`-deep wrapper** — `el.skills.pefile_deep` shipped: Rich Header, imphash + cross-case clustering, per-section entropy (packed-section flag), anomalous-import sensitive-API groups (lsass handles, memory APIs, process APIs) → ATT&CK technique tags. Wired into `MalwareTriageAgent._run_pefile_deep`.
- ✅ **`ssdeep`** + **`TLSH`** — both shipped via `el.skills.similarity_digest` + `knowledge.fuzzy_hashes` (`tlsh` column added with auto-migration on legacy DBs). Cross-case malware-family clustering: ssdeep lookup at threshold 20 (Roussev marginal), TLSH lookup at distance ≤70 (Trend Micro same-family); a TLSH match at distance ≤30 (very-close-variant) bumps confidence to medium.
- ✅ **`olevba`** + **`rtfobj`** shipped via `el.skills.office_deobf`. `pcodedmp` / `xlmdeobfuscator` / `pdfparser` still open.

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

### macOS / APFS forensics (FOR518)

EL's abstractions are OS-agnostic: `Triage` already routes by
`evidence_kind`, the `MemoryForensicator` has a `family` branch point,
and vol3 already ships `mac.*` plugins. Extension, not greenfield.

**Triage additions** — evidence-kind detectors for:
- `apfs_disk_image` — magic `NXSB` at offset `0x20` of container superblock
- `dmg` / `sparseimage` — Apple disk image wrappers
- `macos_memory` — vol3 banner match for xnu / Darwin kernel
- `ios_backup` — presence of `Manifest.mbdb` or `Manifest.db`

**New skills (all Python-scriptable or subprocess-wrapped):**
- `apfs_fuse` — FUSE mount wrapper around the community `apfs-fuse` binary (read-only, unencrypted containers)
- `mac_apt_skill` — wrap the open-source `mac_apt` (MIT, Python) which already extracts KnowledgeC.db, Unified Logs, plists, FSEvents, Spotlight metadata, MRU lists
- `plist_triage` — native `plistlib` parser for `*.plist`, binary + XML
- `unified_log_parse` — wrap `log show --style json` (requires a macOS host) OR the `UnifiedLogReader` Python tool
- `knowledgec_parse` — SQLite-based; query `ZOBJECT` table for application-usage events
- `fsevents_parse` — wrap `FSEventsParser` (David Cowen)

**New agents:**
- `MacDiskForensicator` — mirrors `DiskForensicator`: mount APFS, walk filesystem, extract high-value plists + KnowledgeC.db + user home, then chain MacArtifactAgent
- `MacArtifactAgent` — parallel to `WindowsArtifactAgent`: consume the extracted plists + SQLite DBs, emit per-artifact findings (SSH authorized keys, LaunchAgents, LaunchDaemons, login-items, persistent-app persistence paths, browser history via WebKit SQLite)
- Family branch inside `MemoryForensicator`: add `mac` plugin list — `mac.pslist.PsList`, `mac.pstree.PsTree`, `mac.lsof.Lsof`, `mac.malfind.Malfind`, `mac.netstat.Netstat`, `mac.check_syscall.Check_syscall` (rootkit detection), `mac.ifconfig.Ifconfig`

**macOS-specific hypothesis additions:**
- `H_MAC_LAUNCH_DAEMON_PERSISTENCE` — plist in `/Library/LaunchDaemons/` or `~/Library/LaunchAgents/`
- `H_MAC_TCC_BYPASS` — Transparency/Consent/Control abuse via `TCC.db`
- `H_MAC_FILELESS_AMFI_BYPASS` — Apple Mobile File Integrity bypass traces

**Known hard constraints:**
- FileVault-encrypted containers need the key from the operator — same as Windows BitLocker
- vol3 `mac.*` symbols need exact kernel-version ISF (same symbol-mismatch pain as Windows)
- No T2/Secure Enclave key material is retrievable without Apple silicon acquisition tools

**Effort estimate:** ~2-3 weeks focused work for Windows-parity disk + memory coverage on unencrypted images.

### Mobile (FOR585 iOS / Android)

Cheapest tier-3 option because `iLEAPP` (iOS) and `ALEAPP` (Android) —
both maintained by Alexis Brignoni, MIT-licensed, pure Python — do
~80% of the artifact extraction already. EL wraps them the way it
wraps `dotnet` for EZ Tools.

**Triage additions:**
- `ios_logical_backup` — detect `Manifest.plist` + `Manifest.db` at root
- `ios_file_system` — AFU (after-first-unlock) dump: presence of `private/var/mobile/`
- `android_adb_tar` — ADB-collected tar stream; identifies by `data/` root + `build.prop`
- `android_full_file_system` — rooted dump with `/data/` + `/system/`

**New skills:**
- `ileapp` — subprocess wrapper: runs iLEAPP against a backup, consumes its JSON/HTML output
- `aleapp` — same for ALEAPP
- `ios_backup_parse` — decrypt a passcode-known iTunes/Finder backup (`iphone-backup-decrypt` Python lib), emit unencrypted file tree
- `apple_kc_parse` — KnowledgeC.db parser (shared with macOS agent)

**New agents:**
- `MobileForensicator` — single agent handling both iOS + Android via iLEAPP/ALEAPP output. Emits findings keyed on:
  - iOS: iMessage SQLite, SMS/MMS, WhatsApp `ChatStorage.sqlite`, Signal, Telegram, Safari `History.db` + `BrowserState.db`, Photos.sqlite (geolocation EXIF + album ACLs), Calendar `Calendar.sqlitedb`, Notes, Call History `CallHistory.storedata`, Apple Pay, KeyChain-access-group-enumeration
  - Android: `contacts2.db`, `mmssms.db`, `Chrome/History`, `webview.db`, location provider `*.db`, app-specific SQLite at `/data/data/<pkg>/databases/`, `logcat` dumps, `Wi-Fi` config
  - Cross-platform: app installation inventory, push-notification history, clipboard history

**Mobile-specific hypotheses:**
- `H_MOBILE_SPYWARE_PERSISTENCE` — Pegasus/Predator-class artifact patterns (DataUsage.sqlite anomalies, unusual cache paths)
- `H_MOBILE_SIDELOADED_APP` — unsigned IPA / outside-Play-Store APK installer
- `H_MOBILE_MDM_ABUSE` — unexpected MDM profile installation

**Known hard constraints:**
- BFU (before-first-unlock) iOS images are essentially unreadable — operator has to acquire AFU
- Cellebrite UFDR / Magnet AXIOM proprietary archives need commercial readers; we'd ingest after their export-to-open-format step
- Passcode unknown ⇒ keychain unavailable
- Android full-disk encryption (FBE) same issue

**Effort estimate:** ~1-2 weeks for mainstream open formats (iTunes/Finder logical backups, ADB tar, iLEAPP/ALEAPP-compatible file-system dumps).

### Deliberately out of scope

- **Web-app pentesting (SEC542)** — offensive, not defensive forensics. Doesn't fit the charter.

## Analyst-facing web view

Separate from the detector/extraction roadmap above: a per-case
single-page HTML report showing timeline + attack-chain graph +
detail drawer + ATT&CK + IOCs. Reference design notes (NodeZero-
inspired) + four-tier implementation plan at
[docs/web-view-design.md](./web-view-design.md). Zero-server,
vendor-everything, deep-linkable by finding_id, integrates with the
existing `el report` CLI.

## Pre-ranked shortlist for follow-up sessions

| Tier | Addition | Reason |
|---|---|---|
| 1 | ~~SIGMA rule ingestion~~ ✅ | Shipped; RC4 Kerberoasting starter rule validated against srl-dc-disk-r3 (124 hits matching credential_analyst) |
| 1 | ~~Kerberos wire parsing~~ ✅ | Shipped; `kerberos_triage` skill + `network_analyst._run_kerberos_triage` with RC4 Kerberoasting + AS-REQ brute/spray + krbtgt-TGS detectors |
| 1 | ~~M365 UAL + Azure Sign-in~~ ✅ | Shipped; 4 sign-in detectors + 4 UAL detectors dispatched by content-sniff in `cloud_forensicator` |
| 2 | ~~ActivitiesCache.db + BAM/DAM~~ ✅ | Shipped; `bam_dam` (regipy) + `win_timeline` (sqlite3 ro) skills, validated 39 BAM entries on wkstn-01 |
| 2 | ~~PowerShell 4104 decoded~~ ✅ | Shipped in `el.skills.powershell_triage` — base64 + gzip(wbits 31/-15/15) decode with Mimikatz / AMSI-bypass / download-cradle pattern families, consumed by `PowerShellAnalystAgent` |
| 2 | ~~`capa` + `FLOSS`~~ ✅ | Shipped; rule-pack resolver + shellcode-mode dispatch; 5 rules fire on real srl-admin-memory dump |
| 3 | ~~vol3 modules / modscan / ldrmodules / handles / getsids~~ ✅ | Shipped; 5 plugins added to `WIN_PLUGINS`, modules-vs-modscan diff detector (rootkit drivers) + ldrmodules three-list diff (reflective-injection signature) |
| 3 | Linux forensics agent | Depends on whether Linux evidence is expected |
| 3 | macOS / APFS agent family | OS-agnostic abstractions already support it; ~2-3 weeks |
| 3 | Mobile (iLEAPP / ALEAPP wrap) | Cheapest tier-3: Python tools already extract 80%; ~1-2 weeks |
| 3 | ~~Teams / Slack / OneDrive parsers~~ ✅ (remote-access subset) | Shipped the high-signal subset: TeamViewer + AnyDesk inbound/outbound session detection. Teams / Slack LevelDB parsing deferred — needs a LevelDB dep; fold in when real cases demand it. |
| 4 | ~~Diamond Model / ACH matrix export~~ ✅ | Shipped; `ach_matrix.py` + `diamond.py` wired into `render_report`; validated on srl-dc-disk-r3 (APT score 30 → Diamond with Kerberoasting SPNs as Victim users) |
| 4 | ~~STIX 2.1 import~~ ✅ (MISP/TAXII deferred) | Shipped `el.skills.stix_import` + `el stix import <bundle.json>` CLI; round-trip validated against EL's own exported bundle (srl-dc-disk-r3: 6 IOCs recovered with provenance tag). TAXII/MISP network-pull deferred — needs auth + retry handling. |

None of these are committed to. They're a menu informed by the posters;
shakedown evidence on the next real cases should still drive ordering.

## Untested image / log / format types (tracker)

_Running list of evidence shapes EL either (a) claims to support but
has not been exercised on real data, or (b) does not yet parse at all.
Each entry is an actionable search term for corpus hunting. Update
rows as evidence lands and a case completes end-to-end._

### Disk images / filesystems

| Format | Status | Where to find a sample |
|---|---|---|
| ~~VMDK (VMware)~~ ✅ | Shipped via `el.skills.disk_convert` (`qemu-img convert -O raw`). Triage detects KDMV / COWD / `# Disk DescriptorFile` magics; DiskForensicator's `_handle_vm_disk` converts to raw under `<case_dir>/raw/converted.img` and reuses the existing mmls + per-partition fls walk. | — |
| ~~VHD / VHDX (Microsoft)~~ ✅ | Same path as VMDK — VHDX detected by `vhdxfile` head-magic; legacy fixed-VHD detected by the `conectix` tail-cookie via `_detect_vhd_footer`. Validated end-to-end on Andrew Rathbun's Anti-Forensics-VHDX (4 partitions, 14.6 KB fls bodyfile, MACB_TIMESTOMP_SKEW detector also added). | — |
| VDI (VirtualBox) | untested | DFIR training VMs, public CTFs |
| APFS encrypted container | **not supported** — needs FileVault recovery key ingestion | Operator-supplied key case |
| ~~BitLocker-encrypted NTFS~~ ✅ | Shipped triage detection (`-FVE-FS-` at offset 0x03 → `evidence_kind="bitlocker"`), `el.skills.dislocker` wrapper (probe metadata + FUSE-mount with recovery-key / user-password / BEK protectors), `disk_forensicator._handle_bitlocker` (probe → unlock → walk → cleanup), `H_DISK_ENCRYPTED` hypothesis. Credentials carry only sha256 digest in the ledger — raw key never persisted. Mount path uses ntfs-3g first (FUSE-file aware) with kernel-loop fallback. Validated end-to-end on a 4 GB AES-128-DIFFUSER image with 2× recovery-key protectors (commits `f47e55a` + `135765b` + `f92588e`). XTS-AES-128/256 path regex-pinned but not yet driven end-to-end. TPM / BEK protectors detected but only recovery-key driven E2E. | Operator-built 4 GB image staged at `/mnt/hgfs/hackathon/bitlocker`; SANS FOR500/FOR508 course images |
| ~~ReFS (incl. Dev Drive on Win11)~~ ✅ | Sleuth Kit + Linux kernel have no ReFS support, so EL wraps refsprogs (https://github.com/unsound/refsprogs, GPLv2+, source-built via `install.sh` → `/usr/local/bin/`). Per-partition path in `_raw_disk_walk` detects the `ReFS`+`FSRS` signature at the partition's start byte → carves the partition sparsely (50 GiB declared, ~50 MB allocated for an empty Dev Drive) → runs refsinfo + refslabel + refsls → emits a single combined `medium`-confidence finding (per upstream's reverse-engineered caveat). Validated end-to-end on the operator's Windows 11 24H2 ReFS 3.14 Dev Drive (50 GiB virtual): probe reads version + serial, walk surfaces planted `test_refs.txt` + Windows housekeeping ($RECYCLE.BIN + System Volume Information), cat retrieves planted content. parse_mmls now accepts ReFS-shaped partition rows (empty description column) — Sleuth Kit doesn't know the ReFS GPT-type GUID so leaves the column blank, which previously dropped the partition silently. Commits `f59568b` + `1fcfd57`. | Operator-built 50 GiB Dev Drive staged at `/mnt/hgfs/hackathon/refs.vhdx` |
| ~~LUKS / LUKS2~~ ✅ | Shipped `mount_luks_ro` + `umount_luks` in `el/skills/sleuthkit.py`; `mount_linux_ro` auto-raises with a hint when a LUKS header is detected instead of returning the kernel's opaque `wrong fs type` error. Validated end-to-end: 32 MiB LUKS1 container → ext4 inside → unlock → read canary → RO-write-blocked assertion. `cryptsetup-bin` + `losetup` already on SIFT. | — |
| FileVault (CoreStorage legacy) | **not supported** | Pre-APFS macOS 10.12 images |
| btrfs / xfs / zfs | **not supported** — extractor assumes ext* | Fedora / openSUSE / Proxmox disk images |
| exFAT | untested — fls may be limited | SD-card / external-drive images |
| ~~E01 multi-part (`.E01 .E02 .E03`)~~ ✅ | Validated end-to-end on the M57-Jean image (`nps-2008-jean.E01 + .E02`, 3 GB split across two parts). `libewf` transparently presents the multi-part set as a single ewf1 stream. `m57-jean-r7` completed final_state=done with H_BEC_ACCOUNT_TAKEOVER score 57. | — |
| L01 logical evidence container | untested — `LVF` magic recognised but no reader path | EnCase logical exports |
| AFF4 | **not supported** | Volatility project example datasets |
| Ex01 (EWF v2) | untested — magic recognised, reader path unverified | Modern FTK + Tableau exports |
| .ad1 (AccessData) | **not supported** | FTK-only exports (commercial) |

### Memory images

| Format | Status | Where to find a sample |
|---|---|---|
| LiME (`.lime`, Linux) | **not supported** — vol3 symbol + profile path untested | LiME repo examples, Chris Lonerz talks |
| AVML (Microsoft Linux) | **not supported** | Azure Defender examples |
| VMware `.vmem` + `.vmss` + `.vmsn` | untested — vol3 can read flat vmem, snapshot side unverified | Any VMware suspend-state |
| Hyper-V `.bin` + `.vsv` | **not supported** | Hyper-V checkpoints |
| Apple XNU core / kernel panic | **not supported** | macOS `/cores/` dumps |
| iOS memory (checkra1n dump) | **not supported** | GrayKey / Cellebrite Advanced Services output |
| Android LiME from RAM | **not supported** | MSAB / forensic labs |
| HPAK (F-Response) | untested | F-Response commercial acquisitions |

### Log formats / telemetry

| Source | Status | Where to find a sample |
|---|---|---|
| ~~systemd journal binary (`.journal`)~~ ✅ | Shipped `el.skills.systemd_journal` — wraps `journalctl --file` + JSON export + per-unit filters (sshd, sudo, cron, systemd units). Consumed by `LinuxForensicatorAgent._analyze_systemd_journal`. | — |
| ~~auditd raw (`audit.log`)~~ ✅ | Shipped `el.skills.auditd` — pure-Python parser AND `ausearch -if` binary wrapper with automatic fallback. Surfaces structured AuditEvent records (type / syscall / exe / uid / pid / argv / msg) with multi-line audit(...) message-ID grouping. Aggregations (`by_type`, `by_user`, `by_key`) + a `suspicious_executions` detector for executables in /tmp / /var/tmp / /dev/shm. Wired into `LinuxForensicatorAgent._analyze_auditd`. Doc claim of "pattern scan only" was stale. | RHEL / Ubuntu server images |
| ~~Linux `utmp` / `wtmp` / `btmp`~~ ✅ | Shipped `el.skills.utmp` — pure-Python parser for the 384-byte glibc utmpx struct, covers utmp (active) / wtmp (historical) / btmp (failed-auth). Detectors: brute-force burst (≥5 btmp rows from same source), remote-root-login. Consumed by `LinuxForensicatorAgent._analyze_utmp_family`. | — |
| ~~IIS W3C logs~~ ✅ | Shipped `el.skills.iis_w3c` — streaming W3C-Extended parser with mid-file `#Fields:` re-emit handling. Five detectors wired into `WindowsArtifactAgent._iis_w3c`: webshell-URI shape, scripted-client UA (offensive vs generic), admin-path success from public IP, upload POST burst, verb-tunnel. `extract_windows_artifacts` walks `inetpub/logs/LogFiles/W3SVC*/` and copies u_ex*.log into `exports/iis_logs/`. | — |
| ~~Apache / nginx access logs~~ ✅ | Shipped `el.skills.webserver_access` (417 lines) — Common + Combined Log Format parser with five detectors mirroring `iis_w3c.py`: webshell URI shape, scripted-client UA (curl/wget/python-requests vs browser), admin-path success from external IP, response-code anomaly burst (5xx storms, 401/403 fan-in), verb tunnel (CONNECT/TRACE/OPTIONS abuse). Wired into `LinuxForensicatorAgent._analyze_webserver_access`. Doc previously claimed "no detector" — it was stale. | Public webserver breach samples |
| Zeek `conn.log` / `http.log` etc. (batch ingest) | partial — pcap-derived Zeek runs validated, standalone Zeek corpus ingest untested | Zeek-published training data, LANL-netflow |
| ~~Suricata EVE JSON~~ ✅ | Shipped `el.skills.suricata_eve` — single-pass JSONL parser that classifies events by type, clusters alerts by (signature_id, signature) with first/last seen + dst-IP/port sets + ATT&CK technique IDs from rule metadata, captures fileinfo events with sha256, aggregates HTTP / DNS / TLS / Anomaly. Triage detects standalone eve.json (10-line probe for `event_type` + canonical-value markers); `NetworkAnalystAgent._handle_eve_json` runs the parser + emits per-cluster Findings (severity→confidence: 1→high, 2→medium, 3→low). The existing pcap-replay path's `_run_suricata` now also calls the new parser on the freshly-written eve.json so cluster + fileinfo + anomaly findings appear alongside the legacy rc-count summary. Validated end-to-end on synthetic EVE → alert cluster + extracted file + anomaly all surfaced → cross-tier corroboration lifted H_APT_ESPIONAGE. Commit `b57f680`. | Synthetic EVE drove the validation; SANS / Suricata-published demo datasets are the natural next test source. |
| AWS VPC Flow Logs (v3/v5 fields) | v2 shipped, v5 extended fields untested | AWS sample datasets |
| AWS GuardDuty JSON | **not supported** — CTI-feed candidate | AWS test-finding datasets |
| Google Workspace Admin / Drive / Gmail audit | **not supported** — in roadmap | Workspace admin export labs |
| Okta System Log JSON | **not supported** | Okta developer sandbox exports |
| JamF / Intune MDM | **not supported** | Endpoint-management vendor labs |
| GitHub / GitLab audit log | **not supported** | Any enterprise tenant export |
| Kubernetes audit log | **not supported** | `kind` / `minikube` + audit-policy demo |
| Docker daemon log + container stdout | **not supported** | Any container forensics lab |
| ESXi host `vmkernel.log` / `hostd.log` | **not supported** | VMware vSphere images |
| Exchange / Postfix message-trace logs | **not supported** — overlaps M365 UAL MailItemsAccessed | On-prem Exchange case images |
| pfSense / OPNsense logs | **not supported** | Home-lab firewall captures |

### Collection / acquisition bundles

| Format | Status | Where to find a sample |
|---|---|---|
| KAPE output tree (complete target set) | untested — only partial Windows-artifacts subset validated | SANS KAPE labs |
| ~~CyLR output (Linux + Windows + macOS)~~ ✅ | Triage zip-detect AND target-OS classification (commits `1f447cd` + macOS auto-extract wiring): canonical `CyLR_Collection_Log_<TS>.log` marker OR ≥5 platform-FS-root-prefixed entries (`var/log/` for Linux, `<drive>/Windows/` / `<drive>/$MFT` for Windows, `private/var/` + `System/Library/` + `Library/` for macOS). Dispatch routes per-OS — Linux→LinuxForensicatorAgent, Windows→WindowsArtifactAgent, macOS→MacOSForensicatorAgent (or LinuxForensicator best-effort for the "unknown" sentinel). Each downstream agent auto-extracts into `<case>/raw/cylr/` once; every existing detector / EZ Tools walker traverses the extracted tree natively because they use `rglob`. Validated end-to-end on THREE operator-built collections: 24 MB Linux zip (`rubicon.zip`) → cracker_tooling matched rockyou.txt (T1110) → systemd_journal + sudo escalation → H_APT_ESPIONAGE; 303 MB Windows zip (`RUBICON.zip`) → MFTECmd $MFT + RECmd Registry + AmcacheParser + PECmd Prefetch + EvtxECmd Logs + SBECmd + JLECmd + LECmd all parsed under the `C/` drive-letter prefix; **331 MB macOS zip (`rubicons-iMac-Pro.zip`) → shell_history_persistence_ssh (T1098.004, `vi authorized_keys`) + shell_history_remote_access_screensharing (T1021.005 + T1543.001, `launchctl load screensharing.plist`) + shell_history_tunnel_vnc (T1572, `ssh -L 5900:…`) → H_C2_BEACONING (score=6, gap=+1)**. macOS-specific shell patterns (`launchctl screensharing` enablement; VNC SSH tunnels on port 5900/3283/5988; interactive-editor `vi authorized_keys`) live in `el/skills/macos_triage.py::_MAC_SHELL_PATTERNS`. | Operator-built Linux + Windows + macOS CyLR collections at `/mnt/hgfs/hackathon/rubicon.zip` + `/mnt/hgfs/hackathon/RUBICON.zip` + `/mnt/hgfs/hackathon/rubicons-iMac-Pro.zip`; CyLR GitHub release labs |
| Magnet AXIOM `.mfdb` / `.case` | **not supported** — commercial proprietary | AXIOM trial exports |
| Cellebrite UFDR (`.ufd`) | **not supported** — commercial; need export-to-open-format step | UFED demo datasets |
| Autopsy case directory | **not supported** | Public Autopsy teaching cases |
| ~~Velociraptor VFS download (offline) + hunt zip~~ ✅ | Shipped triage zip-detect (`hunt_info.json` / `client_info.json` / `collection_context.json` markers inside the zip; cheap namelist probe, no decompression), `EndpointAnalystAgent` auto-extracts into `<case>/raw/velociraptor/` before walking. **Two-tier artifact ingest** added: specific-parser tier (KNOWN_PARSERS — Pslist / Pstree / Netstat / Autoruns / Amcache / MFT / Lnk / Pedump / 12+ others) for structured graph + IOC population; generic-ingest tier captures every other JSON / JSONL / CSV artifact via schema-aware probe (row count + column names + time range from any timestamp-shaped column + 3 sample rows) so any custom YAML artifact surfaces in the ledger automatically. Validated against operator's hunt-download zip (`H.D8618G34A7B54.zip`, Generic.System.Pstree on host `rubicon`): triage routed correctly, 453 graph Process nodes populated, generic tier emitted the schema-aware summary. Commit `a865121`. | Operator-built hunt zip at `/mnt/hgfs/hackathon/H.D8618G34A7B54.zip` |
| CrowdStrike RTR / SentinelOne / Carbon Black exports | **not supported** | Vendor case studies, DFIR-exported tickets |
| FTK Imager `.ad1` logical | **not supported** | FTK labs |

### Mobile

| Format | Status | Where to find a sample |
|---|---|---|
| iTunes / Finder unencrypted backup | **not supported** — in roadmap | iPhone SE lab on any Mac |
| iTunes / Finder encrypted backup + passcode | **not supported** — in roadmap | Same + known passcode |
| Android ADB tar stream | **not supported** — in roadmap | `adb backup` of any dev device |
| iOS `.ipa` sideloaded app | partial — presence detected via our Bundle/Application walk, but no in-bundle plist / Mach-O parsing | Developer-signed IPAs |
| Android APK (on-tree, unpacked) | partial — presence + installer-source checks, no Manifest.xml parse | Any malware-APK corpus |
| checkra1n / GrayKey file-system image | untested — we handle the unpacked tree, not the raw acquisition container | Forensic service outputs |
| Xiaomi / Huawei brand partitions | untested | Vendor-specific ROMs |

### Application artifacts (Windows-Apps poster follow-ups)

| App | Status | Where to find a sample |
|---|---|---|
| Microsoft Teams (LevelDB + IndexedDB) | **not supported** — deferred, needs LevelDB dep | Any Teams-using workstation image |
| Slack (same Electron LevelDB shape) | **not supported** | Slack desktop on any dev workstation |
| Microsoft Edge User Data | **not supported** — shares Chrome schema, parser reachable | Any Edge-using workstation |
| OneDrive `SyncEngine.log` + `AppLock` | **not supported** | Enterprise Windows image |
| Dropbox `sync_history.db` / `config.dbx` | **not supported** | Dropbox-using workstation |
| Discord IndexedDB | **not supported** | Consumer dev workstation |
| 1Password / Bitwarden state (existence, not content) | **not supported** | Any endpoint with password manager |
| iCloud (on Windows) `CloudStorage.db` | **not supported** | Mac-sync-to-PC workstation |

### Cloud breadth gaps (explicit extras)

| Source | Status | Where to find a sample |
|---|---|---|
| Azure Storage blob / file access logs | **not supported** | Azure public sample-logs bucket |
| GCP Cloud Storage audit | **not supported** | GCP public sample logs |
| Azure Firewall / WAF logs | **not supported** | Azure diagnostic-log exports |
| AWS Config / CloudWatch Logs subscription | **not supported** | AWS sample environments |
| Duo / Ping / Auth0 audit | **not supported** | Identity-vendor dev sandboxes |

_Maintenance rule: when a new format lands with a validated end-to-end
case, move it out of this table and into the "Validated on real
evidence" section of [README.md](../README.md). When a format proves
to need a new agent or skill rather than a detector tweak, link the
corresponding row to the pull request._

## Test-corpus sourcing

Primary image source for extending coverage:
**[The Evidence Locker](https://theevidencelocker.github.io/)** —
curated DFIR evidence index. Images pulled from there drive the
shakedown-improvement loop for every new platform EL adds. For the
Tier-3 additions specifically:

- **macOS / APFS** — pull APFS disk images + macOS memory dumps from
  the Locker; EL's improvement loop then fires PRs off the same
  ≥2-case repetition rule it uses today.
- **Mobile** — pull iOS logical backups + Android ADB tars; iLEAPP /
  ALEAPP output drives `MobileForensicator` findings.
- **Linux** — pull any Linux IR image set (the Locker indexes several)
  to populate the `LinuxForensicator` agent.

Coverage additions that don't need evidence (SIGMA rule ingestion,
`capa`/`FLOSS` wrappers, cloud-log parsers) can proceed independently
of corpus sourcing.

## M57-Jean validation April 2026 + remaining gaps

Ran EL against the `nps-2008-jean.E01 + .E02` pair (digitalcorpora.org
M57-Jean scenario) to stress-test the Executive Narrative layer. EL
arrived at **H_BEC_ACCOUNT_TAKEOVER** (score 30, gap +17) as the leading
hypothesis — the canonical scenario answer (Jean was socially-engineered
via a fake "Alison/President" email thread and sent `m57biz.xls` to
`tuckgorge@gmail.com`). Neither of the two public GitHub writeups
([Basilmellow](https://github.com/Basilmellow/Autopsy-M57-Linux-Forensics),
[jynxora](https://github.com/jynxora/M57-Jean-Case-Analysis)) reached
that conclusion; one invented USB-insider details, the other landed on
browser-compromise-plus-AIM6-bundleware. EL's `email_forensicator`
display-name vs SMTP-mismatch detector fired on two outbound messages
(RE: "Please send me the information now" + RE: "Thanks!"), with the
actual attachment `1_m57biz.xls (291840B)` named inline.

Real gaps surfaced by the M57 run (none are blockers — the narrative is
complete and correct — but each is worth addressing on the next pass):

| Gap | Symptom on M57 | Fix sketch |
|---|---|---|
| Inbound-phishing detector | Narrative says "initial compromise vector not reconstructible" even though the spoofed-Alison inbound email that Jean replied to is literally in her Inbox | Extend `email_forensicator` to flag INBOUND messages whose From-display-name and From-SMTP-address mismatch, or whose Subject later appears in an outbound "RE:" with the mismatch detector above → tag H_INITIAL_ACCESS_PHISHING |
| XP EVT (pre-Vista event logs) | `credential_analyst` + `lateral_movement_analyst` both emit confidence=insufficient because no `evtx_parsed.csv` was produced — EvtxECmd handles only EVTX, not EVT | Add a `.evt` → `.evtx` conversion step or wrap the legacy `grokevt`/`evtexport` path when XP `.evt` files are detected at intake |
| IE5 Content.IE5 cache parsing | jynxora's session-hijack + `userSynchronization.htm` finding came from this subtree — EL currently doesn't parse `Content.IE5` index.dat records | New skill `el/skills/ie_cache.py` — walk `Content.IE5` subdirs, parse `index.dat` binary format for visited URLs, cookies, and form data |
| Anti-forensics signal strength | jynxora flagged mass-zeroed system binaries (`debug.exe`, `ipconfig.exe`, `wscntfy.exe` with size=0, timestamps=0000-00-00) — EL's `disk_anomaly` sees executables in Temp but doesn't flag system-binary tampering | Extend `disk_anomaly` patterns with a "system-binary zero-size OR zero-timestamp" detector keyed to `/WINDOWS/system32/` + `/dllcache/` + `/ServicePackFiles/` |

Net: EL's narrative already out-performs the public writeups on this
specific scenario. The gaps above would make the narrative's opening
beat ("Initial compromise") explicitly cite the inbound phishing email
instead of declaring the vector unreconstructible.

### Update (validated — m57-jean-r7)

All four gaps closed; validated end-to-end. Final ACH leader
**H_BEC_ACCOUNT_TAKEOVER score 57 (gap +44 over runner-up
H_INSIDER_EMAIL_EXFIL 13)** — up from score 30 pre-fix. Closures
land in commits `450da13` + `dbb0868` + `c77cb43` + `7850e51`:

| Gap | How it fires now |
|---|---|
| Inbound-phishing detector | 4 findings in the "Initial compromise" beat: two "Inbound precursor" (heuristic B: reply-chain correlation → pretexting-email inbound in Inbox matches an outbound mismatch reply) + two "Inbound phishing / spoofed From" (heuristic A: direct From display/SMTP mismatch). Subjects `"Thanks!"` and `"Please send me the information now"` both caught. |
| XP `.evt` parsing | `el/skills/xp_evt.py` wraps `evtexport`; `windows_artifact._evtx` falls back automatically when no `.evtx` found. Parsed 575 records from the M57 AppEvent + SysEvent pair (SecEvent empty = log cleared, flagged separately). Downstream credential / lateral / sigma / powershell analysts now report "parsed evtx_parsed.csv but no pattern crossed threshold" instead of "no CSV to consume" — i.e. they can now reason honestly about the absence of evidence. |
| IE5 Content.IE5 cache | `el/skills/ie_cache.py` wraps `msiecfexport`; `sleuthkit.extract_windows_artifacts` pulls 9 index.dat files (3 users × Content.IE5 / Cookies / History.IE5). Parsed 4778 records across all three Jean/Administrator/Devon profiles, flagged 116 suspicious URLs (24 tracker-sync including the jynxora M57-Jean `__utm` / session-sync signal). |
| Zero-size / zero-timestamp anti-forensics | `disk_anomaly._scan_bodyfile_rowwise` flags 15 zero-size + 15 zero-timestamp Windows system binaries (pdh.dll, auditusr.exe, ciadmin.dll, etc. — matches jynxora's mass-wipe signature). |

Bonus gap (graph): empty Kùzu graph on email-only case fixed by the
Email node type + 4 new edges in `graph.py` + email_forensicator's
`_populate_graph` method — 15 entity nodes + 13 edges on M57-Jean.

## Category extras shipped April 2026 (no-corpus chain)

Beyond the Tier 1–4 shortlist, the following category items landed:

| Item | Commit | Deferred (needs corpus or bigger dep) |
|---|---|---|
| Network depth — DGA entropy + DNS tunneling + SMB admin-share writes | `9821af5` | (JA3 part landed in `9c2df40`; Umbrella allowlist wrapper present but not yet wired) |
| ~~JA3 known-bad + cross-case rarity~~ ✅ | `9c2df40` | Umbrella top-1M allowlist ◐ — `el.skills.umbrella_allowlist` exists and is imported by `el.skills.network_anomaly`, but `network_anomaly` itself is not yet imported by any agent, so the allowlist is **not in the live pipeline** (wrapper-done, consumer-pending) |
| Cloud breadth — Azure Activity + GCP Cloud Audit + AWS VPC Flow | `d070478` | Google Workspace + AWS GuardDuty |
| PowerShell breadth — EID 4103 + PSReadline + transcription scans | `15fdaee` | Windows Cloud-Clipboard (UWP state) ✅ shipped via `el.skills.uwp_clipboard` (consumed by `windows_artifact`) |
| vol3 extras — ssdt + driverirp + kernel-hook detector + filescan + mftscan + dumpfiles per-PID | `8de8f9d` | `_carve_dumpfiles` runs dumpfiles against malfind-flagged PIDs (8-PID cap); carved files feed threat_hunter |
| ~~vol3 yarascan~~ ✅ | `811764c` + `0874487` | Wraps `windows.vadyarascan.VadYaraScan` with PID + ImageFileName attribution; volume-noise suppression (≥10× median or ≥1000 absolute → low confidence). Validated end-to-end on `srl2018-admin-memory`. |
| Windows artifact extras — RecentDocs + OpenSave-MRU | `b6ead0d` | CapabilityAccess ✅ (`el.skills.capability_access`) / UAL mdb ✅ (`el.skills.ual`) / VSS mounting ✅ (`el.skills.vss` + `vss_diff`) — all wired (`windows_artifact` / `disk_forensicator`) |
| ~~IIS W3C parser~~ ✅ | `71a9a1c` | 5 detectors (webshell URI, scripted UA, admin path, upload burst, verb tunnel) |
| ~~VMDK / VHD / VHDX ingest~~ ✅ | `317d568` | qemu-img convert → raw → existing fls pipeline |
| ~~MACB timestomp-skew detector~~ ✅ | `096459b` | crtime > mtime by ≥7 days; first-class `H_ANTI_FORENSICS` hypothesis |
| ~~`linux-fs-dir` + `qnap-nas-dir` triage kinds~~ ✅ | `e32424f` | LinuxForensicatorAgent now accepts `ctx.input_path` directly when triage routes via these kinds; QNAP DataVol1 mount validates |
| ~~`bulk-extractor-output` triage + agent~~ ✅ | `9430eba` | Histograms + carved-record buckets become Findings; MSAB attribution + 172.21 LAN subnet surfaced from QNAP case 21APR_245 |
| ~~TLSH cross-case fuzzy clustering~~ ✅ | `aab2cea` | `el.skills.similarity_digest.tlsh_*` + `knowledge.fuzzy_hashes.tlsh` w/ auto-migration; companion to existing ssdeep |
| ~~Cross-host graph merging~~ ✅ | `4b352e6` | Shared IPs / domains / hashes collapse across cases; case-anchor bridges via `OBSERVED_IN`; layout ring + sunflower |
| ~~ATT&CK row expand + timeline drawer~~ ✅ | `d6aec5d` | combined.html click-to-detail per technique + per finding |
| ~~Cross-evidence divergence detector~~ ✅ | `cbd42f9` | Flags hosts where disk vs memory disagree on leader / score span ≥15 |
| ~~Coordinator SIGTERM/SIGINT guard~~ ✅ | `212d1e8` | `coordinator_signalled` audit line on graceful kills (SIGKILL still untrappable) |
| ~~Coordinator auto-renders case.html~~ ✅ | `6701836` | `el investigate` no longer requires a follow-up `el report --html` |
| ~~ACH corpus regression golden~~ ✅ | `0904840` | tests/fixtures/ach_golden.json locks leading hypothesis + score per case |
| ~~IOC noise — Windows filename TLDs~~ ✅ | `66c9894` | .pf / .fon / .ttc / .mum / .cat etc. dropped from domain bucket |
| Detection engineering — IOC rarity scoring + ubiquitous-noise suppression | `84359ba` | MITRE CAR analytic import (overlaps SIGMA) |
| ~~MITRE CAR analytic import (loader + pack-fetch)~~ ✅ | `9d10bd3` + `3c460f5` | Loader at `el.skills.car_import` wired into `SigmaAnalystAgent`. `install.sh` clones MITRE's upstream CAR repo (https://github.com/mitre-attack/car) to `/opt/EL/rules/car/` — ~100 analytics. **Important finding**: MITRE's `type: Sigma` implementations reference SigmaHQ URLs rather than inlining `code:`, so on a fresh clone the loader extracts 0 runnable rules. The analytic YAMLs still carry useful ATT&CK coverage metadata, and the loader works against any third-party CAR fork that DOES embed sigma code. SigmaAnalystAgent's summary now distinguishes "no CAR dir" / "CAR dir with no embedded sigma" / "CAR dir with runnable sigma" so the analyst doesn't chase phantom misconfigurations. |
| ~~Velociraptor zip + two-tier ingest~~ ✅ | `a865121` | Triage zip-detect (peek inside `H.<id>.zip` / `Collection-…zip` for hunt or client metadata; cheap namelist probe). EndpointAnalystAgent auto-extracts to `<case>/raw/velociraptor/`. **Generic-ingest tier** added alongside KNOWN_PARSERS: every JSON / JSONL / CSV artifact file not claimed by a specific parser gets a schema-aware probe (row count + column names + time range + 3 sample rows). Stops EL from falling behind Velociraptor's 500+ artifact catalogue — custom YAMLs surface automatically. Validated on operator's hunt zip with Generic.System.Pstree (now also a specific parser → graph Process nodes). |
| ~~Suricata EVE JSON parser~~ ✅ | `b57f680` | `el.skills.suricata_eve` — JSONL classifier with alert clustering by (sid, signature) + ATT&CK metadata extraction + fileinfo capture + HTTP/DNS/TLS/Anomaly rollups. Triage detects standalone eve.json; NetworkAnalystAgent emits per-cluster Findings + augments the existing pcap-replay path with per-event detail (was rc-count-only before). Severity → confidence map matches Suricata convention. Validated on synthetic EVE → Cobalt Strike cluster + extracted-file finding + cross-tier corroboration via malware_triage + threat_hunter → leading hypothesis H_APT_ESPIONAGE. |
| ~~CyLR triage + auto-extract + OS classify~~ ✅ | `88526d6` + `1f447cd` + macOS auto-extract wiring | Triage zip-detect (canonical marker OR ≥5 platform-prefix entries) PLUS target-OS classification (Linux / Windows / macOS / unknown) — dispatch routes per-OS to LinuxForensicator / WindowsArtifact / MacOSForensicator. Each agent auto-extracts; existing detectors traverse natively. Validated end-to-end on THREE real CyLR collections: 24 MB Linux (`rubicon.zip`) → rockyou.txt + sudo escalation → H_APT_ESPIONAGE; 303 MB Windows (`RUBICON.zip`) → all 8 EZ Tools walkers parsed targets under `C/` drive-letter prefix; 331 MB macOS (`rubicons-iMac-Pro.zip`) → persistence_ssh (T1098.004) + remote_access_screensharing (T1021.005 + T1543.001) + tunnel_vnc (T1572) → H_C2_BEACONING (score=6). MacOSForensicatorAgent's CyLR auto-extract branch + macOS-only `_MAC_SHELL_PATTERNS` (launchctl screensharing enablement; SSH-tunnel VNC on 5900/3283/5988; interactive-editor `vi authorized_keys`) live in `el/skills/macos_triage.py`. |
| ~~Pre-attack / lone-offender planning detection~~ ✅ | Lone Wolf 2018 trio | Triple fix shipped against NIST CFReDS Lone Wolf 2018 corpus (Moore): (1) `ioc_extract` AWS access-key regex (`AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA + [A-Z0-9]{16}`) + AWS secret-key assignment regex — Cloudy's `rootkey.csv` + Brother-Chat handoff (`AKIAJQCL74OG6U6JRXKQ`) now surfaces. (2) `el.skills.pre_attack_planning_lexicon` — 5 categories (weapons, ammo, opsec/escape, intent/manifesto, destination) curated from solution-guide quotes; same ≥2-category co-occurrence rule as `narcotic_lexicon`. Suppresses single-keyword FPs (Glock-at-the-range posts). (3) `el.skills.cross_cloud_mirror` — detects ≥3-cloud-sync-provider duplication of the same SHA-256 file under one user profile (the Lone Wolf evidence-preservation signature: same Manifesto.docx in Box/Dropbox/OneDrive/Google Drive/S3). WindowsArtifactAgent gained `_cross_cloud_mirror` + `_pre_attack_planning` + `_aws_credential_exposure` methods. New ACH hypothesis `H_PRE_ATTACK_PLANNING` scores on the three detectors + claim-text fallbacks; `H_BENIGN_NO_INCIDENT` strongly refuted by either tag. Validated on synthetic Lone-Wolf-shaped tree using verbatim quotes from the Moore solution guide → ACH ranked H_PRE_ATTACK_PLANNING=+23, H_BENIGN_NO_INCIDENT=-15. 23 regression tests pin every primitive. |
| ~~Case-local DNS enrichment~~ ✅ | `9d10bd3` | `el.skills.dns_enrichment` walks Zeek dns.log answers; `correlator` writes RESOLVED_TO edges into the Kùzu graph + emits a per-case "IPs ↔ domains" finding |
| ~~Low-entropy IOC filter~~ ✅ | `4ead5c1` | Drops padding-shaped tokens (`aaaa…`, `AAAA…`) that satisfied the hash/crypto regex but were memory slack — SRL-2018 r9's shared-IOC table no longer fabricates ghost overlaps |
| ~~BitLocker volume support~~ ✅ | `f47e55a` + `135765b` + `f92588e` | Triage detect → DiskForensicator `_handle_bitlocker` → `dislocker` skill (probe + mount with cred-digest-only audit) → ntfs-3g-first NTFS mount with kernel-loop fallback. Validated on 4 GB AES-128-DIFFUSER image. |
| ~~ReFS volume support~~ ✅ | `f59568b` + `1fcfd57` | `el.skills.refsprogs` wraps the unsound/refsprogs GPLv2+ userspace ReFS reader (refsinfo / refslabel / refsls / refscat); `_raw_disk_walk` per-partition path detects `ReFS`+`FSRS` signature and routes to `_walk_refs_partition` which carves the partition sparsely + runs the refsprogs chain. parse_mmls bug fix: previously dropped partitions with empty description (which is how Sleuth Kit renders ReFS-type GUIDs). Validated end-to-end on operator's 50 GiB Win11 24H2 ReFS 3.14 Dev Drive. `install.sh` clones + builds refsprogs to /usr/local/. |
| ~~Cross-host AI executive brief~~ ✅ | `4656572` | `el.reporting.combined_executive_ai` — six-section CombinedExecutiveBrief (cross-host overview / attack chain / affected hosts / data movement / enterprise risk / confidence). Same three-path synthesis as per-case (cache → API → defer-skill). Validated on SRL-2015-r9 + SRL-2018-r9. |
| ~~Per-host clock-skew + TZ baseline~~ ✅ | `6535824` + `2aa8857` | `el.skills.ewf_skew` (acquirer-vs-target delta from `ewfinfo`) + `el.skills.time_baseline` (SYSTEM hive TimeZoneInformation + W32Time). Combined dashboard surfaces a `#clocks` panel + TZ-split / NoSync alerts. |
| ~~Lateral-movement graph populates Users + IPs + edges~~ ✅ | `be78e92` | `lateral_movement_analyst._populate_graph` writes Host + Event + User + IPAddress nodes + OBSERVED_ON / AUTHENTICATED_AS / SOURCE_IP edges. SRL-2015-dc graph went from 11 nodes / 0 edges to 23 nodes / 32 edges. |

## Corpus-gated tier-3 status (refreshed April 2026)

| Tier | Item | Status | Evidence validated against |
|---|---|---|---|
| T3-2 | Linux forensicator family | ✅ Complete | BelkaCTF Kidnapper case + several SRL cases |
| T3-4 | macOS / APFS family | ◐ Mostly shipped — see open items below | macOS BigSur APFS image |
| T3-5 | Mobile (iOS + Android) family | ◐ Mostly shipped — see open items below | iPhone SE iOS 14.3 AFU dump |

**T3-2 Linux** — `el.skills.linux_triage`,
`el.skills.linux_artifacts`, `el.skills.utmp`,
`el.skills.systemd_journal`, `el.skills.thunderbird_mbox`,
`el.skills.narcotic_lexicon`, plus April 2026 additions
`el.skills.auditd`, `el.skills.webserver_access`, and
`el.skills.rootkit_scanners` — all consumed by
`LinuxForensicatorAgent`. 41+ passing tests.

**T3-4 macOS / APFS** — shipped: `el.skills.apfs`,
`el.skills.macos_artifacts`, `el.skills.macos_triage`,
`MacOSForensicatorAgent`, four triage detectors
(launch-persistence, shell-history malicious, quarantine unusual
source, Safari downloads suspicious). Validated against the
operator's BigSur APFS image. **Open items** (not corpus-gated —
shipped April 2026 as part of the hypothesis-set wire-up):
- ✅ `H_MAC_LAUNCH_DAEMON_PERSISTENCE`, `H_MAC_TCC_BYPASS`,
  `H_MAC_FILELESS_AMFI_BYPASS` registered + scored + ATT&CK-mapped
  (T1543.001/004, T1548.006, T1556, T1620, T1027.007).

  - ✅ **`el.skills.macos_unifiedlogs`** — Unified Log parser
    shipped (consumed by `MacOSForensicatorAgent`); when the
    Apple-only `log show`/`log archive` tooling is absent it
    surfaces a clear "needs macOS host" marker rather than
    failing.

  **Truly corpus-gated** (still open): dedicated `fsevents_parse`
  skill, vol3 `mac.*` family branch in `MemoryForensicator`
  (needs a macOS memory image with matching ISF symbols).

**T3-5 Mobile** — shipped: `el.skills.ileapp`,
`el.skills.ios_artifacts`, `el.skills.ios_triage`,
`el.skills.android_artifacts`, `el.skills.android_triage`,
`IOSForensicatorAgent`, `AndroidForensicatorAgent`, four triage
detectors per platform. Validated against the operator's iPhone
SE AFU dump. **Open items** (shipped April 2026):
- ✅ `H_MOBILE_SPYWARE_PERSISTENCE`, `H_MOBILE_SIDELOADED_APP`,
  `H_MOBILE_MDM_ABUSE` registered + scored + ATT&CK-mapped
  (T1547, T1404, T1476, T1444, T1481, T1462).
- ✅ **`el.skills.aleapp`** — dedicated ALEAPP wrapper, mirrors
  the iLEAPP shape (auto-detect mode from extension, parse
  `_TSV_Exports/` into `ArtifactTable` records). Validated
  against the Android 12 Magnet TAR (`/mnt/hgfs/hackathon/
  Android 12/TAR File/`).
- ✅ **`el.skills.ios_backup_parse`** — iTunes/Finder logical
  backup parser. Reads `Manifest.plist` + `Manifest.db`,
  surfaces device metadata (iOS version, product type,
  encryption flag, application count), enumerates the file
  inventory keyed by domain. Encrypted-backup decryption path
  available when the operator stages
  `iphone_backup_decrypt`. Validated against the encrypted
  iPhone8,4 backup at `/mnt/hgfs/hackathon/ios_13_4_1`.
- ✅ **`el.skills.sysdiagnose`** — iOS sysdiagnose tarball
  triage. Extract + index by subsystem (crashes_and_spins,
  logs, summaries, system_logs.logarchive, …); parse `.ips`
  records (Apple's JSON-then-JSON crash / jetsam / wakeups
  format); surface largestProcess + memory state on Jetsam
  events. Validated against the iOS 13.4.1 sysdiagnose at
  `/mnt/hgfs/hackathon/ios_13_4_1/iOS 13.4.1 Extraction/
  Sysdiagnose Logs/`.

- ✅ **`el.skills.yaffs2`** — MTD/YAFFS2 phone-dump support.
  Two-stage extraction chain:
    1. **`unyaffs`** (Whitechapel, apt — added to
       `provisioning/apt-packages.txt`); 6 canonical Android
       NAND geometries (`-b -c 2 -s 64`, `-c 2 -s 64`, …,
       autodetect).
    2. **`unyaffs2`** (yaffs2utils, source-built — `install.sh`
       clones + builds to `/opt/yaffs2utils/`); 6 page+spare
       combos (`-p 2048 -s 64`, `-p 2048 -s 32`, …,
       `-p 4096 -s 128`, `-p 512 -s 16`, autodetect).
  Stage 2 fires when stage 1 produces 0 files — handles the
  long tail of NAND layouts unyaffs 0.9.7 doesn't recognise.
  Structural detector identifies YAFFS2 partitions by
  stride-aligned object headers (parent_id range +
  null-padded ASCII name + 512 / 1024 / 2048 / 4096 B page
  support). `walk_bundle()` chains: detect → extract → merge
  partitions into a unified FS tree (special-file-aware
  copy that skips FIFOs / sockets / device nodes that
  unyaffs2 faithfully preserved) → role detection
  (system / data / cache from extracted shape) → standard
  android-artifacts walker. Validated end-to-end against
  `/mnt/hgfs/hackathon/Case2/` (2011-vintage Android phone,
  10 mtd*.dd partitions): mtd6 extracted via unyaffs (615
  files, 118 MB system partition); **mtd8 extracted via
  unyaffs2 (1,997 files, 182 MB userdata partition** with
  `accounts.db`, `packages.xml`, KakaoTalk + Google Maps +
  YouTube + 30+ per-app data dirs); 2 FIFOs/sockets skipped
  during merge (low-confidence note). Standard android-
  artifacts walker recognises both extracted shapes:
  `anr_traces=1, app_contacts_files=1,
  app_telephony_files=2, system_app_entries=140,
  system_build_prop=1`.

  **Truly corpus-gated** (still open): full
  `system_logs.logarchive` Unified Log replay (Apple-only
  `log show`/`log archive` tools; the sysdiagnose skill
  surfaces a clear "needs macOS host" marker when the archive
  is present).

Everything else in the doc is shipped or listed under a
deferred-with-rationale item above.
